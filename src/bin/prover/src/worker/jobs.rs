//! PostgreSQL-backed proof jobs.
//!
//! A job is keyed by `(chain, guest, commitment)`. The canonical commitment
//! binds the guest, the pre/post roots, the height and the exact transaction
//! set, so a completion for another tip or guest can never satisfy this key.
//! Private witness bytes live in a separate table and are removed when the
//! job finishes. Public status exposes only timing, attempts and rejection.
use super::*;
use tokio_postgres::{types::ToSql, Client, Config, NoTls};
use workstream_core::dev::crash_point;

pub(super) struct Jobs {
    client: tokio::sync::Mutex<Client>,
    chain: String,
}

fn db(e: tokio_postgres::Error) -> Error {
    let detail = e
        .as_db_error()
        .map(|e| e.message().to_string())
        .unwrap_or_else(|| e.to_string());
    Error::Io(format!("proof job database: {detail}"))
}
fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(|e| Error::Serialization(e.to_string()))
}
fn decode<T: serde::de::DeserializeOwned>(v: &[u8]) -> Result<T> {
    postcard::from_bytes(v).map_err(|e| Error::Serialization(e.to_string()))
}
type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// A completion belongs to this job only when both its commitment and guest
/// match the key. Commitments bind height, roots and transactions, so a late
/// result from another tip or program cannot satisfy a different key.
fn completion_matches(proof: &ZkProof, guest: &[u8], key: &[u8]) -> bool {
    proof.commitment.as_bytes() == key && proof.guest_hash.as_bytes() == guest
}

async fn delete_witness(
    tx: &tokio_postgres::Transaction<'_>,
    chain: &str,
    guest: &[u8],
    key: &[u8],
) -> Result<()> {
    tx.execute(
        "DELETE FROM proof_job_witness WHERE chain=$1 AND guest=$2 AND commitment=$3",
        &[&chain as &(dyn ToSql + Sync), &guest, &key],
    )
    .await
    .map_err(db)?;
    Ok(())
}

impl Jobs {
    pub(super) async fn open(chain: u64) -> Result<Self> {
        let socket = std::env::var_os("WORKSTREAM_JOBS_SOCKET")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Config("missing WORKSTREAM_JOBS_SOCKET".into()))?;
        if !socket.is_absolute() {
            return Err(Error::Config(
                "expected absolute PostgreSQL socket directory".into(),
            ));
        }
        let mut cfg = Config::new();
        cfg.host_path(socket)
            .dbname("proofjobs")
            .user("worker")
            .connect_timeout(std::time::Duration::from_secs(5));
        if let Some(port) = std::env::var_os("WORKSTREAM_JOBS_PORT") {
            let port = port
                .to_str()
                .ok_or_else(|| Error::Config("invalid WORKSTREAM_JOBS_PORT".into()))?;
            cfg.port(
                port.parse()
                    .map_err(|_| Error::Config("invalid WORKSTREAM_JOBS_PORT".into()))?,
            );
        }
        if let Some(file) = std::env::var_os("WORKSTREAM_JOBS_PASSWORD_FILE") {
            let password = std::fs::read_to_string(file).map_err(ipc::io_err)?;
            cfg.password(password.trim_end());
        }
        let (client, connection) = cfg.connect(NoTls).await.map_err(db)?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!(error = %e, "proof database connection ended");
            }
        });
        // A session advisory lock is released by PostgreSQL on disconnect.
        // Only its owner may reclaim work or replace this chain's socket.
        let owner = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&(chain as i64)])
            .await
            .map_err(db)?
            .get::<_, bool>(0);
        if !owner {
            return Err(Error::State("another proof worker owns this chain".into()));
        }
        client
            .batch_execute(include_str!("schema.sql"))
            .await
            .map_err(db)?;
        Ok(Self {
            client: tokio::sync::Mutex::new(client),
            chain: chain.to_string(),
        })
    }

    pub(super) async fn submit(
        &self,
        t: &ProveBlockTransition,
        backend: &dyn ZkvmBackend,
    ) -> Result<ZkProof> {
        t.validate()?;
        let guest = t.guest_hash.as_bytes().as_slice();
        let key: &[u8] = &t.block_hash;
        let height = t.height.to_string();
        let witness = encode(t)?;
        let mut client = self.client.lock().await;
        let tx = client.transaction().await.map_err(db)?;
        let created = tx
            .execute(
                "INSERT INTO proof_jobs(chain,guest,commitment,height) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                &[&self.chain as &(dyn ToSql + Sync), &guest, &key, &height],
            )
            .await
            .map_err(db)?;
        if created == 1 {
            tx.execute(
                "INSERT INTO proof_job_witness(chain,guest,commitment,payload) VALUES($1,$2,$3,$4)",
                &[&self.chain as &(dyn ToSql + Sync), &guest, &key, &witness],
            )
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        drop(client);
        self.run(guest, key, backend).await
    }

    /// Complete jobs left with a witness by a previous process. Safe because
    /// proving is deterministic and every completion is checked against its
    /// key before being stored.
    pub(super) async fn recover(&self, backend: &dyn ZkvmBackend) -> Result<()> {
        let rows = self
            .client
            .lock()
            .await
            .query(
                "SELECT guest,commitment FROM proof_job_witness WHERE chain=$1 ORDER BY commitment",
                &[&self.chain],
            )
            .await
            .map_err(db)?;
        for row in rows {
            let guest: Vec<u8> = row.get(0);
            let key: Vec<u8> = row.get(1);
            match self.run(&guest, &key, backend).await {
                Ok(_) | Err(Error::InvalidProof(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn run(&self, guest: &[u8], key: &[u8], backend: &dyn ZkvmBackend) -> Result<ZkProof> {
        let args: Params<'_> = &[&self.chain, &guest, &key];
        let mut client = self.client.lock().await;
        let row = client
            .query_one(
                "SELECT p.result,p.rejection,w.payload FROM proof_jobs p \
                 LEFT JOIN proof_job_witness w USING (chain,guest,commitment) \
                 WHERE p.chain=$1 AND p.guest=$2 AND p.commitment=$3",
                args,
            )
            .await
            .map_err(db)?;
        if let Some(bytes) = row.get::<_, Option<Vec<u8>>>(0) {
            let proof: ZkProof = decode(&bytes)?;
            if !completion_matches(&proof, guest, key) {
                return Err(Error::State("stored proof identity mismatch".into()));
            }
            return Ok(proof);
        }
        if row.get::<_, Option<String>>(1).is_some() {
            return Err(Error::InvalidProof("proof job rejected".into()));
        }
        let payload: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(2)
            .ok_or_else(|| Error::State("proof job has no witness or result".into()))?;
        let t: ProveBlockTransition = decode(&payload)?;
        t.validate()?;
        if t.guest_hash.as_bytes() != guest || t.block_hash != key {
            return Err(Error::State("stored proof job identity mismatch".into()));
        }
        client
            .execute(
                "UPDATE proof_jobs SET attempts=attempts+1, \
                 queue_ms=(extract(epoch FROM clock_timestamp()-queued_at)*1000)::bigint \
                 WHERE chain=$1 AND guest=$2 AND commitment=$3",
                args,
            )
            .await
            .map_err(db)?;

        // Dev-only fault injection: deterministic in-flight window for the
        // worker-restart drill. It is ignored outside the dev profile.
        if matches!(
            std::env::var("WORKSTREAM_PROFILE").as_deref(),
            Ok("dev") | Err(_)
        ) {
            if let Ok(ms) = std::env::var("WORKSTREAM_DEV_PROOF_DELAY_MS") {
                if let Ok(ms) = ms.parse::<u64>() {
                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                }
            }
        }

        let started = std::time::Instant::now();
        let produced = backend.prove_block_transition(&t).await;
        let elapsed = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let proof = match produced {
            Ok(proof) => {
                let matches = completion_matches(&proof, guest, key)
                    && backend.verify_block_transition(&t, &proof)?;
                if matches {
                    proof
                } else {
                    self.reject(
                        &mut client,
                        guest,
                        key,
                        "proof did not match its key or transition",
                        elapsed,
                    )
                    .await?;
                    return Err(Error::InvalidProof("proof did not match its key".into()));
                }
            }
            Err(e @ (Error::InvalidProof(_) | Error::Validation(_))) => {
                let reason = e.to_string();
                self.reject(&mut client, guest, key, &reason, elapsed)
                    .await?;
                return Err(Error::InvalidProof(reason));
            }
            Err(e) => return Err(e),
        };
        let encoded = encode(&proof)?;
        let tx = client.transaction().await.map_err(db)?;
        let written = tx
            .execute(
                "UPDATE proof_jobs SET result=$4,runtime_ms=$5 \
                 WHERE chain=$1 AND guest=$2 AND commitment=$3 AND result IS NULL",
                &[
                    &self.chain as &(dyn ToSql + Sync),
                    &guest,
                    &key,
                    &encoded,
                    &elapsed,
                ],
            )
            .await
            .map_err(db)?;
        if written != 1 {
            return Err(Error::State("proof completion already superseded".into()));
        }
        delete_witness(&tx, &self.chain, guest, key).await?;
        tx.commit().await.map_err(db)?;
        // Proof completion is durable. A crash here leaves a replayable
        // result; the writer's retry resolves to this same keyed proof.
        crash_point("proof-completed");
        Ok(proof)
    }

    async fn reject(
        &self,
        client: &mut Client,
        guest: &[u8],
        key: &[u8],
        reason: &str,
        elapsed: i64,
    ) -> Result<()> {
        let tx = client.transaction().await.map_err(db)?;
        tx.execute(
            "UPDATE proof_jobs SET rejection=$4,runtime_ms=$5 \
             WHERE chain=$1 AND guest=$2 AND commitment=$3 AND result IS NULL",
            &[
                &self.chain as &(dyn ToSql + Sync),
                &guest,
                &key,
                &reason,
                &elapsed,
            ],
        )
        .await
        .map_err(db)?;
        delete_witness(&tx, &self.chain, guest, key).await?;
        tx.commit().await.map_err(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_core::Hash;

    fn proof(commitment: H256, guest: H256) -> ZkProof {
        ZkProof {
            version: 1,
            proof_bytes: vec![1],
            public_inputs: vec![0; 32],
            guest_id: "test".into(),
            guest_hash: guest,
            stateroot_pre: H256::ZERO,
            commitment,
        }
    }

    #[test]
    fn stale_or_wrong_guest_completions_are_rejected() {
        let key = Hash::sha256(b"this tip");
        let guest = Hash::sha256(b"approved guest");
        assert!(completion_matches(
            &proof(key, guest),
            guest.as_bytes(),
            key.as_bytes()
        ));
        assert!(!completion_matches(
            &proof(Hash::sha256(b"another tip"), guest),
            guest.as_bytes(),
            key.as_bytes()
        ));
        assert!(!completion_matches(
            &proof(key, Hash::sha256(b"other guest")),
            guest.as_bytes(),
            key.as_bytes()
        ));
    }
}
