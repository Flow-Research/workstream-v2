//! Verified-block PostgreSQL projections (issue #128).
//!
//! Projection state is derived exclusively from blocks that passed full node
//! verification. Every block's rows and the indexed cursor are committed in a
//! single PostgreSQL transaction, so an abrupt restart exposes either the
//! whole block or none of it. Projection tables are never consulted by the
//! state transition function; they cannot authorize a transaction.
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_postgres::{types::ToSql, Client, Config, NoTls, Transaction};
use workstream_core::{
    dev::crash_point,
    types::{AccountId, Block, BlockNumber, Event, LeaseId, StateRoot, SubmissionId},
    Error, Result, H256,
};
use workstream_stf::handlers::{derive_lease, Capability, ReviewDecision};

const SCHEMA_VERSION: i32 = 1;
const MAX_PAGE: u64 = 200;

fn db(e: tokio_postgres::Error) -> Error {
    let detail = e
        .as_db_error()
        .map(|e| e.message().to_string())
        .unwrap_or_else(|| e.to_string());
    Error::Io(format!("projection database: {detail}"))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::Serialization(format!("projection encode: {e}")))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Serialization(format!("projection decode: {e}")))
}

fn decode_event<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    postcard::from_bytes(bytes)
        .map_err(|e| Error::Serialization(format!("projection event decode: {e}")))
}

fn h256(bytes: Vec<u8>) -> Result<H256> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::State("projection hash length mismatch".into()))?;
    Ok(H256::from_bytes(array))
}

fn raw(hash: &H256) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

fn number(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| Error::Validation("projection height exceeds database range".into()))
}

fn genesis_root() -> Result<Vec<u8>> {
    encode(&StateRoot::new(H256::ZERO, H256::ZERO))
}

/// Cursor over `(height, tx_index, event ordinal)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub height: u64,
    pub tx_index: u32,
    pub ordinal: u32,
}

impl Cursor {
    fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Ok(Self::default());
        }
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::Validation("invalid pagination cursor".into()));
        }
        Ok(Self {
            height: parts[0]
                .parse()
                .map_err(|_| Error::Validation("invalid cursor height".into()))?,
            tx_index: parts[1]
                .parse()
                .map_err(|_| Error::Validation("invalid cursor transaction".into()))?,
            ordinal: parts[2]
                .parse()
                .map_err(|_| Error::Validation("invalid cursor ordinal".into()))?,
        })
    }

    fn encode(self) -> String {
        format!("{}:{}:{}", self.height, self.tx_index, self.ordinal)
    }
}

/// Deterministic projection status derived from committed cursor metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectionStatus {
    pub chain: String,
    pub schema_version: i32,
    pub verified_height: u64,
    pub indexed_height: u64,
    pub lag: u64,
    pub indexed_state_root: StateRoot,
    pub indexed_da_ref: H256,
    pub updated_at: String,
}

/// One verifier-accepted block and the events emitted while applying it.
pub struct ProjectionInput<'a> {
    pub height: BlockNumber,
    pub state_root: &'a StateRoot,
    pub da_ref: H256,
    pub block: &'a Block,
    pub events: &'a [Event],
    pub tx_hashes: &'a [H256],
}

#[derive(Clone)]
pub struct Projection {
    client: std::sync::Arc<tokio::sync::Mutex<Client>>,
    chain: String,
}

impl Projection {
    /// Connect to the private projection database when it is configured.
    ///
    /// Projections are optional so unit tests and standalone nodes remain
    /// usable without PostgreSQL. A connected service that configures a
    /// socket fails closed if it cannot own the chain projection.
    pub async fn open(chain: u64) -> Result<Option<Self>> {
        let Ok(socket) = std::env::var("WORKSTREAM_PROJECTIONS_SOCKET") else {
            return Ok(None);
        };
        let path = Path::new(&socket)
            .canonicalize()
            .map_err(|e| Error::Config(format!("invalid WORKSTREAM_PROJECTIONS_SOCKET: {e}")))?;
        let mut config = Config::new();
        config.host_path(path);
        config.dbname("projections");
        config.user("projection");
        config.connect_timeout(std::time::Duration::from_secs(5));
        if let Ok(port) = std::env::var("WORKSTREAM_PROJECTIONS_PORT") {
            let port: u16 = port
                .parse()
                .map_err(|_| Error::Config("invalid WORKSTREAM_PROJECTIONS_PORT".into()))?;
            config.port(port);
        }
        if let Ok(path) = std::env::var("WORKSTREAM_PROJECTIONS_PASSWORD_FILE") {
            let password = std::fs::read_to_string(path)
                .map_err(|e| Error::Config(format!("projection password file: {e}")))?;
            config.password(password.trim());
        }
        let (client, connection) = config.connect(NoTls).await.map_err(db)?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!(error = %e, "projection database connection ended");
            }
        });
        let chain = chain.to_string();
        let chain_number = number(chain.parse::<u64>().unwrap_or(0))?;
        let locked: bool = client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&chain_number])
            .await
            .map_err(db)?
            .get(0);
        if !locked {
            return Err(Error::Config(
                "another projection indexer owns this chain".into(),
            ));
        }
        client
            .batch_execute(include_str!("projection/schema.sql"))
            .await
            .map_err(db)?;
        client
            .execute(
                "INSERT INTO projection_meta(chain,schema_version,indexed_state_root,indexed_da_ref) \
                 VALUES($1,$2,$3,$4) ON CONFLICT(chain) DO NOTHING",
                &[
                    &chain,
                    &SCHEMA_VERSION,
                    &genesis_root()?,
                    &raw(&H256::ZERO),
                ],
            )
            .await
            .map_err(db)?;
        Ok(Some(Self {
            client: std::sync::Arc::new(tokio::sync::Mutex::new(client)),
            chain,
        }))
    }

    /// Apply one block atomically with its cursor. Re-applying an identical
    /// already-indexed block is a no-op; divergent bytes fail closed.
    pub async fn apply(&self, input: ProjectionInput<'_>) -> Result<()> {
        let height = number(input.height)?;
        let block_bytes = encode(input.block)?;
        let state_bytes = encode(input.state_root)?;
        let da_ref = raw(&input.da_ref);
        let mut client = self.client.lock().await;
        let tx = client.transaction().await.map_err(db)?;
        let row = tx
            .query_opt(
                "SELECT indexed_height FROM projection_meta WHERE chain=$1 FOR UPDATE",
                &[&self.chain],
            )
            .await
            .map_err(db)?
            .ok_or_else(|| Error::State("projection metadata row is missing".into()))?;
        let indexed_height: i64 = row.get(0);

        if height <= indexed_height {
            let stored: Option<Vec<u8>> = tx
                .query_opt(
                    "SELECT block FROM verified_blocks WHERE chain=$1 AND height=$2",
                    &[&self.chain, &height],
                )
                .await
                .map_err(db)?
                .map(|row| row.get(0));
            match stored {
                Some(bytes) if bytes == block_bytes => {}
                Some(_) => {
                    return Err(Error::Determinism(format!(
                        "projection replay diverged at height {}",
                        input.height
                    )))
                }
                None if indexed_height == 0 => {}
                None => {
                    return Err(Error::State(format!(
                        "projection cursor {} has no verified block record",
                        indexed_height
                    )))
                }
            }
            tx.execute(
                "UPDATE projection_meta SET verified_height=GREATEST(verified_height,$2) \
                 WHERE chain=$1",
                &[&self.chain, &height],
            )
            .await
            .map_err(db)?;
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        if height != indexed_height + 1 {
            return Err(Error::State(format!(
                "projection expected height {}, received {}",
                indexed_height + 1,
                input.height
            )));
        }

        // Rebuilds replay blocks already present in the preserved log. The
        // bytes are identical (they came from this table), so conflict is a
        // no-op; a genuinely divergent block is rejected by the replay check
        // above and by the unique DA reference constraint.
        tx.execute(
            "INSERT INTO verified_blocks(chain,height,block,state_root,da_ref) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(chain,height) DO NOTHING",
            &[&self.chain, &height, &block_bytes, &state_bytes, &da_ref],
        )
        .await
        .map_err(db)?;

        for (ordinal, event) in input.events.iter().enumerate() {
            if event.block_number != input.height {
                return Err(Error::State("projection event block mismatch".into()));
            }
            let index = event.tx_index as usize;
            let tx_hash = input
                .tx_hashes
                .get(index)
                .ok_or_else(|| Error::State("projection event transaction mismatch".into()))?;
            let account = input
                .block
                .transactions
                .get(index)
                .map(|tx| tx.account)
                .ok_or_else(|| Error::State("projection event transaction missing".into()))?;
            let ordinal = ordinal as u32;
            self.insert_event(&tx, event, ordinal, tx_hash).await?;
            self.insert_domain(&tx, event, ordinal, tx_hash, &account, input.height)
                .await?;
        }
        for (index, tx_hash) in input.tx_hashes.iter().enumerate() {
            tx.execute(
                "INSERT INTO projection_receipts(chain,tx_hash,height,tx_index,ordinal,status) \
                 VALUES($1,$2,$3,$4,0,'Verified') ON CONFLICT(chain,tx_hash) DO NOTHING",
                &[&self.chain, &raw(tx_hash), &height, &number(index as u64)?],
            )
            .await
            .map_err(db)?;
        }

        // Deterministic fault point: rows are inserted but the cursor has not
        // advanced. Aborting here must roll the entire block back.
        crash_point("projection-mid-batch");

        tx.execute(
            "UPDATE projection_meta SET verified_height=GREATEST(verified_height,$2), \
             indexed_height=$2, indexed_state_root=$3, indexed_da_ref=$4, \
             updated_at=clock_timestamp() WHERE chain=$1",
            &[&self.chain, &height, &state_bytes, &da_ref],
        )
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn insert_event(
        &self,
        tx: &Transaction<'_>,
        event: &Event,
        ordinal: u32,
        tx_hash: &H256,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO projection_events(chain,height,tx_index,ordinal,tx_hash,event_type,data) \
             VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(chain,height,tx_index,ordinal) DO NOTHING",
            &[
                &self.chain,
                &number(event.block_number)?,
                &number(event.tx_index as u64)?,
                &number(ordinal as u64)?,
                &raw(tx_hash),
                &event.event_type,
                &&event.data[..],
            ],
        )
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn insert_domain(
        &self,
        tx: &Transaction<'_>,
        event: &Event,
        ordinal: u32,
        tx_hash: &H256,
        account: &AccountId,
        height: u64,
    ) -> Result<()> {
        let height_i = number(height)?;
        let index_i = number(event.tx_index as u64)?;
        let ord_i = number(ordinal as u64)?;
        let id = format!("{}:{}:{}", height, event.tx_index, ordinal);
        // Every indexed event begins with the subject hash (32 raw bytes in
        // postcard). Decoding only the leading H256 keeps this projection
        // stable when trailing fields differ, e.g. `task.released` carries a
        // reason string while `task.claimed` carries an account. Postcard's
        // `from_bytes` intentionally ignores trailing bytes. `review.leased`
        // is the sole event whose subject is the second field.
        let subject: Option<H256> = match event.event_type.as_str() {
            "project.created" | "task.created" | "task.screened" | "task.released"
            | "task.claimed" | "task.started" | "bundle.prepared" | "bundle.admitted"
            | "submission.created" | "review.decided" | "accept.finalized" | "award.fulfilled" => {
                Some(decode_event::<H256>(&event.data)?)
            }
            "review.leased" => Some(decode_event::<(H256, H256)>(&event.data)?.1),
            _ => None,
        };
        if let Some(subject) = subject {
            tx.execute(
                "INSERT INTO projection_work_items(chain,id,height,tx_index,ordinal,kind,subject,actor,tx_hash,data) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(chain,id) DO NOTHING",
                &[
                    &self.chain,
                    &id,
                    &height_i,
                    &index_i,
                    &ord_i,
                    &event.event_type,
                    &raw(&subject),
                    &raw(account),
                    &raw(tx_hash),
                    &&event.data[..],
                ],
            )
            .await
            .map_err(db)?;
        }
        match event.event_type.as_str() {
            "actor.granted" | "actor.revoked" => {
                let (grantee, capability): (AccountId, Capability) = decode_event(&event.data)?;
                let active = event.event_type == "actor.granted";
                tx.execute(
                    "INSERT INTO projection_grants(chain,grantee,grantor,capability,active,height,tx_index,ordinal,tx_hash) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                     ON CONFLICT(chain,grantee,grantor,capability) DO UPDATE SET \
                     active=EXCLUDED.active,height=EXCLUDED.height,tx_index=EXCLUDED.tx_index, \
                     ordinal=EXCLUDED.ordinal,tx_hash=EXCLUDED.tx_hash",
                    &[
                        &self.chain,
                        &raw(&grantee),
                        &raw(account),
                        &format!("{capability:?}"),
                        &active,
                        &height_i,
                        &index_i,
                        &ord_i,
                        &raw(tx_hash),
                    ],
                )
                .await
                .map_err(db)?;
            }
            "review.leased" => {
                let (lease, submission, reviewer): (LeaseId, SubmissionId, AccountId) =
                    decode_event(&event.data)?;
                self.insert_review(
                    tx,
                    &format!("lease:{}", lease.to_hex()),
                    submission,
                    reviewer,
                    Some(lease),
                    None,
                    None,
                    height_i,
                    index_i,
                    ord_i,
                    tx_hash,
                )
                .await?;
            }
            "review.decided" => {
                let (submission, record_index, decision): (SubmissionId, u64, ReviewDecision) =
                    decode_event(&event.data)?;
                self.insert_review(
                    tx,
                    &format!("decision:{}:{}:{}", height, event.tx_index, ordinal),
                    submission,
                    *account,
                    Some(derive_lease(&submission, account)),
                    Some(format!("{decision:?}")),
                    Some(record_index),
                    height_i,
                    index_i,
                    ord_i,
                    tx_hash,
                )
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_review(
        &self,
        tx: &Transaction<'_>,
        id: &str,
        submission: SubmissionId,
        reviewer: AccountId,
        lease: Option<LeaseId>,
        decision: Option<String>,
        record_index: Option<u64>,
        height: i64,
        tx_index: i64,
        ordinal: i64,
        tx_hash: &H256,
    ) -> Result<()> {
        let lease = lease.unwrap_or(H256::ZERO);
        let decision = decision.unwrap_or_default();
        let record_index = record_index.map(number).transpose()?;
        tx.execute(
            "INSERT INTO projection_reviews(chain,id,height,tx_index,ordinal,submission,reviewer,lease,decision,record_index,tx_hash) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(chain,id) DO NOTHING",
            &[
                &self.chain,
                &id,
                &height,
                &tx_index,
                &ordinal,
                &raw(&submission),
                &raw(&reviewer),
                &raw(&lease),
                &decision,
                &record_index,
                &raw(tx_hash),
            ],
        )
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Committed status as seen by read clients.
    pub async fn status(&self) -> Result<ProjectionStatus> {
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                "SELECT schema_version,verified_height,indexed_height,indexed_state_root,indexed_da_ref,updated_at::text \
                 FROM projection_meta WHERE chain=$1",
                &[&self.chain],
            )
            .await
            .map_err(db)?
            .ok_or_else(|| Error::State("projection metadata row is missing".into()))?;
        let schema_version: i32 = row.get(0);
        let verified_height: i64 = row.get(1);
        let indexed_height: i64 = row.get(2);
        let state_root = decode::<StateRoot>(row.get::<_, Vec<u8>>(3).as_slice())?;
        let da_ref = h256(row.get(4))?;
        let updated_at: String = row.get(5);
        let verified = u64::try_from(verified_height.max(0)).unwrap_or(0);
        let indexed = u64::try_from(indexed_height.max(0)).unwrap_or(0);
        Ok(ProjectionStatus {
            chain: self.chain.clone(),
            schema_version,
            verified_height: verified,
            indexed_height: indexed,
            lag: verified.saturating_sub(indexed),
            indexed_state_root: state_root,
            indexed_da_ref: da_ref,
            updated_at,
        })
    }

    /// Expose archive metadata, never the archived transaction or proof bytes.
    pub async fn lookup(&self, kind: &str, key: &str) -> Result<Vec<(String, String)>> {
        let invalid = || Error::Validation("invalid explorer lookup".into());
        if kind == "review-queue" {
            let rows=self.client.lock().await.query("SELECT encode(s.subject,'hex'),s.height FROM projection_work_items s WHERE s.chain=$1 AND s.kind='submission.created' AND NOT EXISTS(SELECT 1 FROM projection_work_items a WHERE a.chain=s.chain AND a.kind='accept.finalized' AND a.subject=s.subject) ORDER BY s.height DESC,s.tx_index DESC,s.ordinal DESC LIMIT 25", &[&self.chain]).await.map_err(db)?;
            return Ok(rows
                .iter()
                .map(|r| (r.get(0), r.get::<_, i64>(1).to_string()))
                .collect());
        }
        if kind == "review-case" {
            return self
                .review_case(H256::from_hex(key).map_err(|_| invalid())?)
                .await;
        }
        if kind == "block" {
            let height: i64 = key.parse().ok().filter(|n| *n > 0).ok_or_else(invalid)?;
            let row = self
                .client
                .lock()
                .await
                .query_opt(
                    "SELECT block FROM verified_blocks WHERE chain=$1 AND height=$2",
                    &[&self.chain, &height],
                )
                .await
                .map_err(db)?;
            let Some(row) = row else {
                return Ok(vec![]);
            };
            let block: Block = decode(row.get::<_, &[u8]>(0))?;
            let h = block.header;
            return Ok(vec![
                ("Archive".into(), "Present in local verified archive".into()),
                ("Height".into(), h.number.to_string()),
                ("DA reference".into(), h.da_ref.to_string()),
                ("Proof guest".into(), h.guest_hash.to_string()),
                (
                    "Proof system version".into(),
                    h.proof_system_version.to_string(),
                ),
                ("Fork".into(), h.fork_id.to_string()),
            ]);
        }
        let id = H256::from_hex(key.strip_prefix("0x").unwrap_or(key)).map_err(|_| invalid())?;
        if kind == "worker" {
            let rows=self.client.lock().await.query("SELECT encode(last.subject,'hex'),last.kind FROM (SELECT DISTINCT ON (subject) subject,actor,kind,height FROM projection_work_items WHERE chain=$1 AND kind IN ('task.released','task.claimed','task.started') ORDER BY subject,height DESC,tx_index DESC,ordinal DESC) last WHERE (last.kind='task.released' AND EXISTS(SELECT 1 FROM projection_grants g WHERE g.chain=$1 AND g.grantor=last.actor AND g.grantee=$2 AND g.capability='ClaimWork' AND g.active)) OR (last.kind!='task.released' AND last.actor=$2) ORDER BY last.height DESC,last.subject LIMIT 25",&[&self.chain,&id.as_bytes().as_slice()]).await.map_err(db)?;
            return Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect());
        }
        let column = match kind {
            "account" => "actor",
            "task" => "subject",
            _ => return Err(invalid()),
        };
        let query = format!("SELECT kind,height FROM projection_work_items WHERE chain=$1 AND {column}=$2 ORDER BY height DESC,tx_index DESC,ordinal DESC LIMIT 25");
        let rows = self
            .client
            .lock()
            .await
            .query(&query, &[&self.chain, &id.as_bytes().as_slice()])
            .await
            .map_err(db)?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    format!("Block {}", r.get::<_, i64>(1)),
                    r.get::<_, String>(0),
                )
            })
            .collect())
    }

    /// Resolve evidence from the signed submission in the verifier archive and
    /// guide version from the task's screening event (never today's active guide).
    async fn review_case(&self, id: H256) -> Result<Vec<(String, String)>> {
        use workstream_stf::{derive_submission, SubmissionCreatePayload};
        let client = self.client.lock().await;
        let Some(row)=client.query_opt("SELECT s.tx_index,b.block FROM projection_work_items s JOIN verified_blocks b USING(chain,height) WHERE s.chain=$1 AND s.kind='submission.created' AND s.subject=$2", &[&self.chain,&raw(&id)]).await.map_err(db)? else{return Ok(vec![])};
        let block: Block = decode(row.get(1))?;
        let tx = usize::try_from(row.get::<_, i64>(0))
            .ok()
            .and_then(|i| block.transactions.get(i))
            .ok_or_else(|| Error::State("missing archived submission".into()))?;
        let payload = tx
            .actions
            .iter()
            .filter(|a| a.action_type == workstream_core::ActionType::SubmissionCreate)
            .map(|a| decode_event::<SubmissionCreatePayload>(&a.payload))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|p| derive_submission(&p.task, &p.content_hash) == id)
            .ok_or_else(|| Error::State("submission commitment mismatch".into()))?;
        let screen=client.query_one("SELECT actor,data FROM projection_work_items WHERE chain=$1 AND kind='task.screened' AND subject=$2", &[&self.chain,&raw(&payload.task)]).await.map_err(db)?;
        let (_, guide): (H256, H256) = decode_event(screen.get(1))?;
        let version=client.query_one("SELECT data FROM projection_events WHERE chain=$1 AND event_type='guide.ingested' AND substring(data from 1 for 32)=$2", &[&self.chain,&raw(&guide)]).await.map_err(db)?;
        let (_, _, version): (H256, H256, u32) = decode_event(version.get(0))?;
        let mut out = vec![
            ("submission".into(), id.to_hex()),
            ("author".into(), tx.account.to_hex()),
            ("sponsor".into(), h256(screen.get(0))?.to_hex()),
            ("task".into(), payload.task.to_hex()),
            ("digest".into(), payload.content_hash.to_hex()),
            ("guide".into(), guide.to_hex()),
            ("version".into(), version.to_string()),
        ];
        for r in client.query("SELECT reviewer,decision,tx_hash FROM projection_reviews WHERE chain=$1 AND submission=$2 ORDER BY height DESC,tx_index DESC,ordinal DESC LIMIT 25", &[&self.chain,&raw(&id)]).await.map_err(db)? {
            let d:String=r.get(1);out.push((format!("{} · {}",if d.is_empty(){"Leased"}else{&d},h256(r.get(0))?.to_hex()),h256(r.get(2))?.to_hex()));
        }
        Ok(out)
    }

    /// Read a whitelisted projection with stable cursor pagination.
    pub async fn page(
        &self,
        kind: &str,
        cursor: &str,
        event_type: &str,
        limit: u64,
    ) -> Result<Value> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(Error::Validation(format!(
                "projection page limit must be between 1 and {MAX_PAGE}"
            )));
        }
        let cursor = Cursor::parse(cursor)?;
        let (table, details) = match kind {
            "events" => (
                "projection_events",
                "json_build_object('event_type',event_type,'data',encode(data,'hex'),'tx_hash',encode(tx_hash,'hex'))::text",
            ),
            "work_items" => (
                "projection_work_items",
                "json_build_object('kind',kind,'subject',encode(subject,'hex'),'actor',encode(actor,'hex'),'tx_hash',encode(tx_hash,'hex'))::text",
            ),
            "grants" => (
                "projection_grants",
                "json_build_object('grantee',encode(grantee,'hex'),'grantor',encode(grantor,'hex'),'capability',capability,'active',active,'tx_hash',encode(tx_hash,'hex'))::text",
            ),
            "reviews" => (
                "projection_reviews",
                "json_build_object('submission',encode(submission,'hex'),'reviewer',encode(reviewer,'hex'),'lease',encode(lease,'hex'),'decision',decision,'record_index',record_index,'tx_hash',encode(tx_hash,'hex'))::text",
            ),
            "receipts" => (
                "projection_receipts",
                "json_build_object('tx_hash',encode(tx_hash,'hex'),'status',status)::text",
            ),
            _ => return Err(Error::Validation("unknown projection page".into())),
        };
        let filtered = kind == "events" && !event_type.is_empty();
        // Keep parameter numbers contiguous: an unused placeholder makes
        // PostgreSQL unable to infer its type during statement preparation.
        let (filter, limit_param) = if filtered {
            (" AND event_type=$5", "$6")
        } else {
            ("", "$5")
        };
        let statement = format!(
            "SELECT height,tx_index,ordinal,{details} FROM {table} \
             WHERE chain=$1 AND (height,tx_index,ordinal) > ($2,$3,$4){filter} \
             ORDER BY height,tx_index,ordinal LIMIT {limit_param}"
        );
        let height = number(cursor.height)?;
        let tx_index = i64::from(cursor.tx_index);
        let ordinal = i64::from(cursor.ordinal);
        let limit_i = number(limit)?;
        let params: Vec<&(dyn ToSql + Sync)> = if filtered {
            vec![
                &self.chain,
                &height,
                &tx_index,
                &ordinal,
                &event_type,
                &limit_i,
            ]
        } else {
            vec![&self.chain, &height, &tx_index, &ordinal, &limit_i]
        };
        let client = self.client.lock().await;
        let rows = client.query(&statement, &params).await.map_err(db)?;
        let mut last = cursor;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            let row_height: i64 = row.get(0);
            let row_tx: i64 = row.get(1);
            let row_ordinal: i64 = row.get(2);
            last = Cursor {
                height: row_height.max(0) as u64,
                tx_index: row_tx.max(0) as u32,
                ordinal: row_ordinal.max(0) as u32,
            };
            let detail: String = row.get(3);
            let mut value: Value = serde_json::from_str(&detail)
                .map_err(|e| Error::Serialization(format!("projection page decode: {e}")))?;
            if let Some(object) = value.as_object_mut() {
                object.insert("height".into(), json!(last.height));
                object.insert("tx_index".into(), json!(last.tx_index));
                object.insert("ordinal".into(), json!(last.ordinal));
            }
            items.push(value);
        }
        let next = if rows.len() as u64 == limit && !items.is_empty() {
            Some(last.encode())
        } else {
            None
        };
        Ok(json!({"kind":kind,"items":items,"next_cursor":next}))
    }

    /// Remove derived rows while preserving the immutable verified block log,
    /// then return the blocks for deterministic rebuild.
    pub async fn reset(&self) -> Result<Vec<Block>> {
        let mut client = self.client.lock().await;
        let tx = client.transaction().await.map_err(db)?;
        for table in [
            "projection_events",
            "projection_work_items",
            "projection_grants",
            "projection_reviews",
            "projection_receipts",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE chain=$1"),
                &[&self.chain],
            )
            .await
            .map_err(db)?;
        }
        tx.execute(
            "UPDATE projection_meta SET verified_height=0,indexed_height=0, \
             indexed_state_root=$2,indexed_da_ref=$3,updated_at=clock_timestamp() WHERE chain=$1",
            &[&self.chain, &genesis_root()?, &raw(&H256::ZERO)],
        )
        .await
        .map_err(db)?;
        let rows = tx
            .query(
                "SELECT block FROM verified_blocks WHERE chain=$1 ORDER BY height",
                &[&self.chain],
            )
            .await
            .map_err(db)?;
        let blocks = rows
            .into_iter()
            .map(|row| decode::<Block>(row.get::<_, Vec<u8>>(0).as_slice()))
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await.map_err(db)?;
        Ok(blocks)
    }
}
