//! Private evidence byte store. Grants are local workspace policy, installed
//! by the operator, and are never inferred from a projected or claimed role.
use super::*;
use axum::{extract::Path as Route, Json};
use rusqlite::{params, Connection, OptionalExtension};
use std::os::unix::fs::PermissionsExt;
use workstream_core::{Hash, H256};

pub struct EvidenceStore(Mutex<Connection>);
type Outcome<T> = Result<T, StatusCode>;
const INTERNAL: StatusCode = StatusCode::INTERNAL_SERVER_ERROR;
const DENIED: StatusCode = StatusCode::FORBIDDEN;
const TTL: i64 = 60;

impl EvidenceStore {
    pub fn open(dir: &Path) -> Result<Self, &'static str> {
        let m =
            std::fs::symlink_metadata(dir).map_err(|_| "private evidence directory required")?;
        if !m.is_dir() || m.permissions().mode() & 0o077 != 0 {
            return Err("evidence directory must be private");
        }
        let db = Connection::open_with_flags(
            dir.canonicalize()
                .map_err(|_| "invalid evidence directory")?
                .join("objects.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
                | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(|_| "cannot open evidence store")?;
        db.execute_batch(include_str!("evidence.sql"))
            .map_err(|_| "cannot initialize evidence store")?;
        Ok(Self(Mutex::new(db)))
    }

    fn upload(&self, subject: &str, task: &str, digest: &str, body: &[u8]) -> Outcome<()> {
        if Hash::sha256(body).to_hex() != digest {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        let db = self.0.lock().map_err(|_| INTERNAL)?;
        // Authorize and store in one statement; replay never changes bytes.
        let n=db.execute("INSERT INTO objects(task,digest,body) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM grants WHERE subject=?4 AND task=?1 AND digest=?2 AND operation='upload') ON CONFLICT(task,digest) DO UPDATE SET digest=excluded.digest WHERE objects.body=excluded.body",params![task,digest,body,subject]).map_err(|_|INTERNAL)?;
        if n == 1 {
            Ok(())
        } else {
            Err(DENIED)
        }
    }

    fn issue(&self, subject: &str, task: &str, digest: &str) -> Outcome<String> {
        let token = hex_random(32);
        let db = self.0.lock().map_err(|_| INTERNAL)?;
        let n=db.execute("INSERT OR REPLACE INTO tickets(subject,task,digest,token_hash,expires) SELECT ?1,?2,?3,?4,unixepoch()+?5 FROM grants JOIN objects USING(task,digest) WHERE subject=?1 AND task=?2 AND digest=?3 AND operation='read'",params![subject,task,digest,Hash::sha256(token.as_bytes()).to_hex(),TTL]).map_err(|_|INTERNAL)?;
        if n == 1 {
            Ok(token)
        } else {
            Err(DENIED)
        }
    }

    fn download(&self, token: &str) -> Outcome<Vec<u8>> {
        let db = self.0.lock().map_err(|_| INTERNAL)?;
        let (digest,body):(String,Vec<u8>)=db.query_row("SELECT digest,body FROM tickets JOIN objects USING(task,digest) WHERE token_hash=? AND expires>unixepoch()",[Hash::sha256(token.as_bytes()).to_hex()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|INTERNAL)?.ok_or(DENIED)?;
        if Hash::sha256(&body).to_hex() != digest {
            return Err(StatusCode::CONFLICT);
        }
        Ok(body)
    }
}

fn canonical(s: &str) -> Outcome<String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    H256::from_hex(hex)
        .map(|h| h.to_hex())
        .map_err(|_| StatusCode::BAD_REQUEST)
}
fn subject<B: Backend>(s: &ApiState<B>, h: &HeaderMap) -> Outcome<String> {
    s.config
        .workspace_login
        .as_ref()
        .and_then(|v| v.subject(&bearer(h)?))
        .ok_or(StatusCode::UNAUTHORIZED)
}
fn store<B: Backend>(s: &ApiState<B>) -> Outcome<Arc<EvidenceStore>> {
    s.config.evidence.clone().ok_or(INTERNAL)
}

async fn upload<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Route((task, digest)): Route<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Outcome<impl IntoResponse> {
    let who = subject(&s, &headers)?;
    let db = store(&s)?;
    let task = canonical(&task)?;
    let digest = canonical(&digest)?;
    tokio::task::spawn_blocking(move || {
        db.upload(&who, &task, &digest, &body)?;
        Ok(Json(
            serde_json::json!({"status":"Uploaded","task":task,"content_hash":digest}),
        ))
    })
    .await
    .map_err(|_| INTERNAL)?
}
async fn issue<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Route((task, digest)): Route<(String, String)>,
    headers: HeaderMap,
) -> Outcome<impl IntoResponse> {
    let who = subject(&s, &headers)?;
    let db = store(&s)?;
    let task = canonical(&task)?;
    let digest = canonical(&digest)?;
    let token = tokio::task::spawn_blocking(move || db.issue(&who, &task, &digest))
        .await
        .map_err(|_| INTERNAL)??;
    Ok(Json(
        serde_json::json!({"url":format!("/v1/evidence/download/{token}"),"expires_in_secs":TTL}),
    ))
}
async fn download<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Route(token): Route<String>,
) -> Outcome<impl IntoResponse> {
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DENIED);
    }
    let db = store(&s)?;
    let body = tokio::task::spawn_blocking(move || db.download(&token))
        .await
        .map_err(|_| INTERNAL)??;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, "attachment"),
        ],
        body,
    ))
}
pub(super) fn routes<B: Backend>(s: &Arc<ApiState<B>>) -> Router<Arc<ApiState<B>>> {
    if s.config.evidence.is_none() || s.config.workspace_login.is_none() {
        return Router::new();
    }
    Router::new()
        .route("/v1/evidence/{task}/{digest}/upload", post(upload::<B>))
        .route("/v1/evidence/{task}/{digest}/link", post(issue::<B>))
        .route("/v1/evidence/download/{token}", get(download::<B>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_core::{ActionType, FeePayer, FeeSpec};
    use workstream_crypto::signature::sign_tx_ed25519;
    use workstream_stf::{encode_payload, SubmissionCreatePayload};
    use workstream_tx::{TxBuilder, TxValidator};

    #[test]
    fn changed_object_cannot_satisfy_signed_submission() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = EvidenceStore::open(tmp.path()).unwrap();
        let bytes = b"original";
        let task = Hash::sha256(b"task");
        let digest = Hash::sha256(bytes);
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let payload = |hash| {
            encode_payload(&SubmissionCreatePayload {
                task,
                content_hash: hash,
            })
            .unwrap()
        };
        let mut tx = TxBuilder::new()
            .chain_id(1)
            .account(Hash::sha256(key.verifying_key().as_bytes()))
            .nonce(0, 0)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1,
            })
            .add_action(ActionType::SubmissionCreate, payload(digest))
            .build()
            .unwrap();
        sign_tx_ed25519(&mut tx, &key).unwrap();
        TxValidator::new().validate(&tx).unwrap();
        store
            .0
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO grants VALUES('worker',?,?,'upload')",
                params![task.to_hex(), digest.to_hex()],
            )
            .unwrap();
        store
            .upload("worker", &task.to_hex(), &digest.to_hex(), bytes)
            .unwrap();
        assert_eq!(
            store.upload("worker", &task.to_hex(), &digest.to_hex(), b"changed"),
            Err(StatusCode::UNPROCESSABLE_ENTITY)
        );
        tx.actions[0].payload = payload(Hash::sha256(b"changed"));
        assert!(TxValidator::new().validate(&tx).is_err());
    }
}
