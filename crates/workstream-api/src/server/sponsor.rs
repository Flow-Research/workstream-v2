//! Produce one unsigned, human-reviewed action. A preview never calls the writer.
use super::*;
use axum::{response::Html, Form};
use explorer::text;
use workstream_core::{ActionType, FeePayer, FeeSpec, Transaction, H256};
use workstream_crypto::signature::tx_message_hash;
use workstream_stf::{self as stf, encode_payload, handlers::*};
use workstream_tx::{tx_hash, TxBuilder, TxValidator};

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Intent {
    action: String,
    account: String,
    nonce: String,
    target: String,
    detail: String,
    version: String,
    amount: String,
}

fn id(s: &str) -> Option<H256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (s.len() == 64).then(|| H256::from_hex(s).ok()).flatten()
}
fn encode<T: Serialize>(p: &T) -> Result<Vec<u8>, &'static str> {
    encode_payload(p).map_err(|_| "Cannot encode action")
}

fn prepare(chain: u64, i: &Intent) -> Result<(Transaction, String), &'static str> {
    let signer = id(&i.account).ok_or("Enter the sponsor account hash")?;
    let seq = i
        .nonce
        .parse()
        .map_err(|_| "Enter the next confirmed nonce")?;
    let target = || id(&i.target).ok_or("Enter the required target ID");
    let title = || {
        if i.detail.trim().is_empty() || i.detail.len() > 256 {
            Err("Enter a title or release reason of 1–256 bytes")
        } else {
            Ok(i.detail.clone())
        }
    };
    let guide = || -> Result<_, &'static str> {
        Ok(GuideIngestPayload {
            project: target()?,
            version: i
                .version
                .parse::<u32>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or("Enter a positive guide version")?,
            content_hash: id(&i.detail).ok_or("Enter the guide content digest")?,
        })
    };
    let (action, bytes, summary) = match i.action.as_str() {
        "register" => (
            ActionType::ActorRegister,
            encode(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })?,
            "Register signer as sponsor".into(),
        ),
        "project" => {
            let title = title()?;
            (
                ActionType::ProjectCreate,
                encode(&ProjectCreatePayload {
                    title: title.clone(),
                })?,
                format!(
                    "Project: {title} · Owner: {signer} · Project ID: {}",
                    stf::derive_project(&signer, &title)
                ),
            )
        }
        "claim-grant" | "submit-grant" => {
            let grantee = target()?;
            let capability = if i.action == "claim-grant" {
                Capability::ClaimWork
            } else {
                Capability::SubmitWork
            };
            (ActionType::ActorGrant,encode(&ActorGrantPayload{grantee,capability})?,format!("Beneficiary: {grantee} · Grant scope: {capability:?} from {signer} (not limited to one task)"))
        }
        "guide" | "activate" => {
            let p = guide()?;
            let guide = stf::derive_guide(&p.project, p.version, &p.content_hash);
            let summary = format!(
                "Project {} · Guide version {} · Content {} · Guide ID {guide}",
                p.project, p.version, p.content_hash
            );
            if i.action == "guide" {
                (ActionType::GuideIngest, encode(&p)?, summary)
            } else {
                (
                    ActionType::GuideActivate,
                    encode(&GuideActivatePayload {
                        project: p.project,
                        guide,
                    })?,
                    summary,
                )
            }
        }
        "policy" => {
            let policy = target()?;
            (
                ActionType::PolicyApprove,
                encode(&PolicyApprovePayload { policy })?,
                format!("Approve compiled policy version (content ID): {policy}"),
            )
        }
        "task" => {
            let project = target()?;
            let title = title()?;
            let award = i
                .amount
                .parse()
                .map_err(|_| "Enter the integer award amount")?;
            (ActionType::TaskCreate,encode(&TaskCreatePayload{project,title:title.clone(),award})?,format!("Project {project} · Task: {title} · ID {} · Award {award} · Beneficiary determined by verified worker claim",stf::derive_task(&project,&title)))
        }
        "screen" => {
            let task = target()?;
            (
                ActionType::TaskScreen,
                encode(&TaskScreenPayload { task })?,
                format!("Screen {task} under project's active guide at execution"),
            )
        }
        "release" => {
            let task = target()?;
            let reason = title()?;
            (
                ActionType::TaskRelease,
                encode(&TaskReleasePayload {
                    task,
                    reason: reason.clone(),
                })?,
                format!("Release screened task {task} · Reason: {reason}"),
            )
        }
        _ => return Err("Choose a sponsor action"),
    };
    let tx = TxBuilder::new()
        .chain_id(chain)
        .account(signer)
        .nonce(0, seq)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1000,
        })
        .add_action(action, bytes)
        .build()
        .map_err(|_| "Invalid draft")?;
    Ok((tx, summary))
}

async fn preview<B: Backend>(State(s): State<Arc<ApiState<B>>>, Form(i): Form<Intent>) -> Response {
    let Ok(chain) = s.backend.network().parse() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (tx, summary) = match prepare(chain, &i) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let (Ok(digest), Ok(draft)) = (tx_message_hash(&tx), serde_json::to_string(&tx)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    Html(format!(r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sponsor review</title><link rel="stylesheet" href="/explorer.css"><main><header>SPONSOR DESK / REVIEW</header><h1>Review action</h1><aside>Network {chain} · Nonce {} · Maximum fee 1000 (asset 0)</aside><h2>{:?}</h2><section><p>{}</p><p>Signing account: {}</p><p>Approval digest: <code id="digest">{digest}</code></p></section><h2>Local signature</h2><p>Save this unsigned JSON as draft.json. Inspect it with workstream-inspect, then sign with workstream-sign using the network and digest above.</p><textarea readonly aria-label="Unsigned transaction" rows="6" cols="40">{}</textarea><p><label>Signed transaction JSON file <input id="signed" type="file" accept="application/json,.json"></label></p><button id="send" type="button">Submit signed action</button><p id="result" role="status"></p><footer><a href="/sponsor">Sponsor desk</a> · <a href="/explorer">Outcome history</a></footer></main><script src="/sponsor.js" defer></script></html>"#,tx.nonce.seq,tx.actions[0].action_type,text(&summary),tx.account,text(&draft))).into_response()
}

/// Maximum accepted signed-transaction check body. User-controlled payloads
/// are bounded before deserialization so oversized requests fail closed.
const MAX_CHECK_BYTES: usize = 256 * 1024;

// Verify exact bytes for the browser handoff without forwarding or signing.
async fn check(
    axum::extract::Path(expected): axum::extract::Path<String>,
    body: Bytes,
) -> Result<String, StatusCode> {
    let bytes: &[u8] = body.as_ref();
    if bytes.len() > MAX_CHECK_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let tx: Transaction = serde_json::from_slice(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if tx_message_hash(&tx).ok() != Some(id(&expected).ok_or(StatusCode::BAD_REQUEST)?) {
        return Err(StatusCode::CONFLICT);
    }
    TxValidator::new()
        .validate(&tx)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(tx_hash(&tx)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .to_string())
}
pub(super) fn routes<B: Backend>() -> Router<Arc<ApiState<B>>> {
    Router::new()
        .route(
            "/sponsor",
            get(|| async { Html(include_str!("sponsor.html")) }),
        )
        .route(
            "/sponsor.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("sponsor.js"),
                )
            }),
        )
        .route("/sponsor/preview", post(preview::<B>))
        .route("/sponsor/check/{digest}", post(check))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beneficiary_scope_and_guide_version_change_reviewed_bytes() {
        let mut intent = Intent {
            action: "claim-grant".into(),
            account: "11".repeat(32),
            nonce: "4".into(),
            ..Intent::default()
        };
        assert!(prepare(7, &intent).is_err());
        intent.target = "22".repeat(32);
        let (claim, review) = prepare(7, &intent).unwrap();
        assert!(review.contains(&intent.target) && review.contains("ClaimWork"));
        assert_eq!(claim.chain_id, 7);
        intent.action = "submit-grant".into();
        let (submit, _) = prepare(7, &intent).unwrap();
        assert_ne!(
            tx_message_hash(&claim).unwrap(),
            tx_message_hash(&submit).unwrap()
        );
        intent.action = "activate".into();
        intent.detail = "33".repeat(32);
        assert!(prepare(7, &intent).is_err());
        intent.version = "1".into();
        let (first, review) = prepare(7, &intent).unwrap();
        assert!(review.contains("Guide version 1"));
        intent.version = "2".into();
        let (second, _) = prepare(7, &intent).unwrap();
        assert_ne!(
            tx_message_hash(&first).unwrap(),
            tx_message_hash(&second).unwrap()
        );
    }
}
