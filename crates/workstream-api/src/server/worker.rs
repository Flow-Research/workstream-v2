//! Worker desk: public read hints and unsigned drafts only.
use super::*;
use axum::{extract::Path as Param, response::Html, Form, Json};
use workstream_core::{ActionType, FeePayer, FeeSpec, H256};
use workstream_crypto::signature::tx_message_hash;
use workstream_stf::{encode_payload, BundleAdmitPayload, SubmissionCreatePayload, TaskIdPayload};
use workstream_tx::TxBuilder;

fn id(s: &str) -> Result<H256, StatusCode> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    H256::from_hex(s).map_err(|_| StatusCode::BAD_REQUEST)
}
#[derive(Deserialize)]
struct Draft {
    account: String,
    task: String,
    nonce: u64,
    action: String,
    content: String,
}
async fn preview<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Form(d): Form<Draft>,
) -> Result<impl IntoResponse, StatusCode> {
    let account = id(&d.account)?;
    let task = id(&d.task)?;
    let (kind, payload) = match d.action.as_str() {
        "claim" => (
            ActionType::TaskClaim,
            encode_payload(&TaskIdPayload { task }),
        ),
        "start" => (
            ActionType::TaskStart,
            encode_payload(&TaskIdPayload { task }),
        ),
        "bundle" => (
            ActionType::BundleAdmit,
            encode_payload(&BundleAdmitPayload {
                task,
                content_hash: id(&d.content)?,
            }),
        ),
        "submit" => (
            ActionType::SubmissionCreate,
            encode_payload(&SubmissionCreatePayload {
                task,
                content_hash: id(&d.content)?,
            }),
        ),
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let chain = s
        .backend
        .network()
        .parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = TxBuilder::new()
        .chain_id(chain)
        .account(account)
        .nonce(0, d.nonce)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1000,
        })
        .add_action(kind, payload.map_err(|_| StatusCode::BAD_REQUEST)?)
        .build()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let digest = tx_message_hash(&tx).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(
        serde_json::json!({"digest":digest.to_string(),"draft":serde_json::to_string(&tx).map_err(|_|StatusCode::BAD_REQUEST)?}),
    ))
}
async fn tasks<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Param(account): Param<String>,
) -> Result<impl IntoResponse, StatusCode> {
    id(&account)?;
    let rows = s
        .backend
        .lookup("worker", &account)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (verified, indexed) = s.backend.heights().await;
    Ok(Json(
        serde_json::json!({"verified":verified,"indexed":indexed,"rows":rows}),
    ))
}
pub(super) fn routes<B: Backend>() -> Router<Arc<ApiState<B>>> {
    Router::new()
        .route("/worker", get(home::<B>))
        .route("/worker/tasks/{account}", get(tasks::<B>))
        .route("/worker/preview", post(preview::<B>))
        .route(
            "/worker.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("worker.js"),
                )
            }),
        )
}
async fn home<B: Backend>(State(s): State<Arc<ApiState<B>>>) -> Html<String> {
    Html(include_str!("worker.html").replace("@NETWORK@", &explorer::text(&s.backend.network())))
}
