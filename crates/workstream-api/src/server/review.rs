use super::*;
use axum::{extract::Path as Param, response::Html, Form, Json};
use workstream_core::ActionType;
use workstream_stf::{encode_payload, ReviewDecidePayload, ReviewDecision, ReviewLeasePayload};

async fn queue<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = s
        .backend
        .lookup("review-queue", "")
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (verified, indexed) = s.backend.heights().await;
    Ok(Json(
        serde_json::json!({"rows":rows,"verified":verified,"indexed":indexed}),
    ))
}
async fn details<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Param(id): Param<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = s
        .backend
        .lookup("review-case", &worker::id(&id)?.to_hex())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if rows.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(rows))
}
#[derive(Deserialize)]
struct Intent {
    account: String,
    submission: String,
    nonce: u64,
    action: String,
}
async fn preview<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Form(i): Form<Intent>,
) -> Result<impl IntoResponse, StatusCode> {
    let account = worker::id(&i.account)?;
    let submission = worker::id(&i.submission)?;
    let rows = s
        .backend
        .lookup("review-case", &submission.to_hex())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if rows.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    if rows
        .iter()
        .any(|(k, v)| matches!(k.as_str(), "author" | "sponsor") && v == &account.to_hex())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (kind, payload) = if i.action == "lease" {
        (
            ActionType::ReviewLease,
            encode_payload(&ReviewLeasePayload { submission }),
        )
    } else {
        let decision = match i.action.as_str() {
            "Accept" => ReviewDecision::Accept,
            "Reject" => ReviewDecision::Reject,
            "NeedsRevision" => ReviewDecision::NeedsRevision,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        (
            ActionType::ReviewDecide,
            encode_payload(&ReviewDecidePayload {
                submission,
                decision,
            }),
        )
    };
    worker::unsigned(
        &s,
        account,
        i.nonce,
        kind,
        payload.map_err(|_| StatusCode::BAD_REQUEST)?,
    )
}
pub(super) fn routes<B: Backend>() -> Router<Arc<ApiState<B>>> {
    Router::new()
        .route(
            "/review",
            get(|| async { Html(include_str!("review.html")) }),
        )
        .route(
            "/review.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("review.js"),
                )
            }),
        )
        .route("/review/queue", get(queue::<B>))
        .route("/review/case/{id}", get(details::<B>))
        .route("/review/preview", post(preview::<B>))
}
