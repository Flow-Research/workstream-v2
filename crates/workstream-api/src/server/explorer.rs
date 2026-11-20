//! Script-free, opt-in public explorer. Only validated identifiers enter URLs.
use super::*;
use axum::response::Html;
use std::fmt::Write;

#[derive(Default, Deserialize)]
#[serde(default)]
pub(super) struct Search {
    kind: String,
    key: String,
    cursor: String,
}

fn text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn hash(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn results<B: Backend>(backend: &B, q: &Search) -> Result<String, ApiErrorBody> {
    let invalid = || ApiErrorBody::new(ErrorCode::InvalidRequest, "invalid lookup");
    let mut html = String::new();
    match q.kind.as_str() {
        "" => {
            if q.cursor.len() > 48 || !q.cursor.bytes().all(|b| b.is_ascii_digit() || b == b':') {
                return Err(invalid());
            }
            let page = backend.page("receipts", &q.cursor, 25).await?;
            html.push_str("<h2>Receipt history</h2><ol>");
            for row in page.items {
                if let (Some(id), Some(height)) = (
                    row["tx_hash"].as_str().filter(|id| hash(id)),
                    row["height"].as_u64(),
                ) {
                    write!(html,"<li><a href=\"/explorer?kind=receipt&amp;key={id}\">{id}</a> · Block {height}</li>").unwrap();
                }
            }
            html.push_str("</ol>");
            if let Some(c) = page
                .next_cursor
                .filter(|s| s.bytes().all(|b| b.is_ascii_digit() || b == b':'))
            {
                write!(html, "<a href=\"/explorer?cursor={c}\">Next page →</a>").unwrap();
            }
        }
        "receipt" if hash(&q.key) => {
            let r = backend.receipt(&q.key).await?;
            write!(
                html,
                "<h2>Transaction receipt</h2><p>{}</p><strong>{}</strong>",
                text(&r.tx_hash),
                text(&r.status)
            )
            .unwrap();
            if let Some(h) = r.height {
                write!(
                    html,
                    " · <a href=\"/explorer?kind=block&amp;key={h}\">Block {h}</a>"
                )
                .unwrap();
            }
        }
        "block" | "task" | "account" => {
            if !(if q.kind == "block" {
                q.key.parse::<i64>().is_ok_and(|v| v > 0)
            } else {
                hash(&q.key)
            }) {
                return Err(invalid());
            }
            let rows = backend.lookup(&q.kind, &q.key).await?;
            write!(
                html,
                "<h2>{} lookup</h2><p>{}</p>",
                text(&q.kind),
                text(&q.key)
            )
            .unwrap();
            if rows.is_empty() {
                html.push_str("<strong>Unknown</strong> · No matching local record");
            }
            for (name, value) in rows {
                write!(html, "<p><b>{}</b> · {}</p>", text(&name), text(&value)).unwrap();
            }
        }
        _ => return Err(invalid()),
    }
    Ok(html)
}

pub(super) async fn view<B: Backend>(
    State(s): State<Arc<ApiState<B>>>,
    Query(q): Query<Search>,
) -> Response {
    let (verified, indexed) = s.backend.heights().await;
    let freshness = if verified == indexed {
        "Current"
    } else {
        "Stale"
    };
    let (status, content) = match results(&s.backend, &q).await {
        Ok(content) => (StatusCode::OK, content),
        Err(err) => (
            status_for(err.code),
            match err.code {
                ErrorCode::NotFound => "Unknown · No receipt recorded",
                ErrorCode::InvalidRequest => "Invalid lookup",
                _ => "Read unavailable · Retry later",
            }
            .into(),
        ),
    };
    (status,Html(format!(r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Chain register · WorkStream</title><link rel="stylesheet" href="/explorer.css"><main><header>WORKSTREAM / PUBLIC REGISTER</header><h1>Chain register</h1><aside>Verified height <b>{verified}</b> · Indexed height <b>{indexed}</b> · {freshness}</aside><form action="/explorer"><label>Index <select name="kind"><option value="receipt">Transaction</option><option>block</option><option>account</option><option>task</option></select></label> <label>Hash or block height <input name="key" required maxlength="66"></label> <button>Look up</button></form><section>{content}</section><footer><a href="/explorer">Receipt history</a> · Read-only local archive</footer></main></html>"#))).into_response()
}

pub(super) async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("explorer.css"),
    )
}
