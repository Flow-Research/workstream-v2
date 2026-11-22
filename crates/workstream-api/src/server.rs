//! Browser-safe HTTPS server for the versioned API (issue #130).
//!
//! Security posture:
//! * TLS 1.3 server-auth listener separate from internal mTLS sockets; the
//!   browser is never given a client credential or a privileged capability.
//! * Exact-origin CORS allowlist (empty by default), never `*`, and no
//!   `Access-Control-Allow-Credentials`; the session is a Bearer token.
//! * Fixed security headers, `no-store`, and a body limit on every response.
//! * Opaque, expiring sessions scoped to idempotency keys; a reused
//!   `X-Request-Id` with a different body is rejected (`DUPLICATE_REQUEST`).
//! * Every error is a versioned envelope with stable string codes; messages
//!   never include transaction payloads, witnesses or signing material.
use std::{
    collections::HashMap,
    io,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::Listener,
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    server::TlsStream,
    TlsAcceptor,
};

use crate::{
    backend::Backend,
    contract::{
        ApiErrorBody, ChainData, Envelope, ErrorCode, PageData, ReceiptData, RequestMeta,
        SessionData, SubmitData, SubmitRequest, API_VERSION,
    },
};

/// Runtime policy for the browser API. Defaults fail closed: no browser
/// origin is trusted until it is explicitly configured.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub allowed_origins: Vec<String>,
    pub session_ttl: Duration,
    pub max_body_bytes: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            session_ttl: Duration::from_secs(300),
            max_body_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone)]
struct CachedResponse {
    fingerprint: [u8; 32],
    status: StatusCode,
    body: String,
}

/// Shared state. Sessions and idempotency entries are kept in-process: the API
/// is a read/forward facade and never becomes an authority for actions.
pub struct ApiState<B: Backend> {
    backend: B,
    config: ApiConfig,
    sessions: Mutex<HashMap<String, Instant>>,
    idempotency: Mutex<HashMap<String, CachedResponse>>,
    sequence: AtomicU64,
}

impl<B: Backend> ApiState<B> {
    pub fn new(backend: B, config: ApiConfig) -> Arc<Self> {
        Arc::new(Self {
            backend,
            config,
            sessions: Mutex::new(HashMap::new()),
            idempotency: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(0),
        })
    }

    /// Expire every session immediately. Used by the expiry contract test so
    /// it does not depend on wall-clock timing.
    #[cfg(test)]
    pub(crate) fn expire_all_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }

    fn issue_session(&self) -> String {
        let token = hex_random(32);
        let expires = Instant::now() + self.config.session_ttl;
        self.sessions.lock().unwrap().insert(token.clone(), expires);
        self.prune_sessions();
        token
    }

    fn prune_sessions(&self) {
        let now = Instant::now();
        self.sessions.lock().unwrap().retain(|_, exp| *exp > now);
    }

    fn session_valid(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }
}

fn hex_random(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).expect("system randomness must be available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b':')
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    (!token.is_empty()).then(|| token.to_string())
}

fn serialize<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

fn json_body(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

fn status_for(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidRequest
        | ErrorCode::UnsupportedVersion
        | ErrorCode::InvalidTransaction
        | ErrorCode::NetworkMismatch => StatusCode::BAD_REQUEST,
        ErrorCode::DuplicateRequest => StatusCode::CONFLICT,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::StaleProjection => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn envelope_error(meta: &RequestMeta, error: ApiErrorBody) -> Response {
    let status = status_for(error.code);
    let env = Envelope::<()>::err(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        error,
    );
    json_body(status, serialize(&env))
}

fn simple_error(meta: &RequestMeta, code: ErrorCode, message: &str) -> Response {
    envelope_error(meta, ApiErrorBody::new(code, message))
}

async fn bootstrap_error<B: Backend>(
    state: &Arc<ApiState<B>>,
    request_id: Option<&str>,
    code: ErrorCode,
    message: &str,
) -> Response {
    let (read_height, indexed_height) = state.backend.heights().await;
    let env = Envelope::<()>::err(
        request_id.unwrap_or("server"),
        state.backend.network(),
        read_height,
        indexed_height,
        ApiErrorBody::new(code, message),
    );
    json_body(status_for(code), serialize(&env))
}

/// Add fixed security headers to every response, including preflights and
/// rejections. Values are static and cannot be influenced by the caller.
fn security_headers(headers: &mut HeaderMap) {
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
}

fn apply_cors(headers: &mut HeaderMap, origin: Option<&str>) {
    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.append(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization, content-type, x-request-id"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    // Deliberately no wildcard origin and no Allow-Credentials.
}

async fn security_and_cors<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let allowed = origin
        .as_deref()
        .map(|o| state.config.allowed_origins.iter().any(|a| a == o))
        .unwrap_or(false);

    if request.method() == Method::OPTIONS {
        let mut response = if allowed {
            StatusCode::NO_CONTENT.into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
        if allowed {
            apply_cors(response.headers_mut(), origin.as_deref());
        }
        security_headers(response.headers_mut());
        return response;
    }

    if origin.is_some() && !allowed {
        let mut response = StatusCode::FORBIDDEN.into_response();
        security_headers(response.headers_mut());
        return response;
    }

    let mut response = next.run(request).await;
    if allowed {
        apply_cors(response.headers_mut(), origin.as_deref());
    }
    security_headers(response.headers_mut());
    response
}

/// Context middleware: validates the session when required, assigns a request
/// id and reads a single consistent `(read_height, indexed_height)` snapshot.
async fn context<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    mut request: Request,
    next: Next,
    require_session: bool,
) -> Response {
    let raw_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let request_id = match raw_id {
        Some(id) if valid_request_id(&id) => id,
        Some(_) => {
            return bootstrap_error(
                &state,
                None,
                ErrorCode::InvalidRequest,
                "invalid X-Request-Id",
            )
            .await
        }
        None => format!("req-{}", hex_random(16)),
    };

    let session = if require_session {
        match bearer(request.headers()) {
            Some(token) if state.session_valid(&token) => token,
            _ => {
                return bootstrap_error(
                    &state,
                    Some(&request_id),
                    ErrorCode::Unauthorized,
                    "session missing or expired",
                )
                .await
            }
        }
    } else {
        String::new()
    };

    let (read_height, indexed_height) = state.backend.heights().await;
    let meta = RequestMeta {
        request_id: request_id.clone(),
        network: state.backend.network(),
        read_height,
        indexed_height,
        session,
        sequence: state.next_sequence(),
    };
    request.extensions_mut().insert(meta);
    next.run(request).await
}

async fn issue_session<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
) -> Response {
    let token = state.issue_session();
    let data = SessionData {
        token,
        api_version: API_VERSION,
        expires_in_secs: state.config.session_ttl.as_secs(),
    };
    let env = Envelope::ok(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        data,
    );
    json_body(StatusCode::OK, serialize(&env))
}

/// Maximum accepted browser submission body. User-controlled payloads are
/// bounded before deserialization so oversized requests fail closed.
const MAX_SUBMISSION_BYTES: usize = 256 * 1024;

async fn submit<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    body: Bytes,
) -> Response {
    let fingerprint = workstream_core::hash::Hash::sha256_concat(&[&body]);
    let key = format!("{}:{}", meta.session, meta.request_id);
    {
        let cache = state.idempotency.lock().unwrap();
        if let Some(cached) = cache.get(&key) {
            if cached.fingerprint == *fingerprint.as_bytes() {
                return json_body(cached.status, cached.body.clone());
            }
            return simple_error(
                &meta,
                ErrorCode::DuplicateRequest,
                "request id reused with a different body",
            );
        }
    }

    // Reject oversized user-controlled submissions before deserializing.
    if body.len() > MAX_SUBMISSION_BYTES {
        return simple_error(
            &meta,
            ErrorCode::InvalidRequest,
            "submission body too large",
        );
    }

    // Validate the user-controlled submission body before typed deserialization:
    // the payload must be a JSON object carrying the required submission fields
    // (version, api_version, tx_bytes); anything else fails closed with
    // `InvalidRequest` before the typed request is decoded.
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return simple_error(&meta, ErrorCode::InvalidRequest, "invalid submission body"),
    };
    let version = parsed.get("version").and_then(serde_json::Value::as_u64);
    let api_version = parsed
        .get("api_version")
        .and_then(serde_json::Value::as_u64);
    let tx_bytes = parsed
        .get("tx_bytes")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|byte| byte.as_u64())
                .map(|byte| byte as u8)
                .collect::<Vec<u8>>()
        });
    let valid_submission = version.is_some_and(|version| version <= u32::MAX as u64)
        && api_version.is_some_and(|api_version| api_version <= u32::MAX as u64)
        && tx_bytes.is_some();
    if !parsed.is_object() || !valid_submission {
        return simple_error(&meta, ErrorCode::InvalidRequest, "invalid submission body");
    }
    let request: SubmitRequest = match serde_json::from_value(parsed) {
        Ok(request) => request,
        Err(_) => return simple_error(&meta, ErrorCode::InvalidRequest, "invalid submission body"),
    };
    let data: SubmitData = match state.backend.submit(request).await {
        Ok(data) => data,
        Err(error) => return envelope_error(&meta, error),
    };
    let env = Envelope::ok(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        data,
    );
    let encoded = serialize(&env);
    state.idempotency.lock().unwrap().insert(
        key,
        CachedResponse {
            fingerprint: *fingerprint.as_bytes(),
            status: StatusCode::OK,
            body: encoded.clone(),
        },
    );
    json_body(StatusCode::OK, encoded)
}

#[derive(Debug, Deserialize)]
struct ReceiptQuery {
    tx_hash: String,
}

async fn receipt<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    Query(query): Query<ReceiptQuery>,
) -> Response {
    let data: ReceiptData = match state.backend.receipt(&query.tx_hash).await {
        Ok(data) => data,
        Err(error) => return envelope_error(&meta, error),
    };
    let env = Envelope::ok(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        data,
    );
    json_body(StatusCode::OK, serialize(&env))
}

async fn chain<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
) -> Response {
    let data: ChainData = match state.backend.chain().await {
        Ok(data) => data,
        Err(error) => return envelope_error(&meta, error),
    };
    let env = Envelope::ok(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        data,
    );
    json_body(StatusCode::OK, serialize(&env))
}

fn default_limit() -> u64 {
    50
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default)]
    cursor: String,
    #[serde(default = "default_limit")]
    limit: u64,
}

async fn projection_page<B: Backend>(
    state: &Arc<ApiState<B>>,
    meta: &RequestMeta,
    kind: &'static str,
    query: PageQuery,
) -> Response {
    let data: PageData = match state.backend.page(kind, &query.cursor, query.limit).await {
        Ok(data) => data,
        Err(error) => return envelope_error(meta, error),
    };
    let env = Envelope::ok(
        &meta.request_id,
        &meta.network,
        meta.read_height,
        meta.indexed_height,
        data,
    );
    json_body(StatusCode::OK, serialize(&env))
}

async fn tasks<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    Query(query): Query<PageQuery>,
) -> Response {
    projection_page(&state, &meta, "work_items", query).await
}

async fn reviews<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    Query(query): Query<PageQuery>,
) -> Response {
    projection_page(&state, &meta, "reviews", query).await
}

async fn receipts<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    Query(query): Query<PageQuery>,
) -> Response {
    projection_page(&state, &meta, "receipts", query).await
}

async fn events<B: Backend>(
    State(state): State<Arc<ApiState<B>>>,
    Extension(meta): Extension<RequestMeta>,
    Query(query): Query<PageQuery>,
) -> Response {
    projection_page(&state, &meta, "events", query).await
}

async fn openapi() -> Response {
    json_body(
        StatusCode::OK,
        serde_json::to_string(&crate::openapi::document()).unwrap_or_default(),
    )
}

/// Assemble the API router. Public routes issue sessions and publish the
/// schema; all data and submission routes require an unexpired session.
pub fn router<B: Backend>(state: Arc<ApiState<B>>) -> Router {
    let public = Router::new()
        .route("/v1/session", post(issue_session::<B>))
        .route("/v1/openapi.json", get(openapi))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            move |s: State<Arc<ApiState<B>>>, r: Request, n: Next| context(s, r, n, false),
        ));

    let protected = Router::new()
        .route("/v1/submit", post(submit::<B>))
        .route("/v1/receipt", get(receipt::<B>))
        .route("/v1/chain", get(chain::<B>))
        .route("/v1/tasks", get(tasks::<B>))
        .route("/v1/reviews", get(reviews::<B>))
        .route("/v1/receipts", get(receipts::<B>))
        .route("/v1/events", get(events::<B>))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            move |s: State<Arc<ApiState<B>>>, r: Request, n: Next| context(s, r, n, true),
        ));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(DefaultBodyLimit::max(state.config.max_body_bytes))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_and_cors::<B>,
        ))
        .with_state(state)
}

/// Load a TLS 1.3 server-auth configuration from the node identity directory.
/// Reuses the node's `cert.der`/`key.der` but never reads its mTLS client
/// verifier: browser connections present no client certificate.
pub fn load_tls_config(dir: &Path) -> Result<ServerConfig, String> {
    use std::os::unix::fs::PermissionsExt;
    let key_path = dir.join("key.der");
    let meta = std::fs::symlink_metadata(&key_path).map_err(|e| format!("TLS key: {e}"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err("browser API key must be a private regular file".into());
    }
    let key =
        PrivateKeyDer::try_from(std::fs::read(&key_path).map_err(|e| format!("TLS key: {e}"))?)
            .map_err(|_| "invalid browser API key".to_string())?;
    let cert = CertificateDer::from(
        std::fs::read(dir.join("cert.der")).map_err(|e| format!("TLS cert: {e}"))?,
    );
    ServerConfig::builder_with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("browser API TLS: {e}"))
}

/// TLS listener adapter so axum can serve rustls streams directly.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: TcpListener, config: ServerConfig) -> Self {
        Self {
            inner,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => match self.acceptor.accept(stream).await {
                    Ok(tls) => return (tls, addr),
                    Err(error) => tracing::warn!(?error, "browser API TLS handshake rejected"),
                },
                Err(error) => {
                    tracing::warn!(?error, "browser API accept failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Serve the browser API over TLS until the listener is shut down.
pub async fn serve_tls<B: Backend>(
    listener: TcpListener,
    config: ServerConfig,
    state: Arc<ApiState<B>>,
) -> Result<(), io::Error> {
    let listener = TlsListener::new(listener, config);
    axum::serve(listener, router(state)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::{to_bytes, Body};
    use serde_json::Value;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct FakeBackend {
        heights: Arc<Mutex<(u64, u64)>>,
        chain_stale: bool,
    }

    impl FakeBackend {
        fn new(read: u64, indexed: u64, stale: bool) -> Self {
            Self {
                heights: Arc::new(Mutex::new((read, indexed))),
                chain_stale: stale,
            }
        }
    }

    #[async_trait]
    impl Backend for FakeBackend {
        fn network(&self) -> String {
            "1".into()
        }
        async fn heights(&self) -> (u64, u64) {
            *self.heights.lock().unwrap()
        }
        async fn submit(&self, _request: SubmitRequest) -> Result<SubmitData, ApiErrorBody> {
            Ok(SubmitData {
                tx_hash: "0xabc".into(),
                status: "Pending".into(),
                height: None,
            })
        }
        async fn receipt(&self, tx_hash: &str) -> Result<ReceiptData, ApiErrorBody> {
            Ok(ReceiptData {
                tx_hash: tx_hash.into(),
                status: "Verified".into(),
                height: Some(1),
            })
        }
        async fn chain(&self) -> Result<ChainData, ApiErrorBody> {
            let (read, indexed) = *self.heights.lock().unwrap();
            Ok(ChainData {
                height: read,
                state_root: "0xroot".into(),
                da_ref: None,
                indexed_height: indexed,
                lag: read.saturating_sub(indexed),
                stale: self.chain_stale,
            })
        }
        async fn page(
            &self,
            kind: &str,
            _cursor: &str,
            _limit: u64,
        ) -> Result<PageData, ApiErrorBody> {
            let (read, indexed) = *self.heights.lock().unwrap();
            Ok(PageData {
                kind: kind.into(),
                items: vec![],
                next_cursor: None,
                stale: read > indexed,
            })
        }
    }

    fn test_config() -> ApiConfig {
        ApiConfig {
            allowed_origins: vec!["https://app.example".into()],
            session_ttl: Duration::from_secs(300),
            max_body_bytes: 256 * 1024,
        }
    }

    async fn json_body(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn issue_session(app: &Router) -> String {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/session")
                    .header("x-request-id", "session-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        body["data"]["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn expired_session_is_rejected() {
        let backend = FakeBackend::new(5, 4, false);
        let state = ApiState::new(backend, test_config());
        let app = router(state.clone());
        let token = issue_session(&app).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        state.expire_all_sessions();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(response).await;
        assert_eq!(body["error"]["code"], "UNAUTHORIZED");
        assert!(body["data"].is_null());
    }

    #[tokio::test]
    async fn idempotency_rejects_reused_request_id_with_different_body() {
        let state = ApiState::new(FakeBackend::new(5, 4, false), test_config());
        let app = router(state);
        let token = issue_session(&app).await;

        let submit_body = |nonce: u64| {
            serde_json::json!({
                "version": 1,
                "api_version": 1,
                "tx_bytes": serde_json::to_vec(&serde_json::json!({"n": nonce})).unwrap()
            })
            .to_string()
        };

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/submit")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "submit-1")
                    .header("content-type", "application/json")
                    .body(Body::from(submit_body(1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let replay = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/submit")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "submit-1")
                    .header("content-type", "application/json")
                    .body(Body::from(submit_body(1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(json_body(replay).await, json_body(first).await);

        let conflict = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/submit")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "submit-1")
                    .header("content-type", "application/json")
                    .body(Body::from(submit_body(2)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let body = json_body(conflict).await;
        assert_eq!(body["error"]["code"], "DUPLICATE_REQUEST");
    }

    #[tokio::test]
    async fn stale_projection_is_visible_in_envelope_and_data() {
        let state = ApiState::new(FakeBackend::new(10, 7, true), test_config());
        let app = router(state);
        let token = issue_session(&app).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/tasks?limit=5")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["read_height"], 10);
        assert_eq!(body["indexed_height"], 7);
        assert_eq!(body["data"]["stale"], true);
        assert_eq!(body["data"]["kind"], "work_items");
    }

    #[tokio::test]
    async fn cors_allowlist_and_security_headers_are_enforced() {
        let state = ApiState::new(FakeBackend::new(5, 5, false), test_config());
        let app = router(state);

        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/chain")
                    .header("origin", "https://app.example")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight.headers()["access-control-allow-origin"],
            "https://app.example"
        );
        assert!(preflight
            .headers()
            .get("access-control-allow-credentials")
            .is_none());
        assert_eq!(preflight.headers()["x-content-type-options"], "nosniff");

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/chain")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    #[tokio::test]
    async fn invalid_request_id_and_openapi_are_handled() {
        let state = ApiState::new(FakeBackend::new(5, 5, false), test_config());
        let app = router(state);

        let bad = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header("x-request-id", "bad id with spaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(bad).await["error"]["code"], "INVALID_REQUEST");

        let doc = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(doc.status(), StatusCode::OK);
        assert_eq!(json_body(doc).await["openapi"], "3.1.0");
    }
}
