//! Opt-in process-local operational endpoints. Metrics never enter chain state.
use axum::{
    extract::State,
    http::{header, StatusCode},
    routing::get,
    Router,
};
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};
use tokio::net::TcpListener;
use workstream_core::{Error, Result};

pub static RPC_REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static RPC_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static PROOFS: AtomicU64 = AtomicU64::new(0);
pub static BLOCKS_SUBMITTED: AtomicU64 = AtomicU64::new(0);

pub struct Monitor {
    started: Instant,
    // Zero means not ready. Otherwise encodes elapsed seconds + 1.
    last_healthy: AtomicU64,
}

impl Monitor {
    pub async fn start(port: Option<u16>) -> Result<Arc<Self>> {
        let monitor = Arc::new(Self {
            started: Instant::now(),
            last_healthy: AtomicU64::new(0),
        });
        if let Some(port) = port {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|e| Error::Io(format!("monitor bind: {e}")))?;
            let app = monitor.router();
            tracing::info!(address = ?listener.local_addr(), "monitor listening");
            tokio::spawn(async move {
                if let Err(error) = axum::serve(listener, app).await {
                    tracing::error!(%error, "monitor stopped");
                }
            });
        }
        Ok(monitor)
    }

    /// Call from the component loop after checking its local dependencies.
    pub fn heartbeat(&self, healthy: bool) {
        self.last_healthy.store(
            if healthy {
                self.started.elapsed().as_secs() + 1
            } else {
                0
            },
            Relaxed,
        );
    }

    fn ready(&self) -> bool {
        let last = self.last_healthy.load(Relaxed);
        last != 0 && self.started.elapsed().as_secs().saturating_sub(last - 1) < 30
    }

    fn router(self: &Arc<Self>) -> Router {
        Router::new().route("/healthz", get(|| async { "ok\n" }))
            .route("/readyz", get(|State(m): State<Arc<Self>>| async move {
                if m.ready() { (StatusCode::OK, "ready\n") } else { (StatusCode::SERVICE_UNAVAILABLE, "not ready\n") }
            }))
            .route("/metrics", get(|State(m): State<Arc<Self>>| async move {
                let body = format!(concat!(
                    "# TYPE workstream_ready gauge\nworkstream_ready {}\n",
                    "# TYPE workstream_rpc_requests_total counter\nworkstream_rpc_requests_total {}\n",
                    "# TYPE workstream_rpc_errors_total counter\nworkstream_rpc_errors_total {}\n",
                    "# TYPE workstream_proofs_generated_total counter\nworkstream_proofs_generated_total {}\n",
                    "# TYPE workstream_blocks_submitted_total counter\nworkstream_blocks_submitted_total {}\n"),
                    u8::from(m.ready()), RPC_REQUESTS.load(Relaxed), RPC_ERRORS.load(Relaxed), PROOFS.load(Relaxed), BLOCKS_SUBMITTED.load(Relaxed));
                ([(header::CONTENT_TYPE,"text/plain; version=0.0.4; charset=utf-8")],body)
            })).with_state(self.clone())
    }
}
