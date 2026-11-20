//! Opt-in process-local operational endpoints. Metrics never enter chain state.
#[cfg(unix)]
pub mod ipc;
pub mod notifications;
pub mod trace;
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

/// Progress signals used to distinguish the five stall categories on the
/// dashboard. Values are safe scalars only: counts, ages and hashes are never
/// replaced with payloads, keys or witnesses.
pub struct StallMetrics {
    /// Signed transactions waiting for a block.
    pub admission_backlog: AtomicU64,
    /// Age in milliseconds of the oldest unfinished proof job.
    pub proof_delay_ms: AtomicU64,
    /// Retryable DA publication or fetch failures.
    pub da_failures_total: AtomicU64,
    /// Blocks rejected by verification after a proof was produced.
    pub verification_rejections_total: AtomicU64,
    /// Verified blocks not yet reflected in the projection read model.
    pub index_lag_blocks: AtomicU64,
}

impl Default for StallMetrics {
    fn default() -> Self {
        Self {
            admission_backlog: AtomicU64::new(0),
            proof_delay_ms: AtomicU64::new(0),
            da_failures_total: AtomicU64::new(0),
            verification_rejections_total: AtomicU64::new(0),
            index_lag_blocks: AtomicU64::new(0),
        }
    }
}

pub struct Monitor {
    started: Instant,
    // Zero means not ready. Otherwise encodes elapsed seconds + 1.
    last_healthy: AtomicU64,
    pub stall: StallMetrics,
}

impl Monitor {
    pub async fn start(port: Option<u16>) -> Result<Arc<Self>> {
        let monitor = Arc::new(Self {
            started: Instant::now(),
            last_healthy: AtomicU64::new(0),
            stall: StallMetrics::default(),
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

    /// Liveness: the process is running and serving. It deliberately ignores
    /// dependency health so an orchestrator never restarts a process that is
    /// correctly waiting on an external stall (DA, prover, peer).
    fn live() -> bool {
        true
    }

    pub fn set_admission_backlog(&self, count: usize) {
        self.stall.admission_backlog.store(count as u64, Relaxed);
    }

    pub fn observe_proof_delay_ms(&self, ms: u64) {
        self.stall.proof_delay_ms.store(ms, Relaxed);
    }

    pub fn inc_da_failure(&self) {
        self.stall.da_failures_total.fetch_add(1, Relaxed);
    }

    pub fn inc_verification_rejection(&self) {
        self.stall
            .verification_rejections_total
            .fetch_add(1, Relaxed);
    }

    pub fn set_index_lag(&self, blocks: u64) {
        self.stall.index_lag_blocks.store(blocks, Relaxed);
    }

    fn metrics_body(&self) -> String {
        format!(concat!(
            "# HELP workstream_up Whether the process is live.\n\
             # TYPE workstream_up gauge\nworkstream_up {}\n",
            "# HELP workstream_ready Whether local dependencies are healthy.\n\
             # TYPE workstream_ready gauge\nworkstream_ready {}\n",
            "# HELP workstream_rpc_requests_total JSON-RPC requests handled.\n\
             # TYPE workstream_rpc_requests_total counter\nworkstream_rpc_requests_total {}\n",
            "# HELP workstream_rpc_errors_total JSON-RPC requests that failed.\n\
             # TYPE workstream_rpc_errors_total counter\nworkstream_rpc_errors_total {}\n",
            "# HELP workstream_proofs_generated_total Proofs completed.\n\
             # TYPE workstream_proofs_generated_total counter\nworkstream_proofs_generated_total {}\n",
            "# HELP workstream_blocks_submitted_total Blocks published.\n\
             # TYPE workstream_blocks_submitted_total counter\nworkstream_blocks_submitted_total {}\n",
            "# HELP workstream_admission_backlog Signed transactions awaiting a block.\n\
             # TYPE workstream_admission_backlog gauge\nworkstream_admission_backlog {}\n",
            "# HELP workstream_proof_delay_ms Age of the oldest unfinished proof job.\n\
             # TYPE workstream_proof_delay_ms gauge\nworkstream_proof_delay_ms {}\n",
            "# HELP workstream_da_failures_total Retryable DA failures.\n\
             # TYPE workstream_da_failures_total counter\nworkstream_da_failures_total {}\n",
            "# HELP workstream_verification_rejections_total Blocks rejected by verification.\n\
             # TYPE workstream_verification_rejections_total counter\nworkstream_verification_rejections_total {}\n",
            "# HELP workstream_index_lag_blocks Verified blocks not yet projected.\n\
             # TYPE workstream_index_lag_blocks gauge\nworkstream_index_lag_blocks {}\n"),
            u8::from(Self::live()),
            u8::from(self.ready()),
            RPC_REQUESTS.load(Relaxed),
            RPC_ERRORS.load(Relaxed),
            PROOFS.load(Relaxed),
            BLOCKS_SUBMITTED.load(Relaxed),
            self.stall.admission_backlog.load(Relaxed),
            self.stall.proof_delay_ms.load(Relaxed),
            self.stall.da_failures_total.load(Relaxed),
            self.stall.verification_rejections_total.load(Relaxed),
            self.stall.index_lag_blocks.load(Relaxed),
        )
    }

    fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(
                "/livez",
                get(|| async {
                    if Self::live() {
                        (StatusCode::OK, "live\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "not live\n")
                    }
                }),
            )
            .route("/healthz", get(|| async { "ok\n" }))
            .route(
                "/readyz",
                get(|State(m): State<Arc<Self>>| async move {
                    if m.ready() {
                        (StatusCode::OK, "ready\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
                    }
                }),
            )
            .route(
                "/metrics",
                get(|State(m): State<Arc<Self>>| async move {
                    let body = m.metrics_body();
                    (
                        [(
                            header::CONTENT_TYPE,
                            "text/plain; version=0.0.4; charset=utf-8",
                        )],
                        body,
                    )
                }),
            )
            .with_state(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> Monitor {
        Monitor {
            started: Instant::now(),
            last_healthy: AtomicU64::new(0),
            stall: StallMetrics::default(),
        }
    }

    #[test]
    fn metrics_expose_all_five_stall_categories() {
        let m = monitor();
        m.set_admission_backlog(3);
        m.observe_proof_delay_ms(4200);
        m.inc_da_failure();
        m.inc_verification_rejection();
        m.set_index_lag(2);
        let body = m.metrics_body();
        for series in [
            "workstream_admission_backlog 3",
            "workstream_proof_delay_ms 4200",
            "workstream_da_failures_total 1",
            "workstream_verification_rejections_total 1",
            "workstream_index_lag_blocks 2",
            "workstream_up 1",
        ] {
            assert!(body.lines().any(|line| line == series), "missing {series}");
        }
        // Every series carries HELP and TYPE so the dashboard and alert
        // expressions can rely on stable names and types.
        for series in [
            "admission_backlog",
            "proof_delay_ms",
            "da_failures_total",
            "verification_rejections_total",
            "index_lag_blocks",
        ] {
            assert!(
                body.contains(&format!("# TYPE workstream_{series}")),
                "{series}"
            );
        }
    }

    #[test]
    fn readiness_tracks_heartbeat_but_liveness_does_not() {
        let m = monitor();
        assert!(!m.ready());
        m.heartbeat(true);
        assert!(m.ready());
        m.heartbeat(false);
        assert!(!m.ready());
        assert!(Monitor::live());
    }
}
