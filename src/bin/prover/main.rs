use std::path::PathBuf;

use clap::Parser;
use tracing::{debug, info};
use workstream_core::config::{load_config, ProverConfig};
use workstream_core::traits::prover::ProverApi;
use workstream_core::{logging, Result};

#[derive(Parser, Debug)]
#[command(name = "workstream-prover")]
#[command(about = "WorkStream prover - generates zkVM proofs for state transitions", long_about = None)]
struct Args {
    /// Serve Prometheus metrics and health checks on loopback.
    #[arg(long)]
    metrics_port: Option<u16>,
    #[arg(short, long)]
    blocks: Option<String>,

    #[arg(long)]
    zkvm: Option<String>,

    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Loading order: defaults -> TOML file -> env -> CLI
    let mut config: ProverConfig = load_config(args.config.as_deref())?;
    if let Some(zkvm) = args.zkvm {
        config.zkvm = zkvm;
    }
    if let Some(blocks) = args.blocks {
        config.blocks = Some(blocks);
    }
    config.validate()?;

    // Configure logging from config
    std::env::set_var("RUST_LOG", &config.log_level);
    logging::init_tracing();
    let (_, prover) =
        workstream_prover::runtime::load_checked(Some(&config.zkvm), config.guest_id.as_deref())?;
    let monitor = workstream_ops::Monitor::start(args.metrics_port).await?;

    info!("Starting WorkStream Prover");
    // Idle loop keeps the process alive until real event loops land; each
    // tick reports prover availability through the live backend.
    let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        let status = prover.get_prover_status().await?;
        monitor.heartbeat(status.available);
        debug!("prover heartbeat: available={}", status.available);
    }
}
