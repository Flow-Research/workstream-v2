use std::path::PathBuf;

use clap::Parser;
use tracing::{debug, info};
use workstream_core::config::{load_config, ProverConfig};
use workstream_core::traits::prover::ProverApi;
use workstream_core::{logging, Result};
use workstream_prover::{Prover, DEFAULT_GUEST_ID};
use workstream_stf::{mvp_genesis_schedule, StateTransitionFunction};

#[derive(Parser, Debug)]
#[command(name = "workstream-prover")]
#[command(about = "WorkStream prover - generates zkVM proofs for state transitions", long_about = None)]
struct Args {
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

    info!("Starting WorkStream Prover");
    info!("Using zkVM: {}", config.zkvm);
    info!("Guest program: {DEFAULT_GUEST_ID}");

    // zkVM proof generation runtime (issue #80): the prover drives guest
    // transitions through a pluggable backend and reports status. The default
    // backend is in-memory; set WORKSTREAM_PROVER_BACKEND=risc0 (plus the
    // guest image/id variables) to opt into real receipt generation.
    let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule()?)?;
    let prover = Prover::from_env(stf)?;

    // Idle loop keeps the process alive until real event loops land; each
    // tick reports prover availability through the live backend.
    let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        let status = prover.get_prover_status().await?;
        debug!("prover heartbeat: available={}", status.available);
    }
}
