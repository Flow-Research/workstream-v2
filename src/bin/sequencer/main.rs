use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::info;
use workstream_core::config::{load_config, SequencerConfig};
use workstream_core::{logging, Result};
use workstream_sequencer::{InMemoryDaClient, Sequencer};

#[derive(Parser, Debug)]
#[command(name = "workstream-sequencer")]
#[command(about = "WorkStream sequencer - orders transactions into blocks", long_about = None)]
struct Args {
    /// Serve Prometheus metrics and health checks on loopback.
    #[arg(long)]
    metrics_port: Option<u16>,
    #[arg(short, long)]
    port: Option<u16>,

    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Loading order: defaults -> TOML file -> env -> CLI
    let mut config: SequencerConfig = load_config(args.config.as_deref())?;
    if let Some(port) = args.port {
        config.port = port;
    }
    config.validate()?;

    // Configure logging from config
    std::env::set_var("RUST_LOG", &config.log_level);
    logging::init_tracing();
    let (stf, prover) = workstream_prover::runtime::load()?;
    let monitor = workstream_ops::Monitor::start(args.metrics_port).await?;

    info!("Starting WorkStream Sequencer on port {}", config.port);
    info!("Sovereign zkRollup for governed work coordination");

    // Event loop: mempool -> block production -> DA submission, with the
    // censorship-resistance escape hatch (DA-direct transaction submissions).
    let mut sequencer =
        Sequencer::with_da_and_backend(stf, Arc::new(InMemoryDaClient::new()), prover.backend());

    let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        if sequencer.pending() > 0 {
            let block = sequencer.build_and_submit_block(None).await?;
            info!(
                "Built and submitted block {} to DA (da_ref {})",
                block.header.number, block.header.da_ref
            );
        }
        monitor.heartbeat(true);
    }
}
