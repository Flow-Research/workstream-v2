use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use workstream_core::config::{load_config, SequencerConfig};
use workstream_core::{logging, Result};

#[derive(Parser, Debug)]
#[command(name = "workstream-sequencer")]
#[command(about = "WorkStream sequencer - orders transactions into blocks", long_about = None)]
struct Args {
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

    info!("Starting WorkStream Sequencer on port {}", config.port);
    info!("Sovereign zkRollup for governed work coordination");

    // TODO: Implement mempool, block production, DA submission
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
