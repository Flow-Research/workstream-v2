use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use workstream_core::config::{load_config, NodeConfig};
use workstream_core::{logging, Result};

#[derive(Parser, Debug)]
#[command(name = "workstream-node")]
#[command(about = "WorkStream full node - validates proofs and maintains canonical state", long_about = None)]
struct Args {
    #[arg(short, long)]
    p2p_port: Option<u16>,

    #[arg(long)]
    sync: bool,

    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Loading order: defaults -> TOML file -> env -> CLI
    let mut config: NodeConfig = load_config(args.config.as_deref())?;
    if let Some(port) = args.p2p_port {
        config.p2p_port = port;
    }
    if args.sync {
        config.sync = true;
    }
    config.validate()?;

    // Configure logging from config
    std::env::set_var("RUST_LOG", &config.log_level);
    logging::init_tracing();

    info!(
        "Starting WorkStream Full Node on P2P port {}",
        config.p2p_port
    );
    info!("Verifying proofs and maintaining canonical state");

    // TODO: Implement P2P, block sync, proof verification, RPC
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
