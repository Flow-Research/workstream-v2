use clap::Parser;
use tracing::info;
use workstream_core::{logging, Result};

#[derive(Parser, Debug)]
#[command(name = "workstream-node")]
#[command(about = "WorkStream full node - validates proofs and maintains canonical state", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "30303")]
    p2p_port: u16,

    #[arg(long)]
    sync: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_tracing();

    let args = Args::parse();

    info!(
        "Starting WorkStream Full Node on P2P port {}",
        args.p2p_port
    );
    info!("Verifying proofs and maintaining canonical state");

    // TODO: Implement P2P, block sync, proof verification, RPC
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
