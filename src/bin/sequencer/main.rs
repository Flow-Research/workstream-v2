use clap::Parser;
use tracing::info;
use workstream_core::{logging, Result};

#[derive(Parser, Debug)]
#[command(name = "workstream-sequencer")]
#[command(about = "WorkStream sequencer - orders transactions into blocks", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "8545")]
    port: u16,

    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    logging::init_tracing();

    let args = Args::parse();

    info!("Starting WorkStream Sequencer on port {}", args.port);
    info!("Sovereign zkRollup for governed work coordination");

    // TODO: Implement mempool, block production, DA submission
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
