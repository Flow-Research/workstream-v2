use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use workstream_core::config::{load_config, ProverConfig};
use workstream_core::{logging, Result};

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

    // TODO: Implement zkVM integration (RISC Zero/SP1), proof generation, recursion
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}
