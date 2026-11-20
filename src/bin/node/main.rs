use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{debug, info};
use workstream_core::config::{load_config, NodeConfig};
use workstream_core::traits::da::DaClient;
use workstream_core::traits::p2p::P2pNetwork;
use workstream_core::traits::prover::ProverApi;
use workstream_core::traits::sequencer::SequencerApi;
use workstream_core::traits::verifier::VerifierApi;
use workstream_core::{logging, Result};
use workstream_node::rpc::RpcServer;
use workstream_node::EventIndexer;
use workstream_prover::ReceiptVerifier;
use workstream_sequencer::{InMemoryDaClient, InMemoryP2pNetwork, SequencerApiImpl};

#[derive(Parser, Debug)]
#[command(name = "workstream-node")]
#[command(about = "WorkStream full node - validates proofs and maintains canonical state", long_about = None)]
struct Args {
    /// Serve Prometheus metrics and health checks on loopback.
    #[arg(long)]
    metrics_port: Option<u16>,
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
    let (stf, prover) = workstream_prover::runtime::load()?;
    let monitor = workstream_ops::Monitor::start(args.metrics_port).await?;

    info!(
        "Starting WorkStream Full Node on P2P port {}",
        config.p2p_port
    );
    info!("Verifying proofs and maintaining canonical state");

    // RPC server (issue #85): JSON-RPC 2.0 over TCP, dispatching over the
    // versioned component traits (sequencer/prover/verifier/DA/P2P).
    let verifier = ReceiptVerifier::new(stf.fork_schedule().genesis_fork().guest_hash);
    let sequencer = SequencerApiImpl::from_sequencer(
        workstream_sequencer::Sequencer::with_backend(stf, prover.backend()),
    );
    let indexer = Arc::new(EventIndexer::new());
    let rpc_server = RpcServer::new(
        Arc::new(sequencer) as Arc<dyn SequencerApi>,
        Arc::new(prover) as Arc<dyn ProverApi>,
        Arc::new(verifier) as Arc<dyn VerifierApi>,
        Arc::new(InMemoryDaClient::new()) as Arc<dyn DaClient>,
        Arc::new(InMemoryP2pNetwork::new()) as Arc<dyn P2pNetwork>,
        indexer,
    );
    let rpc_task = if let Some(port) = config.rpc_port {
        let server = rpc_server.clone();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| workstream_core::Error::Io(format!("RPC bind: {e}")))?;
        Some(tokio::spawn(async move { server.serve(listener).await }))
    } else {
        info!("RPC server disabled (no rpc_port configured)");
        None
    };

    // Idle loop keeps the process alive until real event loops land.
    let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        monitor.heartbeat(rpc_task.as_ref().is_none_or(|task| !task.is_finished()));
        debug!("node heartbeat");
    }
}
