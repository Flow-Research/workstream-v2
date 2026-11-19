//! Route proof generation to a local worker; verification remains independent.
use super::*;
use std::path::{Path, PathBuf};
use workstream_ops::{ipc, Monitor};
mod jobs;

pub struct WorkerBackend {
    pub client: ipc::tls::Client,
    pub socket: PathBuf,
    pub verifier: Arc<dyn ZkvmBackend>,
}
#[async_trait]
impl ZkvmBackend for WorkerBackend {
    async fn prove_block_transition(&self, t: &ProveBlockTransition) -> Result<ZkProof> {
        ipc::call(&self.client, &self.socket, t).await
    }
    fn verify_block_transition(&self, t: &ProveBlockTransition, p: &ZkProof) -> Result<bool> {
        self.verifier.verify_block_transition(t, p)
    }
}
pub async fn serve(dir: &Path, chain: u64, prover: Prover, monitor: Arc<Monitor>) -> Result<()> {
    let tls = ipc::tls::Server::load()?;
    let jobs = jobs::Jobs::open(chain).await?;
    let socket = dir.join("worker.sock");
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
        std::fs::remove_file(&socket).map_err(ipc::io_err)?;
    }
    let listener = ipc::listen(&socket)?;
    let backend = prover.backend();
    jobs.recover(backend.as_ref()).await?;
    loop {
        monitor.heartbeat(true);
        let Ok(connection) =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
        else {
            continue;
        };
        let (socket, _) = connection.map_err(ipc::io_err)?;
        let Ok(mut s) = tls.accept(socket).await else {
            continue;
        };
        let Ok(t) = ipc::read::<ProveBlockTransition>(&mut s, ipc::BLOCK_LIMIT).await else {
            continue;
        };
        let result = jobs
            .submit(&t, backend.as_ref())
            .await
            .map_err(|e| e.to_string());
        let _ = ipc::write(&mut s, &result).await;
    }
}
