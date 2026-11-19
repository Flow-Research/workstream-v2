//! One socket owner serializes admission and production for this local chain.
use crate::{da_from_env, Sequencer};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::{path::Path, sync::Arc, time::Duration};
use workstream_core::{
    dev::crash_point,
    types::{Block, Transaction},
    Result,
};
use workstream_core::{Error, H256};
use workstream_ops::{ipc, Monitor};
use workstream_prover::{worker::WorkerBackend, Prover};
use workstream_stf::StateTransitionFunction;
mod journal;

#[derive(Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: H256,
    pub status: String,
    pub height: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    Submit(Box<Transaction>),
    Block(u64),
    /// Published DA reference only. A node with object DA configured must
    /// fetch the exact bytes from the provider, not from this journal.
    DaRef(u64),
    Tip,
    Receipt(H256),
    Queue,
}

pub async fn serve(
    dir: &Path,
    stf: StateTransitionFunction,
    prover: Prover,
    monitor: Arc<Monitor>,
) -> Result<()> {
    let tls = ipc::tls::Server::load()?;
    let client = ipc::tls::Client::load("prover.workstream.internal")?;
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("writer.lock"))
        .map_err(ipc::io_err)?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| Error::State("writer already running".into()))?;
    let socket = dir.join("writer.sock");
    if std::fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
        std::fs::remove_file(&socket).map_err(ipc::io_err)?;
    }
    let data = std::path::PathBuf::from(
        std::env::var_os("WORKSTREAM_WRITER_DATA")
            .ok_or_else(|| Error::Config("missing WORKSTREAM_WRITER_DATA".into()))?,
    );
    let meta = std::fs::symlink_metadata(&data).map_err(ipc::io_err)?;
    if !data.is_absolute() || !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(Error::Config(
            "writer data directory must be absolute and private".into(),
        ));
    }
    let data_lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(data.join("owner.lock"))
        .map_err(ipc::io_err)?;
    fs2::FileExt::try_lock_exclusive(&data_lock)
        .map_err(|_| Error::State("writer data already in use".into()))?;
    let mut journal = journal::Journal::open(&data, stf.fork_schedule().chain_id)?;
    let backend: Arc<dyn workstream_core::traits::prover::ZkvmBackend> = Arc::new(WorkerBackend {
        client,
        socket: dir.join("worker.sock"),
        verifier: prover.backend(),
    });
    let mut seq = Sequencer::with_da_and_backend(stf, da_from_env()?, backend);
    journal.restore(&mut seq)?;
    let listener = ipc::listen(&socket)?;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=tick.tick()=>{
                // Admission backlog is a safe count, not a payload. It is the
                // first stall category on the operations dashboard.
                monitor.set_admission_backlog(seq.pending());
                let Some(first)=seq.mempool.pending.front() else {
                    monitor.heartbeat(true);
                    continue;
                };
                let id=crate::tx_hash(first)?;
                let outcome = async {
                    let mut prepared = seq.prepare_block(Some(1)).await?;
                    journal.record_publication(prepared.block())?;
                    if let Err(e) = prepared.publish().await {
                        monitor.inc_da_failure();
                        return Err(e);
                    }
                    // After DA acceptance but before the local checkpoint is
                    // committed. Replay in a fresh writer reproduces the same
                    // publication key and bytes.
                    crash_point("da-accepted");
                    let block = prepared.commit(&mut seq)?;
                    journal.finish(id, &block, &seq)?;
                    crash_point("local-commit");
                    Ok::<_, workstream_core::Error>(block)
                }.await;
                match outcome {
                    Ok(_) => monitor.heartbeat(true),
                    Err(e) => { tracing::warn!(error=%e,"publication deferred"); monitor.heartbeat(false); }
                }
            },
            accepted=listener.accept()=>{
                let (socket,_)=accepted.map_err(ipc::io_err)?;
                let Ok(mut s)=tls.accept(socket).await else {continue};
                let Ok(req)=ipc::read::<Request>(&mut s,ipc::ADMISSION_LIMIT).await else {continue};
                match req {
                    Request::Submit(tx)=>{
                        // Correlate this transaction's whole journey by its
                        // immutable signed hash. Only the hash is a field: the
                        // transaction body (and any witness) is never logged.
                        // A malformed transaction must not stop the writer, so
                        // correlation is best-effort; admission does validation.
                        let _guard = crate::tx_hash(&tx).ok().map(|id| {
                            let context = workstream_ops::trace::Correlation::new(id.as_bytes(), "admit");
                            let span = context.span();
                            tracing::info!(tx_hash = %id, "transaction admitted");
                            span.entered()
                        });
                        let r=journal.admit(&mut seq,*tx).map_err(|e|e.to_string());
                        if r.is_ok() {
                            // Signed bytes are durable before the acknowledgement.
                            crash_point("admission");
                        }
                        let _=ipc::write(&mut s,&r).await;
                    },
                    Request::Block(n)=>{let b=journal.block(n)?;let _=ipc::write(&mut s,&Ok::<_,String>(b)).await;},
                    Request::DaRef(n)=>{let r=journal.da_ref(n)?.map(|d|(n,d));let _=ipc::write(&mut s,&Ok::<_,String>(r)).await;},
                    Request::Receipt(id)=>{let r=journal.receipt(id)?;let _=ipc::write(&mut s,&Ok::<_,String>(r)).await;},
                    Request::Queue=>{let r=journal.queue()?;let _=ipc::write(&mut s,&Ok::<_,String>(r)).await;},
                    Request::Tip=>{let _=ipc::write(&mut s,&Ok::<_,String>((seq.tip(),seq.state().root()))).await;}
                }
            }
        }
    }
}
