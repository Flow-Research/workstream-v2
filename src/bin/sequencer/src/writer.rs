//! One socket owner serializes admission and production for this local chain.
use crate::Sequencer;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::{path::Path, sync::Arc, time::Duration};
use workstream_core::{
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
    let mut seq = Sequencer::with_backend(
        stf,
        Arc::new(WorkerBackend {
            client,
            socket: dir.join("worker.sock"),
            verifier: prover.backend(),
        }),
    );
    journal.restore(&mut seq)?;
    let listener = ipc::listen(&socket)?;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=tick.tick()=>{
                if let Some(first)=seq.mempool.pending.front() {
                    let id=crate::tx_hash(first)?;
                    match seq.build_and_submit_block(Some(1)).await {
                        Ok(b)=>journal.finish(id,&b,&seq)?,
                        Err(e)=>{tracing::warn!(error=%e,"publication deferred");monitor.heartbeat(false);continue;}
                    }
                }
                monitor.heartbeat(true);
            },
            accepted=listener.accept()=>{
                let (socket,_)=accepted.map_err(ipc::io_err)?;
                let Ok(mut s)=tls.accept(socket).await else {continue};
                let Ok(req)=ipc::read::<Request>(&mut s,ipc::ADMISSION_LIMIT).await else {continue};
                match req {
                    Request::Submit(tx)=>{let r=journal.admit(&mut seq,*tx).map_err(|e|e.to_string());let _=ipc::write(&mut s,&r).await;},
                    Request::Block(n)=>{let b=journal.block(n)?;let _=ipc::write(&mut s,&Ok::<_,String>(b)).await;},
                    Request::Receipt(id)=>{let r=journal.receipt(id)?;let _=ipc::write(&mut s,&Ok::<_,String>(r)).await;},
                    Request::Queue=>{let r=journal.queue()?;let _=ipc::write(&mut s,&Ok::<_,String>(r)).await;},
                    Request::Tip=>{let _=ipc::write(&mut s,&Ok::<_,String>((seq.tip(),seq.state().root()))).await;}
                }
            }
        }
    }
}
