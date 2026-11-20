//! One socket owner serializes admission and production for this local chain.
use crate::Sequencer;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use workstream_core::{
    types::{Block, Transaction},
    Result,
};
use workstream_ops::{ipc, Monitor};
use workstream_prover::{worker::WorkerBackend, Prover};
use workstream_stf::StateTransitionFunction;

#[derive(Serialize, Deserialize)]
pub enum Request {
    Submit(Box<Transaction>),
    Block(u64),
    Tip,
}

pub async fn serve(
    dir: &Path,
    stf: StateTransitionFunction,
    prover: Prover,
    monitor: Arc<Monitor>,
) -> Result<()> {
    let tls = ipc::tls::Server::load()?;
    let client = ipc::tls::Client::load("prover.workstream.internal")?;
    let listener = ipc::listen(&dir.join("writer.sock"))?;
    let mut seq = Sequencer::with_backend(
        stf,
        Arc::new(WorkerBackend {
            client,
            socket: dir.join("worker.sock"),
            verifier: prover.backend(),
        }),
    );
    let mut blocks = Vec::<Block>::new();
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=tick.tick()=>{
                if seq.pending()>0 {
                    match seq.build_and_submit_block(Some(1)).await {
                        Ok(b)=>blocks.push(b),
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
                    Request::Submit(tx)=>{let r=seq.submit_tx(*tx).map_err(|e|e.to_string());let _=ipc::write(&mut s,&r).await;},
                    Request::Block(n)=>{let b=n.checked_sub(1).and_then(|n|usize::try_from(n).ok()).and_then(|idx|blocks.get(idx));let _=ipc::write(&mut s,&Ok::<_,String>(b)).await;},
                    Request::Tip=>{let _=ipc::write(&mut s,&Ok::<_,String>((seq.tip(),seq.state().root()))).await;}
                }
            }
        }
    }
}
