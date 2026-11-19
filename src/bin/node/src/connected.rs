//! Connected-mode node: admission is forwarded; the verified tip is local.
use crate::{rpc::*, MemoryBlockSource, Node};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use workstream_core::{
    traits::sequencer::SubmitTxRequest,
    types::{Block, StateRoot},
    Error, Result, H256,
};
use workstream_ops::{ipc, Monitor};
use workstream_prover::Prover;
use workstream_sequencer::writer::Request;
use workstream_stf::StateTransitionFunction;

#[derive(Clone)]
struct Gateway {
    client: ipc::tls::Client,
    writer: PathBuf,
    tip: tokio::sync::watch::Receiver<(u64, StateRoot, Option<H256>)>,
}

impl Gateway {
    async fn submit(&self, params: Option<Value>) -> Result<Value> {
        let req: SubmitTxRequest = serde_json::from_value(params.unwrap_or(Value::Null))
            .map_err(|_| Error::Validation("invalid submission".into()))?;
        req.validate()?;
        let tx = serde_json::from_slice(&req.tx_bytes)
            .map_err(|_| Error::Validation("invalid transaction".into()))?;
        let hash: H256 =
            ipc::call(&self.client, &self.writer, &Request::Submit(Box::new(tx))).await?;
        Ok(json!({"version":1,"api_version":1,"status":"Pending","tx_hash":hash.as_bytes()}))
    }
}
#[async_trait::async_trait]
impl LineEndpoint for Gateway {
    async fn line(&self, input: &str) -> JsonRpcResponse {
        let mut id = None;
        let result = match serde_json::from_str::<JsonRpcRequest>(input) {
            Err(_) => Err((RPC_ERROR_PARSE, "parse error")),
            Ok(req) => {
                id = req.id;
                match (req.jsonrpc.as_str(), req.method.as_str()) {
                    ("2.0", "workstream.sequencer.submitTransaction") => {
                        self.submit(req.params).await.map_err(|e| match e {
                            Error::Validation(_) => {
                                (RPC_ERROR_INVALID_PARAMS, "transaction rejected")
                            }
                            _ => (RPC_ERROR_INTERNAL, "writer unavailable"),
                        })
                    }
                    ("2.0", "workstream.node.verifiedTip") => {
                        let (height, root, da_ref) = self.tip.borrow().clone();
                        Ok(json!({"height":height,"state_root":root,"da_ref":da_ref}))
                    }
                    ("2.0", _) => Err((RPC_ERROR_METHOD_NOT_FOUND, "unknown method")),
                    _ => Err((RPC_ERROR_INVALID_REQUEST, "unsupported JSON-RPC version")),
                }
            }
        };
        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(value),
                error: None,
            },
            Err((code, message)) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(JsonRpcError {
                    code,
                    message: message.into(),
                    data: None,
                }),
            },
        }
    }
}
pub async fn serve(
    dir: &Path,
    port: Option<u16>,
    stf: StateTransitionFunction,
    prover: Prover,
    monitor: Arc<Monitor>,
) -> Result<()> {
    let port = port.ok_or_else(|| Error::Config("connected node requires rpc_port".into()))?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(ipc::io_err)?;
    let schedule = stf.fork_schedule().clone();
    let mut node = Node::with_backend(stf, schedule, MemoryBlockSource::new(), prover.backend())
        .require_proof();
    let (tx, tip) = tokio::sync::watch::channel((0, node.state_root(), None));
    let writer = dir.join("writer.sock");
    let client = ipc::tls::Client::load("sequencer.workstream.internal")?;
    let rpc = serve_endpoint(
        listener,
        Gateway {
            client: client.clone(),
            writer: writer.clone(),
            tip,
        },
    );
    let sync = async {
        loop {
            let height = node
                .tip()
                .checked_add(1)
                .ok_or_else(|| Error::Consensus("height exhausted".into()))?;
            match ipc::call::<_, Option<Block>>(&client, &writer, &Request::Block(height)).await {
                Ok(Some(block)) => {
                    let da_ref = block.header.da_ref;
                    node.apply_block(block)?;
                    tx.send_replace((node.tip(), node.state_root(), Some(da_ref)));
                    monitor.heartbeat(true);
                    continue;
                }
                Ok(None) => monitor.heartbeat(true),
                Err(_) => monitor.heartbeat(false),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::select! {result=sync=>result,_=rpc=>Err(Error::Io("connected node listener stopped".into()))}
}
