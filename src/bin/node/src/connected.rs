//! Connected-mode node: admission is forwarded; the verified tip is local.
use crate::{
    projection::{Projection, ProjectionInput},
    rpc::*,
    MemoryBlockSource, Node,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use workstream_core::{
    traits::{
        da::{DaClient, GetBlockRequest},
        sequencer::SubmitTxRequest,
    },
    types::{Block, StateRoot},
    Error, Result, H256,
};
use workstream_ops::{ipc, Monitor};
use workstream_prover::Prover;
use workstream_sequencer::{
    writer::{Receipt, Request},
    ObjectDaClient,
};
use workstream_stf::StateTransitionFunction;

#[derive(Clone)]
struct Gateway {
    included: Arc<tokio::sync::RwLock<std::collections::HashMap<H256, u64>>>,
    client: ipc::tls::Client,
    writer: PathBuf,
    tip: tokio::sync::watch::Receiver<(u64, StateRoot, Option<H256>)>,
    projection: Option<Arc<Projection>>,
}

fn default_page_limit() -> u64 {
    50
}

#[derive(Debug, Deserialize)]
struct ProjectionPageParams {
    kind: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    event_type: String,
    #[serde(default = "default_page_limit")]
    limit: u64,
}

impl Gateway {
    async fn submit(&self, params: Option<Value>) -> Result<Value> {
        let req: SubmitTxRequest = serde_json::from_value(params.unwrap_or(Value::Null))
            .map_err(|_| Error::Validation("invalid submission".into()))?;
        req.validate()?;
        let tx = serde_json::from_slice(&req.tx_bytes)
            .map_err(|_| Error::Validation("invalid transaction".into()))?;
        let receipt: Receipt =
            ipc::call(&self.client, &self.writer, &Request::Submit(Box::new(tx))).await?;
        Ok(
            json!({"version":1,"api_version":1,"status":receipt.status,"height":receipt.height,"tx_hash":receipt.tx_hash}),
        )
    }

    async fn projection_status(&self) -> Result<Value> {
        let projection = self
            .projection
            .as_ref()
            .ok_or_else(|| Error::NotFound("projection is not configured".into()))?;
        Ok(serde_json::to_value(projection.status().await?)?)
    }

    async fn projection_page(&self, params: Option<Value>) -> Result<Value> {
        let projection = self
            .projection
            .as_ref()
            .ok_or_else(|| Error::NotFound("projection is not configured".into()))?;
        let params: ProjectionPageParams = serde_json::from_value(params.unwrap_or(Value::Null))
            .map_err(|_| Error::Validation("invalid projection page request".into()))?;
        projection
            .page(
                &params.kind,
                &params.cursor,
                &params.event_type,
                params.limit,
            )
            .await
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
                    ("2.0","workstream.sequencer.getMempoolStatus")=>ipc::call::<_,(u64,u64)>(&self.client,&self.writer,&Request::Queue).await.map(|(pending_count,size_bytes)|json!({"pending_count":pending_count,"size_bytes":size_bytes})).map_err(|_|(RPC_ERROR_INTERNAL,"writer unavailable")),
                    ("2.0","workstream.indexer.getStatus")=>self.projection_status().await.map_err(|e|match e {Error::NotFound(_)=>(RPC_ERROR_METHOD_NOT_FOUND,"projection unavailable"),Error::Validation(_)=>(RPC_ERROR_INVALID_PARAMS,"invalid projection request"),_=>(RPC_ERROR_INTERNAL,"projection unavailable")}),
                    ("2.0","workstream.indexer.getPage")=>self.projection_page(req.params).await.map_err(|e|match e {Error::NotFound(_)=>(RPC_ERROR_METHOD_NOT_FOUND,"projection unavailable"),Error::Validation(_)=>(RPC_ERROR_INVALID_PARAMS,"invalid projection request"),_=>(RPC_ERROR_INTERNAL,"projection unavailable")}),
                    ("2.0","workstream.node.getReceipt")=>match req.params.and_then(|p|p.get("tx_hash").cloned()).and_then(|v|serde_json::from_value::<H256>(v).ok()) {
                        None=>Err((RPC_ERROR_INVALID_PARAMS,"expected tx_hash")),
                        Some(id)=>{let height=self.included.read().await.get(&id).copied();if let Some(height)=height {Ok(json!({"tx_hash":id,"status":"Verified","height":height}))} else {ipc::call::<_,Receipt>(&self.client,&self.writer,&Request::Receipt(id)).await.map(|r|json!(r)).map_err(|_|(RPC_ERROR_INTERNAL,"writer unavailable"))}}
                    },
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
    let chain_id = schedule.chain_id;
    let projection = Projection::open(chain_id).await?.map(Arc::new);
    let notifications_db_path: PathBuf = std::env::var_os("WORKSTREAM_NOTIFICATIONS_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("notifications.sqlite"));
    let notifications_outbox = workstream_ops::notifications::Outbox::open(&notifications_db_path)?;
    let mut node = Node::with_backend(stf, schedule, MemoryBlockSource::new(), prover.backend())
        .require_proof()
        .with_notifications(notifications_outbox);
    let (tx, tip) = tokio::sync::watch::channel((0, node.state_root(), None));
    let writer = dir.join("writer.sock");
    let included = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let client = ipc::tls::Client::load("sequencer.workstream.internal")?;
    // In object-DA mode the writer publishes only a reference. The node is
    // then independent of producer-local block storage: it fetches the exact
    // bytes from the configured provider and verifies the header binding.
    let object_da = if std::env::var_os("WORKSTREAM_DA_ENDPOINT").is_some() {
        Some(ObjectDaClient::from_env()?)
    } else {
        None
    };
    let rpc = serve_endpoint(
        listener,
        Gateway {
            included: included.clone(),
            client: client.clone(),
            writer: writer.clone(),
            tip: tip.clone(),
            projection: projection.clone(),
        },
    );
    // Browser-safe HTTPS API (issue #130). Optional; when enabled it reuses
    // the node identity's server certificate and the verifier's read state.
    // No signing, DA, P2P or proving capability crosses this boundary.
    let api = async {
        let Some(port) = std::env::var("WORKSTREAM_API_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
        else {
            // No browser API configured: this task never completes so the
            // node's main select loop keeps running on sync + RPC only.
            return std::future::pending::<Result<()>>().await;
        };
        let identity_dir =
            PathBuf::from(std::env::var("WORKSTREAM_IDENTITY_DIR").map_err(|_| {
                Error::Config("browser API requires WORKSTREAM_IDENTITY_DIR".into())
            })?);
        let tls = workstream_api::load_tls_config(&identity_dir).map_err(Error::Config)?;
        // Loopback by default. An operator may opt into a wider bind (e.g. a
        // container bridge) with WORKSTREAM_API_BIND; CORS still fails closed.
        let bind: std::net::Ipv4Addr = std::env::var("WORKSTREAM_API_BIND")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
        let listener = tokio::net::TcpListener::bind((bind, port))
            .await
            .map_err(ipc::io_err)?;
        let allowed_origins = std::env::var("WORKSTREAM_API_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        let config = workstream_api::ApiConfig {
            evidence: std::env::var_os("WORKSTREAM_EVIDENCE_DIR")
                .map(|path| {
                    workstream_api::server::EvidenceStore::open(Path::new(&path))
                        .map(Arc::new)
                        .map_err(|e| Error::Config(e.into()))
                })
                .transpose()?,
            explorer: std::env::var("WORKSTREAM_EXPLORER").as_deref() == Ok("1"),
            workspace_login: std::env::var_os("WORKSTREAM_WORKSPACE_OIDC_CONFIG")
                .map(|path| {
                    let bytes = std::fs::read(path)
                        .map_err(|_| Error::Config("workspace configuration unavailable".into()))?;
                    workstream_api::workspace::WorkspaceLogin::from_config(&bytes)
                        .map_err(|e| Error::Config(e.into()))
                })
                .transpose()?,
            allowed_origins,
            ..workstream_api::ApiConfig::default()
        };
        let backend = crate::browser_api::NodeApiBackend::new(
            included.clone(),
            client.clone(),
            writer.clone(),
            chain_id,
            tip,
            projection.clone(),
        );
        let state = workstream_api::ApiState::new(backend, config);
        workstream_api::serve_tls(listener, tls, state)
            .await
            .map_err(|error| Error::Io(format!("browser API: {error}")))
    };
    let sync = async {
        loop {
            let height = node
                .tip()
                .checked_add(1)
                .ok_or_else(|| Error::Consensus("height exhausted".into()))?;
            let fetched = match &object_da {
                Some(da) => {
                    // The writer may be restarting after a crash. A transport
                    // error is a retryable miss, never a reason to stop the
                    // verifier or roll back its locally verified tip.
                    let published = match ipc::call::<_, Option<(u64, H256)>>(
                        &client,
                        &writer,
                        &Request::DaRef(height),
                    )
                    .await
                    {
                        Ok(value) => value,
                        Err(_) => {
                            monitor.inc_da_failure();
                            monitor.heartbeat(false);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                    };
                    let Some((published_height, da_ref)) = published else {
                        monitor.heartbeat(true);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        continue;
                    };
                    if published_height != height {
                        return Err(Error::State(
                            "writer returned a reference for another height".into(),
                        ));
                    }
                    let response = match da
                        .get_block(GetBlockRequest {
                            version: 1,
                            api_version: 1,
                            da_id: format!("da:{}", da_ref.to_hex()),
                        })
                        .await
                    {
                        Ok(response) => response,
                        Err(e) => {
                            monitor.inc_da_failure();
                            monitor.heartbeat(false);
                            tracing::warn!(error = %e, height, "DA fetch failed");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                    };
                    let bytes = response
                        .block_bytes
                        .ok_or_else(|| Error::NotFound("DA response had no block bytes".into()))?;
                    let block: Block = serde_json::from_slice(&bytes)
                        .map_err(|e| Error::Serialization(format!("DA block decode: {e}")))?;
                    if da_ref == H256::ZERO
                        || block.header.number != height
                        || block.header.da_ref != da_ref
                    {
                        return Err(Error::Validation(
                            "DA block does not match its committed reference".into(),
                        ));
                    }
                    Some((block, da_ref))
                }
                None => {
                    match ipc::call::<_, Option<Block>>(&client, &writer, &Request::Block(height))
                        .await
                    {
                        Ok(block) => block.map(|block| {
                            let da_ref = block.header.da_ref;
                            (block, da_ref)
                        }),
                        Err(_) => {
                            monitor.heartbeat(false);
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            continue;
                        }
                    }
                }
            };
            match fetched {
                Some((block, da_ref)) => {
                    let verified_block = block.clone();
                    let ids = verified_block
                        .transactions
                        .iter()
                        .map(workstream_sequencer::tx_hash)
                        .collect::<Result<Vec<_>>>()?;
                    // Correlate verification by the DA reference: a public
                    // hash committed by the writer and shared by every node.
                    // Block bodies (and their witnesses) are never fields.
                    let context =
                        workstream_ops::trace::Correlation::new(da_ref.as_bytes(), "verify");
                    let span = context.span();
                    let _entered = span.enter();
                    let applied = match node.apply_block(block) {
                        Ok(applied) => applied,
                        Err(e) => {
                            monitor.inc_verification_rejection();
                            tracing::warn!(height, da_ref = %da_ref, "block rejected by verification");
                            return Err(e);
                        }
                    };
                    // Emit the safe identifiers a block joins on. `da_ref`
                    // equals the proof commitment, so the prover's job key and
                    // this verification share one trace id; each transaction
                    // hash links back to its admission and receipt trace.
                    tracing::info!(height, da_ref = %da_ref, txs = ids.len(), "block verified");
                    for id in &ids {
                        tracing::info!(tx_hash = %id, height, "transaction verified");
                    }
                    if let Some(projection) = projection.as_ref() {
                        projection
                            .apply(ProjectionInput {
                                height: applied.height,
                                state_root: &applied.state_root,
                                da_ref,
                                block: &verified_block,
                                events: &applied.events,
                                tx_hashes: &ids,
                            })
                            .await?;
                        // Index lag is a safe derived count used by the stall
                        // alert and the read-only status endpoint.
                        monitor.set_index_lag(projection.status().await?.lag);
                    }
                    included
                        .write()
                        .await
                        .extend(ids.into_iter().map(|id| (id, height)));
                    tx.send_replace((node.tip(), node.state_root(), Some(da_ref)));
                    monitor.heartbeat(true);
                }
                None => monitor.heartbeat(true),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let webhook_url = std::env::var("WORKSTREAM_NOTIFICATION_WEBHOOK_URL").ok();
    let webhook_secret = std::env::var("WORKSTREAM_NOTIFICATION_WEBHOOK_SECRET").ok();
    let notifications_task = async move {
        let (url, secret) = match (webhook_url, webhook_secret) {
            (None, None) => return std::future::pending().await,
            (Some(url), Some(secret)) if !secret.is_empty() => (url, secret),
            _ => {
                return Err(Error::Config(
                    "notification webhook requires URL and secret".into(),
                ))
            }
        };
        workstream_ops::notifications::run(
            &notifications_db_path,
            Arc::new(workstream_ops::notifications::WebhookSink::new(
                url, secret,
            )?) as Arc<dyn workstream_ops::notifications::DeliverySink>,
        )
        .await
    };
    tokio::select! {
        result = sync => result,
        result = api => result,
        result = notifications_task => result,
        _ = rpc => Err(Error::Io("connected node listener stopped".into())),
    }
}
