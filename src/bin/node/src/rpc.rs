//! JSON-RPC 2.0 API server over the versioned component traits (issue #85).
//!
//! Exposes the versioned component interfaces ([`SequencerApi`], [`ProverApi`],
//! [`VerifierApi`], [`DaClient`], [`P2pNetwork`]) behind a JSON-RPC 2.0
//! endpoint so clients (wallets, explorers, ops tooling) can submit
//! transactions, build blocks, and verify proofs without reaching into
//! component internals. The development transport is newline-delimited JSON
//! over TCP; a production HTTP/gRPC transport can implement the same
//! [`RpcServer::handle_request`] dispatch later.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use workstream_core::traits::da::{
    DaClient, GetBlockRequest as DaGetBlockRequest, PostBlockRequest, PostTxRequest,
};
use workstream_core::traits::p2p::{
    GetBlockRequest as P2pGetBlockRequest, P2pNetwork, PublishBlockRequest,
};
use workstream_core::traits::prover::{ProveBlockRequest, ProverApi};
use workstream_core::traits::sequencer::{BuildBlockRequest, SequencerApi, SubmitTxRequest};
use workstream_core::traits::verifier::{VerifierApi, VerifyBlockRequest, VerifyProofRequest};
use workstream_core::Error;

use crate::EventIndexer;

/// JSON-RPC protocol version implemented by this server.
pub const JSON_RPC_VERSION: &str = "2.0";
const MAX_FRAME_BYTES: u64 = 256 * 1024;
const MAX_CONNECTIONS: usize = 32;
const IO_DEADLINE: Duration = Duration::from_secs(10);

/// JSON-RPC error codes used by this server.
pub const RPC_ERROR_PARSE: i64 = -32700;
pub const RPC_ERROR_INVALID_REQUEST: i64 = -32600;
pub const RPC_ERROR_METHOD_NOT_FOUND: i64 = -32601;
pub const RPC_ERROR_INVALID_PARAMS: i64 = -32602;
pub const RPC_ERROR_INTERNAL: i64 = -32603;

/// Request: events emitted by a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexGetEventsRequest {
    pub version: u32,
    pub api_version: u32,
    pub block_number: u64,
}

impl IndexGetEventsRequest {
    pub fn validate(&self) -> std::result::Result<(), RpcError> {
        if self.version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported dto version",
            ));
        }
        if self.api_version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported api version",
            ));
        }
        Ok(())
    }
}

/// Request: events of a given type across the indexed chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexGetEventsByTypeRequest {
    pub version: u32,
    pub api_version: u32,
    pub event_type: String,
}

impl IndexGetEventsByTypeRequest {
    pub fn validate(&self) -> std::result::Result<(), RpcError> {
        if self.version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported dto version",
            ));
        }
        if self.api_version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported api version",
            ));
        }
        if self.event_type.is_empty() {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "event_type cannot be empty",
            ));
        }
        Ok(())
    }
}

/// Request: state root observed after a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexGetStateRootAtRequest {
    pub version: u32,
    pub api_version: u32,
    pub block_number: u64,
}

impl IndexGetStateRootAtRequest {
    pub fn validate(&self) -> std::result::Result<(), RpcError> {
        if self.version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported dto version",
            ));
        }
        if self.api_version != 1 {
            return Err(RpcError::new(
                RPC_ERROR_INVALID_PARAMS,
                "unsupported api version",
            ));
        }
        Ok(())
    }
}

/// JSON-RPC 2.0 request envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response envelope (either `result` or `error`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Internal dispatch failure carrying a JSON-RPC error code.
#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// JSON-RPC 2.0 API server dispatching over the versioned component traits.
#[derive(Clone)]
pub struct RpcServer {
    sequencer: Arc<dyn SequencerApi>,
    prover: Arc<dyn ProverApi>,
    verifier: Arc<dyn VerifierApi>,
    da: Arc<dyn DaClient>,
    p2p: Arc<dyn P2pNetwork>,
    indexer: Arc<EventIndexer>,
}

impl RpcServer {
    /// Create a server over the given versioned component trait objects and
    /// event indexer.
    pub fn new(
        sequencer: Arc<dyn SequencerApi>,
        prover: Arc<dyn ProverApi>,
        verifier: Arc<dyn VerifierApi>,
        da: Arc<dyn DaClient>,
        p2p: Arc<dyn P2pNetwork>,
        indexer: Arc<EventIndexer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sequencer,
            prover,
            verifier,
            da,
            p2p,
            indexer,
        })
    }

    /// Handle a single JSON-RPC request and produce the response envelope.
    pub async fn handle_request(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        workstream_ops::RPC_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if request.jsonrpc != JSON_RPC_VERSION {
            return self.error_response(
                request.id,
                RPC_ERROR_INVALID_REQUEST,
                "jsonrpc version must be \"2.0\"",
            );
        }
        match self
            .dispatch(&request.method, request.params.as_ref())
            .await
        {
            Ok(result) => JsonRpcResponse {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: request.id,
                result: Some(result),
                error: None,
            },
            Err(e) => self.error_response(request.id, e.code, &e.message),
        }
    }

    /// Serve JSON-RPC requests over a TCP listener (newline-delimited JSON).
    pub async fn serve(&self, listener: TcpListener) {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let server = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
                server.handle_connection(socket).await;
            });
        }
    }

    async fn handle_connection(&self, socket: TcpStream) {
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        loop {
            line.clear();
            let mut bounded = (&mut reader).take(MAX_FRAME_BYTES + 1);
            let Ok(Ok(bytes)) =
                tokio::time::timeout(IO_DEADLINE, bounded.read_line(&mut line)).await
            else {
                break;
            };
            if bytes == 0 || bytes as u64 > MAX_FRAME_BYTES || !line.ends_with('\n') {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let response = self.handle_line(trimmed).await;
            let Ok(mut out) = serde_json::to_string(&response) else {
                break;
            };
            out.push('\n');
            if !matches!(
                tokio::time::timeout(IO_DEADLINE, reader.write_all(out.as_bytes())).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    }

    async fn handle_line(&self, line: &str) -> JsonRpcResponse {
        let parsed = serde_json::from_str::<JsonRpcRequest>(line);
        let Ok(request) = parsed else {
            workstream_ops::RPC_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return self.error_response(None, RPC_ERROR_PARSE, "parse error");
        };
        // The development socket is not a service identity. Deny new methods
        // by default rather than accidentally exporting an operator capability.
        match request.method.as_str() {
            "workstream.sequencer.submitTransaction"
            | "workstream.sequencer.getMempoolStatus"
            | "workstream.prover.getStatus"
            | "workstream.prover.getSupportedGuests"
            | "workstream.indexer.getEvents"
            | "workstream.indexer.getEventsByType"
            | "workstream.indexer.getStateRootAt" => self.handle_request(&request).await,
            _ => {
                workstream_ops::RPC_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.error_response(
                    request.id,
                    RPC_ERROR_METHOD_NOT_FOUND,
                    "method unavailable on this listener",
                )
            }
        }
    }

    async fn dispatch(
        &self,
        method: &str,
        params: Option<&Value>,
    ) -> std::result::Result<Value, RpcError> {
        match method {
            "workstream.sequencer.submitTransaction" => {
                let req = parse_params::<SubmitTxRequest>(params)?;
                let resp = self
                    .sequencer
                    .submit_tx(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.sequencer.previewBlock" => {
                let req = parse_params::<BuildBlockRequest>(params)?;
                let resp = self
                    .sequencer
                    .preview_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.sequencer.getMempoolStatus" => {
                let resp = self
                    .sequencer
                    .get_mempool_status()
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.prover.proveBlock" => {
                let req = parse_params::<ProveBlockRequest>(params)?;
                let resp = self
                    .prover
                    .prove_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.prover.getSupportedGuests" => {
                let resp = self
                    .prover
                    .get_supported_guests()
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.prover.getStatus" => {
                let resp = self
                    .prover
                    .get_prover_status()
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.verifier.verifyBlock" => {
                let req = parse_params::<VerifyBlockRequest>(params)?;
                let resp = self
                    .verifier
                    .verify_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.verifier.verifyProof" => {
                let req = parse_params::<VerifyProofRequest>(params)?;
                let resp = self
                    .verifier
                    .verify_proof(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.da.postBlock" => {
                let req = parse_params::<PostBlockRequest>(params)?;
                let resp = self
                    .da
                    .post_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.da.postTx" => {
                let req = parse_params::<PostTxRequest>(params)?;
                let resp = self.da.post_tx(req).await.map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.da.getBlock" => {
                let req = parse_params::<DaGetBlockRequest>(params)?;
                let resp = self.da.get_block(req).await.map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.da.getAvailability" => {
                let resp = self
                    .da
                    .get_availability()
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.p2p.publishBlock" => {
                let req = parse_params::<PublishBlockRequest>(params)?;
                self.p2p
                    .publish_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(json!({ "status": "ok" }))
            }
            "workstream.p2p.getBlock" => {
                let req = parse_params::<P2pGetBlockRequest>(params)?;
                let resp = self
                    .p2p
                    .get_block(req)
                    .await
                    .map_err(|e| rpc_internal(&e))?;
                Ok(serde_json::to_value(resp).map_err(rpc_encode)?)
            }
            "workstream.indexer.getEvents" => {
                let req = parse_params::<IndexGetEventsRequest>(params)?;
                req.validate()?;
                let events = self.indexer.events(req.block_number);
                Ok(serde_json::to_value(events).map_err(rpc_encode)?)
            }
            "workstream.indexer.getEventsByType" => {
                let req = parse_params::<IndexGetEventsByTypeRequest>(params)?;
                req.validate()?;
                let events = self.indexer.events_by_type(&req.event_type);
                Ok(serde_json::to_value(events).map_err(rpc_encode)?)
            }
            "workstream.indexer.getStateRootAt" => {
                let req = parse_params::<IndexGetStateRootAtRequest>(params)?;
                req.validate()?;
                let state_root = self.indexer.state_root_at(req.block_number);
                Ok(serde_json::to_value(state_root).map_err(rpc_encode)?)
            }
            _ => Err(RpcError::new(
                RPC_ERROR_METHOD_NOT_FOUND,
                format!("method not found: {method}"),
            )),
        }
    }

    fn error_response(&self, id: Option<u64>, code: i64, message: &str) -> JsonRpcResponse {
        workstream_ops::RPC_ERRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        JsonRpcResponse {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
}

fn rpc_internal(e: &Error) -> RpcError {
    let code = if matches!(e, Error::Validation(_)) {
        RPC_ERROR_INVALID_PARAMS
    } else {
        RPC_ERROR_INTERNAL
    };
    RpcError::new(code, format!("rpc handler failed: {e}"))
}

fn rpc_encode(e: serde_json::Error) -> RpcError {
    RpcError::new(
        RPC_ERROR_INTERNAL,
        format!("rpc encode response failed: {e}"),
    )
}

fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<&Value>,
) -> std::result::Result<T, RpcError> {
    let value = params.ok_or_else(|| RpcError::new(RPC_ERROR_INVALID_PARAMS, "missing params"))?;
    serde_json::from_value(value.clone())
        .map_err(|_| RpcError::new(RPC_ERROR_INVALID_PARAMS, "invalid params"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use workstream_core::hash::H256;
    use workstream_core::types::{ActionType, Event, FeePayer, FeeSpec, StateRoot};
    use workstream_prover::{Prover, ReceiptVerifier};
    use workstream_sequencer::{InMemoryDaClient, InMemoryP2pNetwork, SequencerApiImpl};
    use workstream_stf::{mvp_genesis_schedule, StateTransitionFunction};
    use workstream_tx::TxBuilder;

    fn in_memory_server() -> Arc<RpcServer> {
        in_memory_server_with_indexer(Arc::new(EventIndexer::new()))
    }

    fn in_memory_server_with_indexer(indexer: Arc<EventIndexer>) -> Arc<RpcServer> {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        let verifier = ReceiptVerifier::new(stf.fork_schedule().forks[0].guest_hash);
        let sequencer = SequencerApiImpl::new(stf);
        RpcServer::new(
            Arc::new(sequencer) as Arc<dyn SequencerApi>,
            Arc::new(Prover::new()) as Arc<dyn ProverApi>,
            Arc::new(verifier) as Arc<dyn VerifierApi>,
            Arc::new(InMemoryDaClient::new()) as Arc<dyn DaClient>,
            Arc::new(InMemoryP2pNetwork::new()) as Arc<dyn P2pNetwork>,
            indexer,
        )
    }

    fn prover_status_request(id: u64) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id: Some(id),
            method: "workstream.prover.getStatus".to_string(),
            params: None,
        }
    }

    #[tokio::test]
    async fn rpc_prover_get_status_returns_ok() {
        let server = in_memory_server();
        let response = server.handle_request(&prover_status_request(7)).await;
        assert!(response.error.is_none());
        let result = response.result.expect("result payload");
        assert_eq!(result["available"], json!(true));
        assert_eq!(result["queue_length"], json!(0));
    }

    #[tokio::test]
    async fn rpc_unknown_method_returns_method_not_found() {
        let server = in_memory_server();
        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(9),
                method: "workstream.unknown.lookup".to_string(),
                params: None,
            })
            .await;
        let error = response.error.expect("error payload");
        assert_eq!(error.code, RPC_ERROR_METHOD_NOT_FOUND);
        assert_eq!(error.message, "method not found: workstream.unknown.lookup");
    }

    #[tokio::test]
    async fn rpc_prove_block_rejects_unsupported_version() {
        let server = in_memory_server();
        let zero_hash = serde_json::to_value(H256::ZERO).unwrap();
        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(3),
                method: "workstream.prover.proveBlock".to_string(),
                params: Some(json!({
                    "version": 2,
                    "api_version": 1,
                    "block_hash": zero_hash,
                    "stateroot_pre": zero_hash,
                    "transactions": [],
                })),
            })
            .await;
        let error = response.error.expect("error payload");
        assert_eq!(error.code, RPC_ERROR_INVALID_PARAMS);
    }

    #[tokio::test]
    async fn rpc_sequencer_submit_tx_roundtrip() {
        let server = in_memory_server();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut tx = TxBuilder::new()
            .chain_id(1)
            .account(workstream_core::Hash::sha256(
                signing_key.verifying_key().as_bytes(),
            ))
            .nonce(0, 0)
            .add_action(ActionType::ActorRegister, b"x".to_vec())
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1_000,
            })
            .build()
            .unwrap();
        workstream_crypto::signature::sign_tx_ed25519(&mut tx, &signing_key).unwrap();
        let submit = SubmitTxRequest {
            version: 1,
            api_version: 1,
            tx_bytes: serde_json::to_vec(&tx).unwrap(),
        };
        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(11),
                method: "workstream.sequencer.submitTransaction".to_string(),
                params: Some(serde_json::to_value(&submit).unwrap()),
            })
            .await;
        assert!(response.error.is_none());
        let result = response.result.expect("result payload");
        assert!(result["tx_hash"].is_array());

        let status_response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(12),
                method: "workstream.sequencer.getMempoolStatus".to_string(),
                params: None,
            })
            .await;
        assert!(status_response.error.is_none());
    }

    #[tokio::test]
    async fn development_listener_denies_privileged_methods_before_dispatch() {
        let server = in_memory_server();
        for method in [
            "workstream.prover.proveBlock",
            "workstream.da.postBlock",
            "workstream.p2p.publishBlock",
            "workstream.sequencer.buildBlock",
        ] {
            let request = json!({"jsonrpc":"2.0", "id":7, "method":method});
            let response = server.handle_line(&request.to_string()).await;
            assert_eq!(response.error.unwrap().code, RPC_ERROR_METHOD_NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn rpc_server_serves_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = in_memory_server();
        let server_clone = server.clone();
        tokio::spawn(async move {
            server_clone.serve(listener).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "workstream.prover.getStatus",
            "params": {},
        });
        stream
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response: JsonRpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(response.error.is_none());
        assert_eq!(response.id, Some(1));
        assert!(response.result.is_some());
    }

    #[tokio::test]
    async fn rpc_indexer_get_events_returns_indexed_events() {
        let mut indexer = EventIndexer::new();
        indexer.record(
            1,
            StateRoot::new(H256::ZERO, H256::ZERO),
            vec![Event {
                event_type: "actor.registered".to_string(),
                data: vec![1, 2],
                block_number: 1,
                tx_index: 0,
            }],
        );
        let server = in_memory_server_with_indexer(Arc::new(indexer));

        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(31),
                method: "workstream.indexer.getEvents".to_string(),
                params: Some(json!({
                    "version": 1,
                    "api_version": 1,
                    "block_number": 1,
                })),
            })
            .await;
        assert!(response.error.is_none());
        let result = response.result.expect("result payload");
        assert_eq!(result.as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn rpc_indexer_get_events_by_type_filters_by_type() {
        let mut indexer = EventIndexer::new();
        indexer.record(
            1,
            StateRoot::new(H256::ZERO, H256::ZERO),
            vec![
                Event {
                    event_type: "actor.registered".to_string(),
                    data: vec![1],
                    block_number: 1,
                    tx_index: 0,
                },
                Event {
                    event_type: "task.created".to_string(),
                    data: vec![2],
                    block_number: 1,
                    tx_index: 1,
                },
            ],
        );
        let server = in_memory_server_with_indexer(Arc::new(indexer));

        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(32),
                method: "workstream.indexer.getEventsByType".to_string(),
                params: Some(json!({
                    "version": 1,
                    "api_version": 1,
                    "event_type": "task.created",
                })),
            })
            .await;
        assert!(response.error.is_none());
        let result = response.result.expect("result payload");
        let events = result.as_array().expect("array");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], json!("task.created"));
    }

    #[tokio::test]
    async fn rpc_indexer_get_state_root_at_returns_indexed_root() {
        let mut indexer = EventIndexer::new();
        let root = StateRoot::new(H256::from_bytes([7u8; 32]), H256::ZERO);
        indexer.record(3, root.clone(), Vec::new());
        let server = in_memory_server_with_indexer(Arc::new(indexer));

        let response = server
            .handle_request(&JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: Some(33),
                method: "workstream.indexer.getStateRootAt".to_string(),
                params: Some(json!({
                    "version": 1,
                    "api_version": 1,
                    "block_number": 3,
                })),
            })
            .await;
        assert!(response.error.is_none());
        let result = response.result.expect("result payload");
        assert_eq!(
            result["smt_root"],
            json!(serde_json::to_value(root.smt_root).unwrap())
        );
    }
}
