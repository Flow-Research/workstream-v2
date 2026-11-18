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

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

/// JSON-RPC protocol version implemented by this server.
pub const JSON_RPC_VERSION: &str = "2.0";

/// JSON-RPC error codes used by this server.
pub const RPC_ERROR_PARSE: i64 = -32700;
pub const RPC_ERROR_INVALID_REQUEST: i64 = -32600;
pub const RPC_ERROR_METHOD_NOT_FOUND: i64 = -32601;
pub const RPC_ERROR_INVALID_PARAMS: i64 = -32602;
pub const RPC_ERROR_INTERNAL: i64 = -32603;

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
struct RpcError {
    code: i64,
    message: String,
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
}

impl RpcServer {
    /// Create a server over the given versioned component trait objects.
    pub fn new(
        sequencer: Arc<dyn SequencerApi>,
        prover: Arc<dyn ProverApi>,
        verifier: Arc<dyn VerifierApi>,
        da: Arc<dyn DaClient>,
        p2p: Arc<dyn P2pNetwork>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sequencer,
            prover,
            verifier,
            da,
            p2p,
        })
    }

    /// Handle a single JSON-RPC request and produce the response envelope.
    pub async fn handle_request(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
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
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let server = self.clone();
            tokio::spawn(async move {
                server.handle_connection(socket).await;
            });
        }
    }

    async fn handle_connection(&self, socket: TcpStream) {
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).await.expect("rpc read");
            if bytes == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let response = self.handle_line(trimmed).await;
            let mut out = serde_json::to_string(&response).expect("rpc encode");
            out.push('\n');
            if reader.write_all(out.as_bytes()).await.is_err() {
                break;
            }
            if reader.flush().await.is_err() {
                break;
            }
        }
    }

    async fn handle_line(&self, line: &str) -> JsonRpcResponse {
        let parsed = serde_json::from_str::<JsonRpcRequest>(line);
        let Ok(request) = parsed else {
            return JsonRpcResponse {
                jsonrpc: JSON_RPC_VERSION.to_string(),
                id: None,
                result: None,
                error: Some(JsonRpcError {
                    code: RPC_ERROR_PARSE,
                    message: "parse error".to_string(),
                    data: None,
                }),
            };
        };
        self.handle_request(&request).await
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
            "workstream.sequencer.buildBlock" => {
                let req = parse_params::<BuildBlockRequest>(params)?;
                let resp = self
                    .sequencer
                    .build_block(req)
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
            _ => Err(RpcError::new(
                RPC_ERROR_METHOD_NOT_FOUND,
                format!("method not found: {method}"),
            )),
        }
    }

    fn error_response(&self, id: Option<u64>, code: i64, message: &str) -> JsonRpcResponse {
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
    use workstream_core::types::{ActionType, FeePayer, FeeSpec};
    use workstream_prover::{InMemoryVerifier, Prover};
    use workstream_sequencer::{InMemoryDaClient, InMemoryP2pNetwork, SequencerApiImpl};
    use workstream_stf::{mvp_genesis_schedule, StateTransitionFunction};
    use workstream_tx::TxBuilder;

    fn in_memory_server() -> Arc<RpcServer> {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        let sequencer = SequencerApiImpl::new(stf);
        RpcServer::new(
            Arc::new(sequencer) as Arc<dyn SequencerApi>,
            Arc::new(Prover::new()) as Arc<dyn ProverApi>,
            Arc::new(InMemoryVerifier::new()) as Arc<dyn VerifierApi>,
            Arc::new(InMemoryDaClient::new()) as Arc<dyn DaClient>,
            Arc::new(InMemoryP2pNetwork::new()) as Arc<dyn P2pNetwork>,
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
        let mut tx = TxBuilder::new()
            .chain_id(1)
            .account(crate::accounts::account(7))
            .nonce(0, 0)
            .add_action(ActionType::ActorRegister, b"x".to_vec())
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1_000,
            })
            .build()
            .unwrap();
        workstream_crypto::signature::sign_tx_ed25519(
            &mut tx,
            &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        )
        .unwrap();
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
}
