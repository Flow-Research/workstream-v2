//! Browser-safe API adapter for the connected node (issue #130).
//!
//! Implements [`Backend`] over the same writer/receipt/projection state the
//! JSON-RPC endpoint uses. Submission revalidates signed bytes with the shared
//! protocol validator before forwarding; reads are projections and the
//! verifier tip. No signing, DA, P2P or proving capability is reachable.
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use workstream_api::{
    ApiErrorBody, Backend, ChainData, ErrorCode, PageData, ReceiptData, SubmitData, SubmitRequest,
};
use workstream_core::{traits::sequencer::SubmitTxRequest, Error, H256};
use workstream_ops::ipc;
use workstream_sequencer::writer::{Receipt, Request};
use workstream_tx::TxValidator;

use crate::projection::Projection;

/// Read/forward capabilities exposed to the browser API. Cloned per request.
#[derive(Clone)]
pub struct NodeApiBackend {
    included: Arc<tokio::sync::RwLock<HashMap<H256, u64>>>,
    client: ipc::tls::Client,
    writer: PathBuf,
    network: String,
    tip: tokio::sync::watch::Receiver<(u64, workstream_core::StateRoot, Option<H256>)>,
    projection: Option<Arc<Projection>>,
}

impl NodeApiBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        included: Arc<tokio::sync::RwLock<HashMap<H256, u64>>>,
        client: ipc::tls::Client,
        writer: PathBuf,
        chain_id: u64,
        tip: tokio::sync::watch::Receiver<(u64, workstream_core::StateRoot, Option<H256>)>,
        projection: Option<Arc<Projection>>,
    ) -> Self {
        Self {
            included,
            client,
            writer,
            network: chain_id.to_string(),
            tip,
            projection,
        }
    }
}

fn map_submit_error(error: Error) -> ApiErrorBody {
    match error {
        Error::Validation(_) | Error::Transaction(_) | Error::InvalidSignature => {
            ApiErrorBody::new(ErrorCode::InvalidTransaction, "transaction rejected")
        }
        Error::NotFound(_) => ApiErrorBody::new(ErrorCode::NotFound, "transaction not found"),
        _ => ApiErrorBody::new(ErrorCode::Internal, "writer unavailable"),
    }
}

fn parse_hash(value: &str) -> Result<H256, ApiErrorBody> {
    let normalized = value.strip_prefix("0x").unwrap_or(value);
    H256::from_hex(normalized)
        .map_err(|_| ApiErrorBody::new(ErrorCode::InvalidRequest, "invalid transaction hash"))
}

#[async_trait]
impl Backend for NodeApiBackend {
    fn network(&self) -> String {
        self.network.clone()
    }

    async fn heights(&self) -> (u64, u64) {
        let read_height = self.tip.borrow().0;
        let indexed = match &self.projection {
            Some(projection) => projection
                .status()
                .await
                .map(|s| s.indexed_height)
                .unwrap_or(0),
            None => 0,
        };
        (read_height, indexed)
    }

    async fn submit(&self, request: SubmitRequest) -> Result<SubmitData, ApiErrorBody> {
        // Reuse the exact DTO validation and protocol validator as the RPC
        // submission path. The browser never supplies a signing key.
        let dto = SubmitTxRequest {
            version: request.version,
            api_version: request.api_version,
            tx_bytes: request.tx_bytes,
        };
        dto.validate().map_err(|e| match e {
            Error::Validation(_) => {
                ApiErrorBody::new(ErrorCode::InvalidRequest, "invalid submission")
            }
            _ => ApiErrorBody::new(ErrorCode::Internal, "validation unavailable"),
        })?;
        let tx: workstream_core::Transaction = serde_json::from_slice(&dto.tx_bytes)
            .map_err(|_| ApiErrorBody::new(ErrorCode::InvalidTransaction, "invalid transaction"))?;
        TxValidator::new().validate(&tx).map_err(map_submit_error)?;
        let receipt: Receipt =
            ipc::call(&self.client, &self.writer, &Request::Submit(Box::new(tx)))
                .await
                .map_err(map_submit_error)?;
        Ok(SubmitData {
            tx_hash: format!("0x{}", receipt.tx_hash.to_hex()),
            status: receipt.status,
            height: receipt.height,
        })
    }

    async fn receipt(&self, tx_hash: &str) -> Result<ReceiptData, ApiErrorBody> {
        let id = parse_hash(tx_hash)?;
        if let Some(height) = self.included.read().await.get(&id).copied() {
            return Ok(ReceiptData {
                tx_hash: format!("0x{}", id.to_hex()),
                status: "Verified".into(),
                height: Some(height),
            });
        }
        let receipt: Receipt = ipc::call(&self.client, &self.writer, &Request::Receipt(id))
            .await
            .map_err(|_| ApiErrorBody::new(ErrorCode::Internal, "writer unavailable"))?;
        if receipt.status == "Unknown" {
            return Err(ApiErrorBody::new(
                ErrorCode::NotFound,
                "no receipt at this height",
            ));
        }
        Ok(ReceiptData {
            tx_hash: format!("0x{}", receipt.tx_hash.to_hex()),
            status: receipt.status,
            height: receipt.height,
        })
    }

    async fn chain(&self) -> Result<ChainData, ApiErrorBody> {
        let (height, root, da_ref) = self.tip.borrow().clone();
        let status =
            match &self.projection {
                Some(projection) => Some(projection.status().await.map_err(|_| {
                    ApiErrorBody::new(ErrorCode::Internal, "projection unavailable")
                })?),
                None => None,
            };
        let (indexed_height, lag, stale) = match status {
            Some(status) => (status.indexed_height, status.lag, status.lag > 0),
            None => (height, 0, false),
        };
        Ok(ChainData {
            height,
            state_root: format!("0x{}", root.hash().to_hex()),
            da_ref: da_ref.map(|value| format!("0x{}", value.to_hex())),
            indexed_height,
            lag,
            stale,
        })
    }

    async fn page(&self, kind: &str, cursor: &str, limit: u64) -> Result<PageData, ApiErrorBody> {
        // Only projection kinds declared in the OpenAPI contract are legal.
        if !matches!(kind, "events" | "work_items" | "reviews" | "receipts") {
            return Err(ApiErrorBody::new(
                ErrorCode::InvalidRequest,
                "unknown page kind",
            ));
        }
        let projection = self.projection.as_ref().ok_or_else(|| {
            ApiErrorBody::new(ErrorCode::StaleProjection, "projection is not configured")
        })?;
        let value = projection
            .page(kind, cursor, "", limit)
            .await
            .map_err(|_| ApiErrorBody::new(ErrorCode::Internal, "projection unavailable"))?;
        let stale = {
            let (read, indexed) = self.heights().await;
            read > indexed
        };
        Ok(serde_json::from_value(serde_json::json!({
            "kind": value.get("kind").cloned().unwrap_or_else(|| serde_json::json!(kind)),
            "items": value.get("items").cloned().unwrap_or_else(|| serde_json::json!([])),
            "next_cursor": value.get("next_cursor").cloned().unwrap_or(serde_json::Value::Null),
            "stale": stale,
        }))
        .map_err(|_| ApiErrorBody::new(ErrorCode::Internal, "projection decode failed"))?)
    }
}
