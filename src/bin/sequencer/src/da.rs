//! In-memory implementation of the Data Availability client (development).
//!
//! Stores published blocks and directly-submitted transactions in memory so
//! the sequencer/node pipelines can be exercised end to end without a real
//! Celestia/EigenDA deployment. A production DA client plugs in behind the
//! same [`DaClient`] trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use workstream_core::hash::Hash;
use workstream_core::traits::da::{
    AvailabilityInfo, DaClient, GetBlockRequest, GetBlockResponse, PostBlockRequest,
    PostBlockResponse, PostTxRequest, PostTxResponse,
};
use workstream_core::{Error, Result};

/// `da_id` assigned to a published payload: domain-tagged SHA-256 of its bytes.
fn da_id_for(bytes: &[u8]) -> String {
    format!("da:{}", Hash::sha256(bytes).to_hex())
}

/// Published payloads kept by the in-memory DA client.
#[derive(Debug, Clone, Default)]
struct Store {
    blocks: HashMap<String, Vec<u8>>,
    txs: HashMap<String, Vec<u8>>,
}

/// Development DA client: keeps published blocks and direct transaction
/// submissions in an in-memory store.
#[derive(Debug, Default)]
pub struct InMemoryDaClient {
    store: Mutex<Store>,
}

impl Clone for InMemoryDaClient {
    fn clone(&self) -> Self {
        let guard = self.store.lock().expect("in-memory da store");
        let store = Store::clone(&*guard);
        Self {
            store: Mutex::new(store),
        }
    }
}

impl InMemoryDaClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a published block by its DA reference.
    pub async fn get_block_bytes(&self, da_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .lock()
            .expect("in-memory da store")
            .blocks
            .get(da_id)
            .cloned())
    }

    /// Look up a directly-submitted transaction by its DA reference.
    pub async fn get_tx_bytes(&self, da_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .lock()
            .expect("in-memory da store")
            .txs
            .get(da_id)
            .cloned())
    }
}

#[async_trait]
impl DaClient for InMemoryDaClient {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn post_block(&self, req: PostBlockRequest) -> Result<PostBlockResponse> {
        req.validate()?;
        let da_id = da_id_for(&req.block_bytes);
        self.store
            .lock()
            .expect("in-memory da store")
            .blocks
            .insert(da_id.clone(), req.block_bytes.clone());
        Ok(PostBlockResponse {
            version: 1,
            api_version: 1,
            da_id: da_id.clone(),
            available: true,
        })
    }

    async fn get_block(&self, req: GetBlockRequest) -> Result<GetBlockResponse> {
        req.validate()?;
        let block_bytes = self
            .store
            .lock()
            .expect("in-memory da store")
            .blocks
            .get(&req.da_id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("block {} not found", req.da_id)))?;
        Ok(GetBlockResponse {
            version: 1,
            api_version: 1,
            block_bytes: Some(block_bytes),
        })
    }

    async fn get_availability(&self) -> Result<AvailabilityInfo> {
        Ok(AvailabilityInfo {
            version: 1,
            api_version: 1,
            available: true,
            latency_ms: 0,
        })
    }

    async fn post_tx(&self, req: PostTxRequest) -> Result<PostTxResponse> {
        req.validate()?;
        let da_id = da_id_for(&req.tx_bytes);
        self.store
            .lock()
            .expect("in-memory da store")
            .txs
            .insert(da_id.clone(), req.tx_bytes);
        Ok(PostTxResponse {
            version: 1,
            api_version: 1,
            da_id: da_id.clone(),
            available: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn da_client_posts_and_gets_block() {
        let client = InMemoryDaClient::new();
        let resp = client
            .post_block(PostBlockRequest {
                version: 1,
                api_version: 1,
                block_bytes: vec![1, 2, 3, 4],
            })
            .await
            .unwrap();
        assert!(resp.available);
        assert!(!resp.da_id.is_empty());

        let got = client
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: resp.da_id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(got.block_bytes.as_deref(), Some(&[1u8, 2, 3, 4][..]));
    }

    #[tokio::test]
    async fn da_client_rejects_empty_block_bytes() {
        let client = InMemoryDaClient::new();
        let err = client
            .post_block(PostBlockRequest {
                version: 1,
                api_version: 1,
                block_bytes: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn da_client_rejects_unknown_block() {
        let client = InMemoryDaClient::new();
        let err = client
            .get_block(GetBlockRequest {
                version: 1,
                api_version: 1,
                da_id: "da:missing".to_string(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn da_client_reports_available() {
        let client = InMemoryDaClient::new();
        let info = client.get_availability().await.unwrap();
        assert!(info.available);
    }

    #[tokio::test]
    async fn da_client_posts_and_gets_tx() {
        let client = InMemoryDaClient::new();
        let resp = client
            .post_tx(PostTxRequest {
                version: 1,
                api_version: 1,
                tx_bytes: vec![9, 8, 7],
            })
            .await
            .unwrap();
        assert!(resp.available);
        assert!(!resp.da_id.is_empty());

        let got = client.get_tx_bytes(&resp.da_id).await.unwrap();
        assert_eq!(got.as_deref(), Some(&[9u8, 8, 7][..]));
    }

    #[tokio::test]
    async fn da_client_rejects_empty_tx_bytes() {
        let client = InMemoryDaClient::new();
        let err = client
            .post_tx(PostTxRequest {
                version: 1,
                api_version: 1,
                tx_bytes: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }
}
