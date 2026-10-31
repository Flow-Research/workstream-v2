//! Sequencer API trait

use crate::{Error, Result};
use async_trait::async_trait;

#[async_trait]
pub trait SequencerApi: Send + Sync {
    /// Get the API version
    fn api_version(&self) -> u32 {
        1
    }

    /// Get minimum supported API version
    fn min_api_version(&self) -> u32 {
        1
    }

    /// Submit a transaction to the mempool
    async fn submit_tx(&self, req: SubmitTxRequest) -> Result<SubmitTxResponse>;

    /// Get mempool status
    async fn get_mempool_status(&self) -> Result<MempoolStatus>;

    /// Build a block from mempool transactions
    async fn build_block(&self, req: BuildBlockRequest) -> Result<BlockHeaderDraft>;
}

#[derive(Clone, Debug)]
pub struct SubmitTxRequest {
    pub version: u32,
    pub api_version: u32,
    pub tx_bytes: Vec<u8>,
}

impl SubmitTxRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        if self.tx_bytes.is_empty() {
            return Err(Error::Validation("tx_bytes cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SubmitTxResponse {
    pub version: u32,
    pub tx_hash: [u8; 32],
    pub status: TxStatus,
}

#[derive(Clone, Debug)]
pub enum TxStatus {
    Pending,
    Rejected(String),
}

#[derive(Clone, Debug)]
pub struct MempoolStatus {
    pub version: u32,
    pub pending_count: u64,
    pub size_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct BuildBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub max_txs: Option<u32>,
}

impl BuildBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BlockHeaderDraft {
    pub version: u32,
    pub block_hash: [u8; 32],
    pub tx_count: u32,
    pub state_root: [u8; 32],
}
