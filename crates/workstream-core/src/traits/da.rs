//! Data Availability Client API trait

use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait DaClient: Send + Sync {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn post_block(&self, req: PostBlockRequest) -> Result<PostBlockResponse>;
    async fn get_block(&self, req: GetBlockRequest) -> Result<GetBlockResponse>;
    async fn get_availability(&self) -> Result<AvailabilityInfo>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub block_bytes: Vec<u8>,
}

impl PostBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        if self.block_bytes.is_empty() {
            return Err(Error::Validation("block_bytes cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostBlockResponse {
    pub version: u32,
    pub api_version: u32,
    pub da_id: String,
    pub available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub da_id: String,
}

impl GetBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        if self.da_id.is_empty() {
            return Err(Error::Validation("da_id cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlockResponse {
    pub version: u32,
    pub api_version: u32,
    pub block_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityInfo {
    pub version: u32,
    pub api_version: u32,
    pub available: bool,
    pub latency_ms: u64,
}
