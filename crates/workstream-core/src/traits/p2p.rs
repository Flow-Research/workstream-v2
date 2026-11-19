//! P2P networking API trait

use crate::{Error, Result};
use async_trait::async_trait;

#[async_trait]
pub trait P2pNetwork: Send + Sync {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    /// Publish a block to the peer network (gossip fan-out destination).
    async fn publish_block(&self, req: PublishBlockRequest) -> Result<()>;

    /// Fetch a block by height from the peer network.
    async fn get_block(&self, req: GetBlockRequest) -> Result<BlockResponse>;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublishBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub block: crate::types::Block,
}

impl PublishBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported dto version: {}",
                self.version
            )));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!(
                "unsupported api version: {}",
                self.api_version
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GetBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub height: crate::types::BlockNumber,
}

impl GetBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported dto version: {}",
                self.version
            )));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!(
                "unsupported api version: {}",
                self.api_version
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockResponse {
    pub version: u32,
    pub api_version: u32,
    pub block: Option<crate::types::Block>,
}
