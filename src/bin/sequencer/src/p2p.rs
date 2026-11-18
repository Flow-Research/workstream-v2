//! In-memory implementation of the P2P networking API (development).
//!
//! Keeps published blocks keyed by height so a syncing peer can retrieve them
//! from the gossip layer. A production transport (libp2p/etc.) plugs in behind
//! the same [`P2pNetwork`] trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use workstream_core::traits::p2p::{GetBlockRequest, P2pNetwork, PublishBlockRequest};
use workstream_core::Result;

/// In-memory P2P network: publishes blocks by height for peer retrieval.
#[derive(Debug, Default)]
pub struct InMemoryP2pNetwork {
    blocks: Mutex<HashMap<u64, workstream_core::types::Block>>,
}

impl InMemoryP2pNetwork {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl P2pNetwork for InMemoryP2pNetwork {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn publish_block(&self, req: PublishBlockRequest) -> Result<()> {
        req.validate()?;
        self.blocks
            .lock()
            .expect("in-memory p2p store")
            .insert(req.block.header.number, req.block);
        Ok(())
    }

    async fn get_block(
        &self,
        req: GetBlockRequest,
    ) -> Result<workstream_core::traits::p2p::BlockResponse> {
        req.validate()?;
        let block = self
            .blocks
            .lock()
            .expect("in-memory p2p store")
            .get(&req.height)
            .cloned();
        Ok(workstream_core::traits::p2p::BlockResponse {
            version: 1,
            api_version: 1,
            block,
        })
    }
}
