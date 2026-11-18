//! RPC-facing adapter that exposes the sequencer's deterministic operations
//! through the versioned [`SequencerApi`] trait object (issue #85).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use workstream_core::traits::sequencer::{
    BlockHeaderDraft, BuildBlockRequest, MempoolStatus, SequencerApi, SubmitTxRequest,
    SubmitTxResponse, TxStatus,
};
use workstream_core::types::Transaction;
use workstream_core::{Error, Result};
use workstream_stf::StateTransitionFunction;

use crate::Sequencer;

/// Adapter that exposes the sequencer's deterministic operations through the
/// versioned [`SequencerApi`] trait object, so RPC handlers and other
/// consumers can submit transactions and build blocks without reaching into
/// the sequencer's concrete internals.
pub struct SequencerApiImpl {
    inner: Arc<Mutex<Sequencer>>,
}

impl SequencerApiImpl {
    /// Create a new sequencer-backed API adapter from a genesis STF.
    pub fn new(stf: StateTransitionFunction) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Sequencer::new(stf))),
        }
    }

    /// Wrap an existing sequencer instance.
    pub fn from_sequencer(sequencer: Sequencer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(sequencer)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Sequencer> {
        self.inner.lock().expect("sequencer api mutex poisoned")
    }
}

#[async_trait]
impl SequencerApi for SequencerApiImpl {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn submit_tx(&self, req: SubmitTxRequest) -> Result<SubmitTxResponse> {
        req.validate()?;
        let tx: Transaction = serde_json::from_slice(&req.tx_bytes)
            .map_err(|e| Error::Validation(format!("transaction decode: {e}")))?;
        let mut sequencer = self.lock();
        let tx_hash = sequencer.submit_tx(tx)?;
        Ok(SubmitTxResponse {
            version: 1,
            api_version: 1,
            tx_hash: *tx_hash.as_bytes(),
            status: TxStatus::Pending,
        })
    }

    async fn get_mempool_status(&self) -> Result<MempoolStatus> {
        let sequencer = self.lock();
        Ok(MempoolStatus {
            version: 1,
            api_version: 1,
            pending_count: sequencer.pending() as u64,
            size_bytes: 0,
        })
    }

    async fn build_block(&self, req: BuildBlockRequest) -> Result<BlockHeaderDraft> {
        req.validate()?;
        let mut sequencer = self.lock();
        let block = sequencer.build_block(req.max_txs)?;
        let block_hash = crate::header_hash(&block.header)?;
        Ok(BlockHeaderDraft {
            version: 1,
            api_version: 1,
            block_hash: *block_hash.as_bytes(),
            tx_count: block.transactions.len() as u32,
            state_root: *block.header.state_root.smt_root.as_bytes(),
        })
    }
}
