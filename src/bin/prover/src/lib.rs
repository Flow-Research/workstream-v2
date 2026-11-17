//! WorkStream prover: zkVM guest program and proof generation runtime (issue #80).
//!
//! The prover executes the deterministic state-transition guest program over
//! block transitions and asks a pluggable [`ZkvmBackend`] for the zero-knowledge
//! proof. The default backend runs the guest logic in memory (local development
//! and tests); a real RISC Zero/SP1 backend plugs in behind the same trait.

use std::sync::Arc;

use async_trait::async_trait;
use workstream_core::hash::Hash;
use workstream_core::traits::prover::{
    GuestInfo, ProofBundleResponse, ProveBlockRequest, ProveBlockTransition, ProverApi,
    ProverStatus, ZkProof, ZkvmBackend,
};
use workstream_core::{Error, Result};
use workstream_state::State;
use workstream_stf::StateTransitionFunction;

/// Guest program identifier: the deterministic STF state-transition program
/// (`stateroot_post = STF(stateroot_pre, txs)`) compiled to the zkVM guest.
pub const DEFAULT_GUEST_ID: &str = "workstream-stf-guest-v1";

/// Prover runtime that generates block-transition proofs through a backend.
pub struct Prover {
    backend: Arc<dyn ZkvmBackend>,
}

impl Prover {
    /// Create a prover backed by the in-memory guest execution backend.
    pub fn new() -> Self {
        Self {
            backend: Arc::new(InMemoryZkBackend::new()),
        }
    }

    /// Create a prover with a custom backend.
    pub fn with_backend(backend: Arc<dyn ZkvmBackend>) -> Self {
        Self { backend }
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProverApi for Prover {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn prove_block(&self, req: ProveBlockRequest) -> Result<ProofBundleResponse> {
        req.validate()?;
        let transition = ProveBlockTransition {
            version: 1,
            block_hash: req.block_hash,
            stateroot_pre: req.stateroot_pre,
            transactions: req.transactions,
        };
        let proof = self.backend.prove_block_transition(&transition).await?;
        proof.validate()?;
        Ok(ProofBundleResponse {
            version: 1,
            api_version: 1,
            proof_bytes: proof.proof_bytes,
            public_inputs: proof.public_inputs,
            guest_id: proof.guest_id,
        })
    }

    async fn get_supported_guests(&self) -> Result<Vec<GuestInfo>> {
        Ok(vec![GuestInfo {
            version: 1,
            api_version: 1,
            guest_id: DEFAULT_GUEST_ID.to_string(),
            name: "workstream-stf-guest-v1".to_string(),
        }])
    }

    async fn get_prover_status(&self) -> Result<ProverStatus> {
        Ok(ProverStatus {
            version: 1,
            api_version: 1,
            available: true,
            queue_length: 0,
        })
    }
}

/// In-memory guest-execution backend: applies block transitions locally and
/// produces the proof envelope over the resulting state commitment. This is the
/// development backend; production proves run inside the zkVM itself.
#[derive(Clone)]
pub struct InMemoryZkBackend {
    stf: StateTransitionFunction,
    state: State,
    tip: u64,
}

impl InMemoryZkBackend {
    pub fn new() -> Self {
        Self {
            stf: StateTransitionFunction::new(),
            state: State::new(),
            tip: 0,
        }
    }
}

impl Default for InMemoryZkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ZkvmBackend for InMemoryZkBackend {
    async fn prove_block_transition(&self, transition: &ProveBlockTransition) -> Result<ZkProof> {
        transition.validate()?;

        let mut draft = self.state.clone();
        let fork = self
            .stf
            .active_fork_at(self.tip + 1)
            .ok_or_else(|| Error::State(format!("no active fork at height {}", self.tip + 1)))?;
        for tx in &transition.transactions {
            // Deterministically drop transactions that fail; the proof covers
            // the transition that actually happened.
            let _ = self.stf.execute_tx_with_fork(&mut draft, tx, fork);
        }
        let post_root = draft.root().smt_root;

        let mut proof_input = Vec::with_capacity(64);
        proof_input.extend_from_slice(transition.stateroot_pre.as_bytes());
        proof_input.extend_from_slice(post_root.as_bytes());
        let proof_hash = Hash::sha256(&proof_input);

        Ok(ZkProof {
            version: 1,
            proof_bytes: proof_hash.as_bytes().to_vec(),
            public_inputs: post_root.as_bytes().to_vec(),
            guest_id: DEFAULT_GUEST_ID.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_core::hash::H256;
    use workstream_core::types::Transaction;

    fn transition(version: u32, transactions: Vec<Transaction>) -> ProveBlockTransition {
        ProveBlockTransition {
            version,
            block_hash: [7u8; 32],
            stateroot_pre: H256::ZERO,
            transactions,
        }
    }

    #[tokio::test]
    async fn in_memory_backend_proves_transition() {
        let backend = InMemoryZkBackend::new();
        let proof = backend
            .prove_block_transition(&transition(1, vec![]))
            .await
            .unwrap();
        proof.validate().unwrap();
        assert_eq!(proof.version, 1);
        assert_eq!(proof.guest_id, DEFAULT_GUEST_ID);
        assert_eq!(proof.public_inputs.len(), 32);
        assert_eq!(proof.proof_bytes.len(), 32);
    }

    #[tokio::test]
    async fn in_memory_backend_rejects_unsupported_version() {
        let backend = InMemoryZkBackend::new();
        let err = backend
            .prove_block_transition(&transition(2, vec![]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn prover_proves_block_transition() {
        let prover = Prover::new();
        let req = ProveBlockRequest {
            version: 1,
            api_version: 1,
            block_hash: [7u8; 32],
            stateroot_pre: H256::ZERO,
            transactions: vec![],
        };
        let bundle = prover.prove_block(req).await.unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.api_version, 1);
        assert_eq!(bundle.guest_id, DEFAULT_GUEST_ID);
        assert!(!bundle.proof_bytes.is_empty());
        assert_eq!(bundle.public_inputs.len(), 32);
    }

    #[tokio::test]
    async fn prover_rejects_unsupported_request_version() {
        let prover = Prover::new();
        let req = ProveBlockRequest {
            version: 2,
            api_version: 1,
            block_hash: [7u8; 32],
            stateroot_pre: H256::ZERO,
            transactions: vec![],
        };
        let err = prover.prove_block(req).await.unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn prover_supports_only_default_guest() {
        let prover = Prover::new();
        let guests = prover.get_supported_guests().await.unwrap();
        assert_eq!(guests.len(), 1);
        assert_eq!(guests[0].guest_id, DEFAULT_GUEST_ID);
    }
}
