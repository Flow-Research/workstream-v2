//! WorkStream prover: zkVM guest program and proof generation runtime (issue #80).
//!
//! The prover executes the deterministic state-transition guest program over
//! block transitions and asks a pluggable [`ZkvmBackend`] for the zero-knowledge
//! proof. Local proving requires a configured RISC Zero guest image.

use std::sync::Arc;

pub mod fold;
pub mod risc0;
mod verifier;
pub use verifier::ReceiptVerifier;

use async_trait::async_trait;
use workstream_core::hash::H256;
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
            backend: Arc::new(RiscZeroBackend::default()),
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
            guest_hash: proof.guest_hash,
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

/// A prover for a particular canonical pre-state, supplied by the block producer.
#[derive(Clone)]
pub struct RiscZeroBackend {
    state: State,
    height: u64,
}

impl RiscZeroBackend {
    pub fn at(state: State, height: u64) -> Self {
        Self { state, height }
    }
}

impl Default for RiscZeroBackend {
    fn default() -> Self {
        Self::at(State::new(), 1)
    }
}

#[async_trait]
impl ZkvmBackend for RiscZeroBackend {
    async fn prove_block_transition(&self, transition: &ProveBlockTransition) -> Result<ZkProof> {
        transition.validate()?;

        let pre = self.state.root().hash();
        if transition.stateroot_pre != pre {
            return Err(Error::InvalidProof("witness pre-state mismatch".into()));
        }
        let (image, approved) = risc0::configured_image()?;
        let mut draft = self.state.clone();
        let stf = StateTransitionFunction::with_schedule(workstream_stf::mvp_genesis_schedule()?)?;
        workstream_stf::governance::check_activation(&draft, stf.fork_schedule(), self.height)?;
        for tx in &transition.transactions {
            stf.execute_tx_at_height(&mut draft, tx, self.height)?;
        }
        let post_root = draft.root().hash();
        let witness = workstream_stf::receipt::Witness {
            before: self.state.snapshot(),
            height: self.height,
            block_hash: H256::from_bytes(transition.block_hash),
            pre,
            post: post_root,
            transactions: transition.transactions.clone(),
        };
        let proof_bytes =
            tokio::task::spawn_blocking(move || risc0::prove(&image, approved, &witness))
                .await
                .map_err(|e| Error::Other(e.to_string()))??;

        Ok(ZkProof {
            version: 1,
            proof_bytes,
            public_inputs: post_root.as_bytes().to_vec(),
            guest_id: approved.to_hex(),
            guest_hash: approved,
            stateroot_pre: pre,
        })
    }

    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool> {
        transition.validate()?;
        proof.validate()?;
        let approved = risc0::configured_id()?;
        let Ok(post) = proof.public_inputs.as_slice().try_into() else {
            return Ok(false);
        };
        let claim = workstream_stf::receipt::Claim::new(
            self.height,
            H256::from_bytes(transition.block_hash),
            transition.stateroot_pre,
            H256::from_bytes(post),
            &transition.transactions,
        )?;
        Ok(proof.stateroot_pre == transition.stateroot_pre
            && proof.guest_id == approved.to_hex()
            && risc0::verify(&proof.proof_bytes, approved, &claim).is_ok())
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
    async fn rejects_transition_without_matching_prestate() {
        let backend = RiscZeroBackend::default();
        let err = backend
            .prove_block_transition(&transition(1, vec![]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidProof(_)));
    }

    #[tokio::test]
    async fn in_memory_backend_rejects_unsupported_version() {
        let backend = RiscZeroBackend::default();
        let err = backend
            .prove_block_transition(&transition(2, vec![]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn prover_propagates_prestate_failure() {
        let prover = Prover::new();
        let req = ProveBlockRequest {
            version: 1,
            api_version: 1,
            block_hash: [7u8; 32],
            stateroot_pre: H256::ZERO,
            transactions: vec![],
        };
        assert!(matches!(
            prover.prove_block(req).await,
            Err(Error::InvalidProof(_))
        ));
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
