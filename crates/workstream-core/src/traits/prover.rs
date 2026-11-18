//! Prover API trait

use crate::hash::H256;
use crate::types::Transaction;
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait ProverApi: Send + Sync {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn prove_block(&self, req: ProveBlockRequest) -> Result<ProofBundleResponse>;
    async fn get_supported_guests(&self) -> Result<Vec<GuestInfo>>;
    async fn get_prover_status(&self) -> Result<ProverStatus>;
}

/// A guest-program transition to prove: given the pre-state root and the
/// block's transactions, the guest computes the post-state root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveBlockTransition {
    pub version: u32,
    pub block_hash: [u8; 32],
    pub stateroot_pre: H256,
    pub transactions: Vec<Transaction>,
}

impl ProveBlockTransition {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported dto version: {}",
                self.version
            )));
        }
        Ok(())
    }
}

/// A zero-knowledge proof over a guest program execution, together with the
/// public inputs the proof attests (here: the post-state root the guest
/// computed from the pre-state root and the block transactions).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    pub version: u32,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub guest_id: String,
    /// Hash of the guest program that produced the proof.
    pub guest_hash: H256,
    /// Pre-state root the guest proved from (the post-state root is the
    /// public input).
    pub stateroot_pre: H256,
}

impl ZkProof {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported proof version: {}",
                self.version
            )));
        }
        Ok(())
    }
}

/// Backend that turns a guest-program transition into a zero-knowledge proof
/// and decides whether a proof is valid for a transition.
#[async_trait]
pub trait ZkvmBackend: Send + Sync {
    /// Prove that the guest program computed the post-state root for the
    /// transition described by `transition`.
    async fn prove_block_transition(&self, transition: &ProveBlockTransition) -> Result<ZkProof>;

    /// Verify a guest-program proof against a transition. The in-memory
    /// backend recomputes the expected proof from the transition and compares;
    /// a real backend verifies inside the zkVM runtime.
    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub block_hash: [u8; 32],
    pub stateroot_pre: H256,
    pub transactions: Vec<Transaction>,
}

impl ProveBlockRequest {
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
        if !self.transactions.is_empty() && self.stateroot_pre == H256::ZERO {
            return Err(Error::Validation(
                "pre-state root required for transitions with transactions".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundleResponse {
    pub version: u32,
    pub api_version: u32,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub guest_id: String,
    pub guest_hash: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInfo {
    pub version: u32,
    pub api_version: u32,
    pub guest_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverStatus {
    pub version: u32,
    pub api_version: u32,
    pub available: bool,
    pub queue_length: u64,
}
