//! Verifier API trait

use super::prover::{ProveBlockTransition, ZkProof};
use crate::hash::H256;
use crate::proof::ProofCommitment;
use crate::types::{BlockNumber, Transaction};
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Synchronous proof verifier used by the node's block-apply path (issue #83).
///
/// `VerifierApi` is the public async DTO interface; nodes need a synchronous
/// check so verification can reject a block before any state is committed.
pub trait BlockProofVerifier: Send + Sync {
    /// Verify a zkVM proof against the state transition it attests.
    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool>;
}

#[async_trait]
pub trait VerifierApi: Send + Sync {
    fn api_version(&self) -> u32 {
        1
    }

    fn min_api_version(&self) -> u32 {
        1
    }

    async fn verify_block(&self, req: VerifyBlockRequest) -> Result<VerifyBlockResponse>;
    async fn verify_proof(&self, req: VerifyProofRequest) -> Result<VerifyProofResponse>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub height: BlockNumber,
    pub block_hash: [u8; 32],
    pub proof_bundle: Vec<u8>,
    /// Pre-state root the proved transition started from.
    pub stateroot_pre: H256,
    /// Post-state root the proved transition produced.
    pub stateroot_post: H256,
    pub guest_hash: H256,
    pub commitment: ProofCommitment,
    /// Transactions of the proved transition.
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub backend_witness: Vec<u8>,
}

impl VerifyBlockRequest {
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
        if self.proof_bundle.is_empty() {
            return Err(Error::Validation(
                "proof_bundle cannot be empty".to_string(),
            ));
        }
        if self.commitment.hash()?.as_bytes() != &self.block_hash {
            return Err(Error::Validation(
                "request block hash does not match proof commitment".to_string(),
            ));
        }
        Ok(())
    }

    pub fn into_transition(self) -> ProveBlockTransition {
        ProveBlockTransition {
            version: 1,
            height: self.height,
            block_hash: self.block_hash,
            stateroot_pre: self.stateroot_pre,
            stateroot_post: self.stateroot_post,
            guest_hash: self.guest_hash,
            commitment: self.commitment,
            transactions: self.transactions,
            backend_witness: self.backend_witness,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyBlockResponse {
    pub version: u32,
    pub api_version: u32,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyProofRequest {
    pub version: u32,
    pub api_version: u32,
    pub height: BlockNumber,
    pub block_hash: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    /// Pre-state root the proved transition started from (the post-state
    /// root is carried in `public_inputs`).
    pub stateroot_pre: H256,
    pub stateroot_post: H256,
    pub guest_hash: H256,
    pub commitment: ProofCommitment,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub backend_witness: Vec<u8>,
}

impl VerifyProofRequest {
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
        if self.proof_bytes.is_empty() {
            return Err(Error::Validation("proof_bytes cannot be empty".to_string()));
        }
        if self.commitment.hash()?.as_bytes() != &self.block_hash {
            return Err(Error::Validation(
                "request block hash does not match proof commitment".to_string(),
            ));
        }
        Ok(())
    }

    pub fn into_transition(self) -> ProveBlockTransition {
        ProveBlockTransition {
            version: 1,
            height: self.height,
            block_hash: self.block_hash,
            stateroot_pre: self.stateroot_pre,
            stateroot_post: self.stateroot_post,
            guest_hash: self.guest_hash,
            commitment: self.commitment,
            transactions: self.transactions,
            backend_witness: self.backend_witness,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    pub version: u32,
    pub api_version: u32,
    pub valid: bool,
    pub error: Option<String>,
}
