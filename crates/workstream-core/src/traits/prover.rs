//! Prover API trait

use crate::hash::H256;
use crate::proof::ProofCommitment;
use crate::types::{BlockNumber, Transaction};
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

/// A guest-program transition to prove: execute `transactions` from
/// `stateroot_pre` and attest `stateroot_post`.
///
/// `block_hash` is the canonical [`ProofCommitment`] hash, not the DA
/// reference or a block hash that includes the attached proof. The
/// `backend_witness` is private input for the backend (a snapshot for the
/// in-memory/guest backends); it is never serialized into a block header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveBlockTransition {
    pub version: u32,
    pub height: BlockNumber,
    /// Canonical proof commitment hash.
    pub block_hash: [u8; 32],
    pub stateroot_pre: H256,
    pub stateroot_post: H256,
    pub guest_hash: H256,
    pub commitment: ProofCommitment,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub backend_witness: Vec<u8>,
}

impl ProveBlockTransition {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported dto version: {}",
                self.version
            )));
        }
        if self.height == 0 {
            return Err(Error::Validation(
                "proof transition height must be greater than zero".to_string(),
            ));
        }
        let expected = self.commitment.hash()?;
        if expected.as_bytes() != &self.block_hash {
            return Err(Error::Validation(
                "transition block hash does not match proof commitment".to_string(),
            ));
        }
        self.commitment.matches_transition(
            self.height,
            self.stateroot_pre,
            self.stateroot_post,
            self.guest_hash,
            &self.transactions,
        )
    }

    /// Canonical commitment hash as an `H256`.
    pub fn commitment_hash(&self) -> Result<H256> {
        self.commitment.hash()
    }
}

/// A zero-knowledge proof over a guest program execution, together with the
/// public inputs the proof attests (here: the post-state root the guest
/// computed from the pre-state root and the block transactions).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof {
    pub version: u32,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub guest_id: String,
    /// Measured hash of the guest program that produced the proof.
    pub guest_hash: H256,
    /// Pre-state root the guest proved from (the post-state root is the
    /// public input).
    pub stateroot_pre: H256,
    /// Hash of the canonical [`ProofCommitment`] bound by the proof.
    pub commitment: H256,
}

impl ZkProof {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported proof version: {}",
                self.version
            )));
        }
        if self.proof_bytes.is_empty() {
            return Err(Error::Validation("proof_bytes cannot be empty".to_string()));
        }
        if self.public_inputs.len() != 32 {
            return Err(Error::Validation(
                "public_inputs must be a 32-byte state root".to_string(),
            ));
        }
        if self.commitment == H256::ZERO {
            return Err(Error::Validation(
                "proof commitment cannot be zero".to_string(),
            ));
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
    pub height: BlockNumber,
    pub block_hash: [u8; 32],
    pub stateroot_pre: H256,
    pub stateroot_post: H256,
    pub guest_hash: H256,
    pub commitment: ProofCommitment,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub backend_witness: Vec<u8>,
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
        if self.height == 0 {
            return Err(Error::Validation(
                "proof request height must be greater than zero".to_string(),
            ));
        }
        let expected = self.commitment.hash()?;
        if expected.as_bytes() != &self.block_hash {
            return Err(Error::Validation(
                "request block hash does not match proof commitment".to_string(),
            ));
        }
        self.commitment.matches_transition(
            self.height,
            self.stateroot_pre,
            self.stateroot_post,
            self.guest_hash,
            &self.transactions,
        )
    }

    /// Convert the DTO into the backend transition.
    pub fn into_transition(self) -> ProveBlockTransition {
        ProveBlockTransition {
            version: self.version,
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
pub struct ProofBundleResponse {
    pub version: u32,
    pub api_version: u32,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub guest_id: String,
    pub guest_hash: H256,
    /// Pre-state root the guest proved from.
    pub stateroot_pre: H256,
    /// Full state root attested by the proof (also encoded in `public_inputs`).
    pub stateroot_post: H256,
    pub commitment: H256,
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
