//! Prover API trait

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveBlockRequest {
    pub version: u32,
    pub api_version: u32,
    pub block_hash: [u8; 32],
}

impl ProveBlockRequest {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundleResponse {
    pub version: u32,
    pub api_version: u32,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub guest_id: String,
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
