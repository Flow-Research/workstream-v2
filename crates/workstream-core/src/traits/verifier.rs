//! Verifier API trait

use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
    pub block_hash: [u8; 32],
    pub proof_bundle: Vec<u8>,
}

impl VerifyBlockRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        if self.proof_bundle.is_empty() {
            return Err(Error::Validation("proof_bundle cannot be empty".to_string()));
        }
        Ok(())
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
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl VerifyProofRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::Validation(format!("unsupported dto version: {}", self.version)));
        }
        if self.api_version != 1 {
            return Err(Error::Validation(format!("unsupported api version: {}", self.api_version)));
        }
        if self.proof_bytes.is_empty() {
            return Err(Error::Validation("proof_bytes cannot be empty".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    pub version: u32,
    pub api_version: u32,
    pub valid: bool,
    pub error: Option<String>,
}
