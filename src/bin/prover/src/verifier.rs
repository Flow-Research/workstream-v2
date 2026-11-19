use async_trait::async_trait;
use workstream_core::traits::verifier::*;
use workstream_core::{Result, H256};
use workstream_stf::receipt::Claim;

/// Standalone receipt verification; no prover or private witness required.
pub struct ReceiptVerifier {
    approved_image: H256,
}

impl ReceiptVerifier {
    pub fn new(approved_image: H256) -> Self {
        Self { approved_image }
    }
}

#[async_trait]
impl VerifierApi for ReceiptVerifier {
    async fn verify_block(&self, req: VerifyBlockRequest) -> Result<VerifyBlockResponse> {
        req.validate()?;
        let valid = if let Ok(claim) =
            super::risc0::verified_claim(&req.proof_bundle, self.approved_image)
        {
            claim
                == Claim::new(
                    req.height,
                    H256::from_bytes(req.block_hash),
                    req.stateroot_pre,
                    req.stateroot_post,
                    &req.transactions,
                )?
        } else {
            false
        };
        Ok(VerifyBlockResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "invalid block receipt".into()),
        })
    }
    async fn verify_proof(&self, req: VerifyProofRequest) -> Result<VerifyProofResponse> {
        req.validate()?;
        let valid = super::risc0::verified_claim(&req.proof_bytes, self.approved_image).is_ok_and(
            |claim| {
                claim.pre == req.stateroot_pre
                    && claim.post.as_bytes().as_slice() == req.public_inputs
            },
        );
        Ok(VerifyProofResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "invalid proof receipt".into()),
        })
    }
}
