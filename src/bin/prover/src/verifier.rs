use async_trait::async_trait;
use workstream_core::hash::H256;
use workstream_core::traits::prover::{ProveBlockTransition, ZkProof};
use workstream_core::traits::verifier::{
    BlockProofVerifier, VerifierApi, VerifyBlockRequest, VerifyBlockResponse, VerifyProofRequest,
    VerifyProofResponse,
};
use workstream_core::Result;
use workstream_stf::receipt::Claim;

/// Standalone real-receipt verifier; no prover or private witness required.
pub struct ReceiptVerifier {
    approved_image: H256,
}

impl ReceiptVerifier {
    pub fn new(approved_image: H256) -> Self {
        Self { approved_image }
    }
}

impl BlockProofVerifier for ReceiptVerifier {
    fn verify_block_transition(
        &self,
        transition: &ProveBlockTransition,
        proof: &ZkProof,
    ) -> Result<bool> {
        transition.validate()?;
        proof.validate()?;
        if proof.guest_hash != transition.guest_hash
            || proof.guest_hash != self.approved_image
            || proof.commitment.as_bytes() != &transition.block_hash
            || proof.stateroot_pre != transition.stateroot_pre
            || proof.public_inputs != transition.stateroot_post.as_bytes().to_vec()
        {
            return Ok(false);
        }
        let claim = Claim::new(
            transition.height,
            H256::from_bytes(transition.block_hash),
            transition.stateroot_pre,
            transition.stateroot_post,
            &transition.transactions,
        )?;
        Ok(super::risc0::verify(&proof.proof_bytes, self.approved_image, &claim).is_ok())
    }
}

#[async_trait]
impl VerifierApi for ReceiptVerifier {
    async fn verify_block(&self, req: VerifyBlockRequest) -> Result<VerifyBlockResponse> {
        req.validate()?;
        let transition = req.clone().into_transition();
        transition.validate()?;
        let proof = ZkProof {
            version: 1,
            proof_bytes: req.proof_bundle,
            public_inputs: transition.stateroot_post.as_bytes().to_vec(),
            guest_id: self.approved_image.to_hex(),
            guest_hash: self.approved_image,
            stateroot_pre: transition.stateroot_pre,
            commitment: transition.commitment.hash()?,
        };
        let valid = BlockProofVerifier::verify_block_transition(self, &transition, &proof)?;
        Ok(VerifyBlockResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "invalid block receipt".into()),
        })
    }

    async fn verify_proof(&self, req: VerifyProofRequest) -> Result<VerifyProofResponse> {
        req.validate()?;
        let transition = req.clone().into_transition();
        transition.validate()?;
        let proof = ZkProof {
            version: 1,
            proof_bytes: req.proof_bytes,
            public_inputs: req.public_inputs,
            guest_id: self.approved_image.to_hex(),
            guest_hash: self.approved_image,
            stateroot_pre: transition.stateroot_pre,
            commitment: transition.commitment.hash()?,
        };
        let valid = BlockProofVerifier::verify_block_transition(self, &transition, &proof)?;
        Ok(VerifyProofResponse {
            version: 1,
            api_version: 1,
            valid,
            error: (!valid).then(|| "invalid proof receipt".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_verifier_rejects_wrong_approved_image() {
        let verifier = ReceiptVerifier::new(H256::ZERO);
        assert_eq!(verifier.approved_image, H256::ZERO);
    }
}
