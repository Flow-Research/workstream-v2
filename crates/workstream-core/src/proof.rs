//! Canonical proof commitments shared by sequencer, prover and node (issue #83).
//!
//! A proof must bind the exact block transition it attests without binding the
//! DA reference (assigned after publication) or the proof itself (attached
//! after generation). The [`ProofCommitment`] below is that stable preimage;
//! every participant derives the same hash from the candidate header and the
//! pre/post state roots.

use serde::{Deserialize, Serialize};

use crate::hash::{Hash, H256};
use crate::types::{BlockHeader, BlockNumber, Transaction};
use crate::{Error, Result};

/// Domain tag for the canonical transaction commitment inside proof data.
pub const TRANSACTIONS_TAG: &[u8] = b"WS:v1:zk-transactions:";

/// Domain tag for the canonical proof commitment.
pub const PROOF_COMMITMENT_TAG: &[u8] = b"WS:v1:proof-commitment:";

/// Version of the canonical proof commitment preimage.
pub const PROOF_COMMITMENT_VERSION: u32 = 1;

/// Commitment over the ordered transactions of a proved transition.
pub fn transactions_commitment(transactions: &[Transaction]) -> Result<H256> {
    let bytes = postcard::to_allocvec(transactions)
        .map_err(|e| Error::Serialization(format!("proof transactions encode: {e}")))?;
    Ok(Hash::sha256_concat(&[TRANSACTIONS_TAG, &bytes]))
}

/// Stable preimage committed by every block-transition proof.
///
/// `da_ref` and `header.proof` are deliberately absent: the former is filled
/// in after DA publication and the latter is the proof being described.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofCommitment {
    pub version: u32,
    pub height: BlockNumber,
    pub parent_hash: H256,
    pub timestamp: u64,
    pub tx_root: H256,
    pub transactions_hash: H256,
    pub stateroot_pre: H256,
    pub stateroot_post: H256,
    pub fork_id: u64,
    pub guest_hash: H256,
    pub proof_system_version: u32,
}

impl ProofCommitment {
    /// Derive the commitment from a candidate header, the pre-state root and
    /// the exact transactions included in the block.
    pub fn new(
        header: &BlockHeader,
        stateroot_pre: H256,
        transactions: &[Transaction],
    ) -> Result<Self> {
        Ok(Self {
            version: PROOF_COMMITMENT_VERSION,
            height: header.number,
            parent_hash: header.parent_hash,
            timestamp: header.timestamp,
            tx_root: header.tx_root,
            transactions_hash: transactions_commitment(transactions)?,
            stateroot_pre,
            stateroot_post: header.state_root.hash(),
            fork_id: header.fork_id,
            guest_hash: header.guest_hash,
            proof_system_version: header.proof_system_version,
        })
    }

    /// Domain-tagged hash of the canonical preimage.
    pub fn hash(&self) -> Result<H256> {
        if self.version != PROOF_COMMITMENT_VERSION {
            return Err(Error::Validation(format!(
                "unsupported proof commitment version: {}",
                self.version
            )));
        }
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| Error::Serialization(format!("proof commitment encode: {e}")))?;
        Ok(Hash::sha256_concat(&[PROOF_COMMITMENT_TAG, &bytes]))
    }

    /// Validate that a transition's fields agree with this preimage.
    pub fn matches_transition(
        &self,
        height: BlockNumber,
        stateroot_pre: H256,
        stateroot_post: H256,
        guest_hash: H256,
        transactions: &[Transaction],
    ) -> Result<()> {
        let expected_txs = transactions_commitment(transactions)?;
        if self.height != height
            || self.stateroot_pre != stateroot_pre
            || self.stateroot_post != stateroot_post
            || self.guest_hash != guest_hash
            || self.transactions_hash != expected_txs
        {
            return Err(Error::InvalidProof(
                "proof commitment does not match transition".into(),
            ));
        }
        Ok(())
    }
}

/// Convenience wrapper returning the canonical proof commitment hash.
pub fn proof_commitment(
    header: &BlockHeader,
    stateroot_pre: H256,
    transactions: &[Transaction],
) -> Result<H256> {
    ProofCommitment::new(header, stateroot_pre, transactions)?.hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Action, ActionType, FeePayer, FeeSpec, Nonce};

    fn test_header() -> BlockHeader {
        BlockHeader {
            number: 1,
            parent_hash: H256::from_bytes([1; 32]),
            timestamp: 12,
            tx_root: H256::from_bytes([2; 32]),
            state_root: crate::StateRoot::new(H256::from_bytes([3; 32]), H256::from_bytes([4; 32])),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::from_bytes([5; 32]),
            proof_system_version: 1,
            proof: None,
        }
    }

    #[test]
    fn commitment_ignores_proof_and_da_reference() {
        let pre = H256::from_bytes([9; 32]);
        let mut header = test_header();
        let bare = proof_commitment(&header, pre, &[]).unwrap();

        header.da_ref = H256::from_bytes([7; 32]);
        header.proof = Some(crate::Proof {
            proof_data: vec![1, 2, 3],
            proof_type: crate::ProofType::ZkVm,
        });
        assert_eq!(bare, proof_commitment(&header, pre, &[]).unwrap());
    }

    #[test]
    fn commitment_binds_every_transition_field() {
        let pre = H256::from_bytes([9; 32]);
        let tx = Transaction {
            chain_id: 1,
            account: H256::from_bytes([8; 32]),
            nonce: Nonce { key_id: 0, seq: 0 },
            actions: vec![Action {
                action_type: ActionType::ActorRegister,
                payload: vec![1],
            }],
            fee: FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1,
            },
            auth: vec![],
            signature: None,
            public_key: None,
        };
        let mut header = test_header();
        let base = ProofCommitment::new(&header, pre, &[]).unwrap();

        header.number = 2;
        assert_ne!(base, ProofCommitment::new(&header, pre, &[]).unwrap());
        header = test_header();

        let with_tx = ProofCommitment::new(&header, pre, std::slice::from_ref(&tx)).unwrap();
        assert_ne!(base, with_tx);
        assert!(with_tx
            .matches_transition(
                header.number,
                pre,
                header.state_root.hash(),
                header.guest_hash,
                &[tx],
            )
            .is_ok());
    }
}
