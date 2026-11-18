use super::*;
use ed25519_dalek::{Signature, VerifyingKey};

/// Operator-configured authority. The domain identifies the source chain,
/// source bridge and destination rollup/bridge deployment.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositAuthority {
    pub domain: H256,
    pub public_key: [u8; 32],
}

impl DepositAuthority {
    pub(super) fn key(&self) -> Result<VerifyingKey> {
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| Error::Config("invalid deposit authority key".into()))?;
        if key.is_weak() || self.domain == H256::ZERO {
            return Err(Error::Config("invalid deposit authority or domain".into()));
        }
        Ok(key)
    }
}

/// Attestation by the configured authority of one finalized source deposit.
/// `source_event` must uniquely identify the deposit (e.g. transaction hash
/// plus log index); it is not a nonce chosen by the depositor.
#[derive(Clone, Serialize, Deserialize)]
pub struct DepositReceipt {
    pub domain: H256,
    pub source_event: H256,
    pub asset: Asset,
    pub amount: u128,
    pub note_commitment: H256,
    pub recipient: AccountId,
    pub task: Option<TaskId>,
}

impl DepositReceipt {
    /// Domain-separated digest signed directly with Ed25519.
    pub fn signing_digest(&self) -> Result<H256> {
        let encoded =
            postcard::to_allocvec(self).map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(Hash::sha256_concat(&[
            b"WS:v1:bridge:deposit-receipt:",
            &encoded,
        ]))
    }

    pub(super) fn verify(
        &self,
        authority: &DepositAuthority,
        signature: &[u8; 64],
        note: &ShieldedNote,
    ) -> Result<()> {
        if self.domain != authority.domain {
            return Err(Error::Unauthorized("receipt for different bridge".into()));
        }
        authority
            .key()?
            .verify_strict(
                self.signing_digest()?.as_bytes(),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| Error::InvalidSignature)?;
        if note.commitment() != self.note_commitment
            || self.asset.id != note.asset
            || self.amount != note.amount
        {
            return Err(Error::Validation("receipt does not match note".into()));
        }
        Ok(())
    }
}
