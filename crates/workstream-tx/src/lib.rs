//! Transaction types and validation for WorkStream
//!
//! Implements the 19 transaction types from the design:
//! actor.*, project.*, policy.*, task.*, bundle.*, submission.*,
//! check.*, route.*, review.*, revision.*, accept.*, award.*, etc.

use serde::{Deserialize, Serialize};
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_crypto::signature::{self, PublicKey, Signature, SignatureAlgorithm};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxValidator;

impl TxValidator {
    pub fn new() -> Self {
        TxValidator
    }

    /// Validate a transaction at admission.
    ///
    /// Checks structural well-formedness and verifies the transaction
    /// signature against the attached verifying key (SEC-001). The check is
    /// fail-closed: an unsigned transaction or one signed by an unknown key is
    /// rejected before any state transition can be attempted.
    pub fn validate(&self, tx: &Transaction) -> Result<()> {
        // Basic validation
        if tx.actions.is_empty() {
            return Err(Error::Transaction("Empty transaction".to_string()));
        }
        if tx.fee.max_fee == 0 {
            return Err(Error::Transaction("Zero fee".to_string()));
        }
        self.verify_signature(tx)?;
        Ok(())
    }

    /// Verify the transaction signature against its attached verifying key.
    ///
    /// The signed message is the canonical transaction hash. A missing
    /// signature or public key is a validation failure; an invalid signature
    /// fails closed as well.
    fn verify_signature(&self, tx: &Transaction) -> Result<()> {
        let signature = tx
            .signature
            .as_ref()
            .ok_or_else(|| Error::Validation("transaction is unsigned".to_string()))?;
        let public_key = tx.public_key.as_ref().ok_or_else(|| {
            Error::Validation("transaction has no verifying public key".to_string())
        })?;
        let algorithm = Self::algorithm_for(public_key)?;
        let sig = Signature::new(algorithm, signature.clone());
        let pk = PublicKey::new(algorithm, public_key.clone());
        let message = signature::tx_message_hash(tx)?;
        let valid = signature::verify(message.as_bytes(), &sig, &pk)?;
        if !valid {
            return Err(Error::InvalidSignature);
        }
        if pk.account_id()? != tx.account {
            return Err(Error::Unauthorized(
                "signing key does not control transaction account".into(),
            ));
        }
        Ok(())
    }

    /// Map raw verifying-key bytes to the signature algorithm they encode.
    fn algorithm_for(public_key: &[u8]) -> Result<SignatureAlgorithm> {
        match public_key.len() {
            32 => Ok(SignatureAlgorithm::Ed25519),
            33 | 65 => Ok(SignatureAlgorithm::Secp256k1),
            _ => Err(Error::Crypto(format!(
                "invalid public key length: {}",
                public_key.len()
            ))),
        }
    }
}

impl Default for TxValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction builder for convenience
#[derive(Default)]
pub struct TxBuilder {
    chain_id: u64,
    account: Option<AccountId>,
    nonce: Option<Nonce>,
    actions: Vec<Action>,
    fee: Option<FeeSpec>,
    auth: Vec<u8>,
    signature: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            chain_id: 1,
            ..Default::default()
        }
    }

    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn account(mut self, account: AccountId) -> Self {
        self.account = Some(account);
        self
    }

    pub fn nonce(mut self, key_id: u16, seq: u64) -> Self {
        self.nonce = Some(Nonce { key_id, seq });
        self
    }

    pub fn add_action(mut self, action_type: ActionType, payload: Vec<u8>) -> Self {
        self.actions.push(Action {
            action_type,
            payload,
        });
        self
    }

    pub fn fee(mut self, fee: FeeSpec) -> Self {
        self.fee = Some(fee);
        self
    }

    pub fn auth(mut self, auth: Vec<u8>) -> Self {
        self.auth = auth;
        self
    }

    /// Attach the transaction signature (raw bytes) and its verifying
    /// public key. Admission verifies the signature; omitting either makes
    /// the built transaction fail closed at validation time (SEC-001).
    pub fn signature_and_key(
        mut self,
        signature: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Self {
        self.signature = signature;
        self.public_key = public_key;
        self
    }

    pub fn build(self) -> Result<Transaction> {
        Ok(Transaction {
            chain_id: self.chain_id,
            account: self
                .account
                .ok_or_else(|| Error::Transaction("Account required".to_string()))?,
            nonce: self
                .nonce
                .ok_or_else(|| Error::Transaction("Nonce required".to_string()))?,
            actions: self.actions,
            fee: self
                .fee
                .ok_or_else(|| Error::Transaction("Fee required".to_string()))?,
            auth: self.auth,
            signature: self.signature,
            public_key: self.public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_crypto::signature;

    fn ed25519_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed_tx() -> Transaction {
        let mut tx = TxBuilder::new()
            .chain_id(1)
            .account(workstream_core::Hash::sha256(
                ed25519_signing_key().verifying_key().as_bytes(),
            ))
            .nonce(0, 0)
            .add_action(ActionType::ActorRegister, b"payload".to_vec())
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1_000,
            })
            .build()
            .unwrap();
        signature::sign_tx_ed25519(&mut tx, &ed25519_signing_key()).unwrap();
        tx
    }

    #[test]
    fn accepts_well_signed_transaction() {
        assert!(TxValidator::new().validate(&signed_tx()).is_ok());
    }

    #[test]
    fn rejects_unsigned_transaction() {
        let mut tx = signed_tx();
        tx.signature = None;
        tx.public_key = None;
        assert!(TxValidator::new().validate(&tx).is_err());
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut tx = signed_tx();
        tx.signature = Some(vec![0u8; 64]);
        assert!(matches!(
            TxValidator::new().validate(&tx),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_malformed_public_key() {
        let mut tx = signed_tx();
        tx.public_key = Some(vec![0u8; 16]);
        assert!(TxValidator::new().validate(&tx).is_err());
    }
}
