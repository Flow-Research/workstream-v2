//! Single-key Ed25519 wallet. Store the age-encrypted backup and the age
//! recovery identity separately. Sequence numbers are supplied by the caller:
//! mempool admission is not confirmation that a nonce was consumed.

pub use age::x25519::{Identity as RecoveryKey, Recipient as RecoveryRecipient};
use ed25519_dalek::SigningKey;
use workstream_core::traits::sequencer::{SequencerApi, SubmitTxRequest, TxStatus};
use workstream_core::{AccountId, Action, Error, FeeSpec, Hash, Result, Transaction, H256};
use workstream_crypto::signature::sign_tx_ed25519;
use workstream_tx::{tx_hash, TxBuilder, TxValidator};
use zeroize::Zeroizing;

pub struct Wallet {
    key: SigningKey,
    chain_id: u64,
}

impl Wallet {
    pub fn generate(chain_id: u64) -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *seed).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
            chain_id,
        })
    }

    /// Encrypt a backup for storage by the caller. No plaintext export API.
    pub fn backup(&self, recipient: &RecoveryRecipient) -> Result<Vec<u8>> {
        age::encrypt(recipient, self.key.as_bytes())
            .map_err(|_| Error::Crypto("wallet backup failed".into()))
    }

    /// Restore a trusted, locally stored backup for the selected chain.
    pub fn restore(chain_id: u64, backup: &[u8], recovery: &RecoveryKey) -> Result<Self> {
        if backup.len() > 4096 {
            return Err(Error::Validation("oversized wallet backup".into()));
        }
        let seed = Zeroizing::new(
            age::decrypt(recovery, backup)
                .map_err(|_| Error::Crypto("cannot decrypt wallet backup".into()))?,
        );
        let key = SigningKey::from_bytes(
            seed.as_slice()
                .try_into()
                .map_err(|_| Error::Crypto("invalid wallet seed".into()))?,
        );
        Ok(Self { key, chain_id })
    }

    pub fn account(&self) -> AccountId {
        Hash::sha256(self.key.verifying_key().as_bytes())
    }

    /// Build and sign one or more actions for this wallet's default nonce lane.
    pub fn sign(
        &self,
        seq: u64,
        fee: FeeSpec,
        actions: impl IntoIterator<Item = Action>,
    ) -> Result<Transaction> {
        let mut builder = TxBuilder::new()
            .chain_id(self.chain_id)
            .account(self.account())
            .nonce(0, seq)
            .fee(fee);
        for action in actions {
            builder = builder.add_action(action.action_type, action.payload);
        }
        let mut tx = builder.build()?;
        sign_tx_ed25519(&mut tx, &self.key)?;
        TxValidator::new().validate(&tx)?;
        Ok(tx)
    }

    /// Submit a previously signed transaction without changing it on retry.
    /// Returns the canonical hash only for a matching admission acknowledgement.
    pub async fn submit(&self, api: &dyn SequencerApi, tx: &Transaction) -> Result<H256> {
        if tx.chain_id != self.chain_id
            || tx.account != self.account()
            || tx.public_key.as_deref() != Some(self.key.verifying_key().as_bytes().as_slice())
        {
            return Err(Error::Validation(
                "transaction does not belong to this wallet and chain".into(),
            ));
        }
        TxValidator::new().validate(tx)?;
        let expected = tx_hash(tx)?;
        let response = api
            .submit_tx(SubmitTxRequest {
                version: 1,
                api_version: 1,
                tx_bytes: serde_json::to_vec(tx)
                    .map_err(|e| Error::Serialization(e.to_string()))?,
            })
            .await?;
        if response.version != 1 || response.api_version != 1 {
            return Err(Error::VersionMismatch(
                "unsupported submission response".into(),
            ));
        }
        if let TxStatus::Rejected(reason) = response.status {
            return Err(Error::Transaction(reason));
        }
        if response.tx_hash != *expected.as_bytes() {
            return Err(Error::Validation(
                "sequencer acknowledged a different transaction".into(),
            ));
        }
        Ok(expected)
    }
}
