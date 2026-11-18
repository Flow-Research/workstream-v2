//! Shielded notes, asset registry, and privacy commitments (issue #88).
//!
//! Implements the cryptographic core of the value model (design §2.4):
//! - shielded note commitments (domain-separated, blinding-aware),
//! - one-time note nullifiers per action family,
//! - spend derivation,
//! - recipient viewing keys,
//! - asset registry for the canonical asset kinds (native gas, bridged
//!   stablecoins, project points).

use std::collections::HashMap;

use crate::hash::{Hash, H256};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Domain tag for shielded note commitments.
const NOTE_COMMITMENT_TAG: &[u8] = b"WS:v1:note-commit:";
/// Domain tag for note-derived one-time nullifiers.
const NOTE_NULLIFIER_TAG: &[u8] = b"WS:v1:note-nullifier:";
/// Domain tag for note-derived viewing keys.
const NOTE_VIEWING_KEY_TAG: &[u8] = b"WS:v1:note-viewing-key:";

/// A shielded note: the private value transfer (asset + amount) held under a
/// one-time blinding factor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedNote {
    pub asset: H256,
    pub amount: u128,
    pub blinding: H256,
}

impl ShieldedNote {
    pub fn new(asset: H256, amount: u128, blinding: H256) -> Self {
        Self {
            asset,
            amount,
            blinding,
        }
    }

    /// Commitment of the note: domain-separated hash over the public note
    /// fields (asset, amount) and the blinding factor (value secrecy).
    pub fn commitment(&self) -> H256 {
        Hash::sha256_concat(&[
            NOTE_COMMITMENT_TAG,
            self.asset.as_bytes(),
            &self.amount.to_be_bytes(),
            self.blinding.as_bytes(),
        ])
    }

    /// One-time nullifier for an action family against this note: the note
    /// can be spent exactly once per family.
    pub fn nullifier(&self, family: &[u8]) -> H256 {
        Hash::sha256_concat(&[NOTE_NULLIFIER_TAG, family, self.commitment().as_bytes()])
    }

    /// Recipient viewing key for the note: derives the per-recipient
    /// authorization material from the note commitment.
    pub fn viewing_key(&self, recipient: H256) -> H256 {
        Hash::sha256_concat(&[
            NOTE_VIEWING_KEY_TAG,
            self.commitment().as_bytes(),
            recipient.as_bytes(),
        ])
    }
}

/// Spend an input note: derives the one-time spend nullifier for an action
/// family and fails closed on zero-value spends.
pub fn spend(note: &ShieldedNote, family: &[u8]) -> Result<H256> {
    if note.amount == 0 {
        return Err(Error::Validation(
            "cannot spend a zero-amount shielded note".to_string(),
        ));
    }
    Ok(note.nullifier(family))
}

/// Kind of asset in the canonical asset registry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssetKind {
    /// Native rollup gas asset.
    NativeGas,
    /// Bridged stablecoin (e.g. USDC).
    BridgedStablecoin,
    /// Project points (soulbound reputation value).
    ProjectPoints,
}

/// Canonical asset registered in the asset registry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub id: H256,
    pub kind: AssetKind,
}

/// Asset registry of canonical assets backing shielded notes.
#[derive(Debug, Default)]
pub struct AssetRegistry {
    assets: HashMap<H256, Asset>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an asset (idempotent by id).
    pub fn register(&mut self, asset: Asset) {
        self.assets.insert(asset.id, asset);
    }

    /// Look up an asset by id.
    pub fn get(&self, id: &H256) -> Option<&Asset> {
        self.assets.get(id)
    }

    /// Number of registered assets.
    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Whether any asset is registered.
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(asset: H256, amount: u128, blinding: H256) -> ShieldedNote {
        ShieldedNote::new(asset, amount, blinding)
    }

    #[test]
    fn shielded_note_commitment_is_deterministic_and_separated() {
        let n = note(H256::ZERO, 10, H256::from_bytes([3u8; 32]));
        assert_eq!(n.commitment(), n.commitment());

        let other_blinding = H256::from_bytes([9u8; 32]);
        assert_ne!(
            n.commitment(),
            note(H256::ZERO, 10, other_blinding).commitment()
        );
        assert_ne!(
            n.commitment(),
            note(H256::from_bytes([5u8; 32]), 10, n.blinding).commitment()
        );
        assert_ne!(
            n.commitment(),
            note(H256::ZERO, 11, n.blinding).commitment()
        );
    }

    #[test]
    fn note_nullifier_is_one_time_per_family() {
        let n = note(H256::ZERO, 10, H256::from_bytes([3u8; 32]));
        assert_eq!(n.nullifier(b"transfer"), n.nullifier(b"transfer"));
        assert_ne!(n.nullifier(b"transfer"), n.nullifier(b"release"));
    }

    #[test]
    fn note_viewing_key_derives_per_recipient() {
        let n = note(H256::ZERO, 10, H256::from_bytes([3u8; 32]));
        let recipient = H256::from_bytes([7u8; 32]);
        assert_eq!(n.viewing_key(recipient), n.viewing_key(recipient));
        assert_ne!(n.viewing_key(recipient), n.viewing_key(H256::ZERO));
    }

    #[test]
    fn spend_rejects_zero_amount_and_derives_nullifier() {
        let n = note(H256::ZERO, 10, H256::from_bytes([3u8; 32]));
        let spent = spend(&n, b"transfer").unwrap();
        assert_eq!(spent, n.nullifier(b"transfer"));

        let zero = note(H256::ZERO, 0, H256::from_bytes([3u8; 32]));
        assert!(spend(&zero, b"transfer").is_err());
    }

    #[test]
    fn asset_registry_registers_and_lookups() {
        let mut registry = AssetRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(Asset {
            id: H256::from_bytes([4u8; 32]),
            kind: AssetKind::BridgedStablecoin,
        });
        registry.register(Asset {
            id: H256::from_bytes([5u8; 32]),
            kind: AssetKind::NativeGas,
        });
        assert_eq!(registry.len(), 2);
        assert!(registry.get(&H256::from_bytes([4u8; 32])).is_some());
        assert!(registry.get(&H256::from_bytes([6u8; 32])).is_none());
    }
}
