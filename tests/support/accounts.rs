//! Deterministic, distinct Ed25519 identities for integration fixtures.
use ed25519_dalek::SigningKey;
use std::{collections::HashMap, sync::OnceLock};
use workstream_core::{AccountId, Hash};

pub fn account(tag: u8) -> AccountId {
    Hash::sha256(
        SigningKey::from_bytes(&[tag; 32])
            .verifying_key()
            .as_bytes(),
    )
}

pub fn signer(id: AccountId) -> SigningKey {
    static TAGS: OnceLock<HashMap<AccountId, u8>> = OnceLock::new();
    let tags = TAGS.get_or_init(|| (0..=255).map(|tag| (account(tag), tag)).collect());
    SigningKey::from_bytes(&[tags[&id]; 32])
}
