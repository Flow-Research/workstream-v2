use flowstream_core::hash::{Hash, H256};

/// Pedersen-style commitment using SHA-256 (simplified)
#[derive(Clone, Debug)]
pub struct Commitment;

impl Commitment {
    pub fn commit(value: &[u8], blinding: &[u8]) -> H256 {
        Hash::sha256_concat(&[b"COMMIT:", value, blinding])
    }
    
    pub fn nullifier(note_hash: &H256, nullifier_key: &[u8]) -> H256 {
        Hash::sha256_concat(&[b"NULLIFIER:", note_hash.as_bytes(), nullifier_key])
    }
}
