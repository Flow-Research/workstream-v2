pub use flowstream_core::hash::*;
use sha2::{Digest, Sha256};

/// Content identifier: sha256:<hex>
#[derive(Clone, Debug)]
pub struct ContentId(String);

impl ContentId {
    pub fn new(data: &[u8]) -> Self {
        let hash = Hash::sha256(data);
        ContentId(format!("sha256:{}", hash.to_hex()))
    }
    
    pub fn from_hash(hash: H256) -> Self {
        ContentId(format!("sha256:{}", hash.to_hex()))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hash a policy body
pub fn hash_policy(body: &[u8]) -> H256 {
    Hash::sha256_concat(&[b"POLICY_V1:", body])
}

/// Hash a guide document
pub fn hash_guide(doc: &[u8]) -> H256 {
    Hash::sha256_concat(&[b"GUIDE_V1:", doc])
}
