pub use workstream_core::hash::*;

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

/// Hash canonical policy bytecode.
///
/// Uses the `POLICY_V1:` domain tag defined by the policy DSL contract.
/// `body` must be canonical `WSPL` bytecode, not policy source text.
pub fn hash_policy(body: &[u8]) -> H256 {
    Hash::sha256_concat(&[b"POLICY_V1:", body])
}

/// Hash a guide document
pub fn hash_guide(doc: &[u8]) -> H256 {
    Hash::sha256_concat(&[b"GUIDE_V1:", doc])
}
