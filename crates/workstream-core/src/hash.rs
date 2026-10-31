use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct H256([u8; 32]);

impl H256 {
    pub const ZERO: H256 = H256([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        H256(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> crate::Result<Self> {
        let bytes = hex::decode(s).map_err(|e| crate::Error::Crypto(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(crate::Error::Crypto("Invalid hash length".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(H256(arr))
    }
}

impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", &self.to_hex()[0..8])
    }
}

impl fmt::Display for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl Default for H256 {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Debug)]
pub struct Hash;

impl Hash {
    pub fn sha256(data: &[u8]) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        H256(result.into())
    }

    pub fn sha256_concat(data: &[&[u8]]) -> H256 {
        let mut hasher = Sha256::new();
        for d in data {
            hasher.update(d);
        }
        let result = hasher.finalize();
        H256(result.into())
    }
}

pub trait Hashable {
    fn hash(&self) -> H256;
}
