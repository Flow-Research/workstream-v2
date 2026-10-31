//! Canonical serialization for WorkStream
//!
//! Ensures canonical encoding for hash-locked lineage

use workstream_core::{Error, Result};

pub struct Rlp;

impl Rlp {
    pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        // Use bincode for now as simplified canonical encoding
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let (result, _): (T, usize) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(result)
    }
}
