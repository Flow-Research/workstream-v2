//! Canonical serialization for FlowStream
//! 
//! Ensures canonical encoding for hash-locked lineage

use flowstream_core::{Result, Error};

pub struct Rlp;

impl Rlp {
    pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        // Use bincode for now as simplified canonical encoding
        bincode::serialize(value).map_err(|e: bincode::Error| Error::Serialization(e.to_string()))
    }
    
    pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        bincode::deserialize(bytes).map_err(|e: bincode::Error| Error::Serialization(e.to_string()))
    }
}
