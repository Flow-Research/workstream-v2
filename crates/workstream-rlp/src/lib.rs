//! Canonical serialization for WorkStream
//!
//! Ensures canonical encoding for hash-locked lineage.
//! Uses postcard: a maintained, deterministic serde-backed
//! binary format (replaces the unmaintained bincode crate, RUSTSEC-2025-0141).

use workstream_core::{Error, Result};

pub struct Rlp;

impl Rlp {
    pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        postcard::to_allocvec(value).map_err(|e| Error::Serialization(e.to_string()))
    }

    pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        postcard::from_bytes(bytes).map_err(|e| Error::Serialization(e.to_string()))
    }
}
