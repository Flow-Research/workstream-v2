//! Canonical serialization for WorkStream (issue #18)
//!
//! Provides deterministic binary encoding for all consensus-critical types.
//! The encoding must satisfy:
//!
//! 1. **Determinism**: Same value always produces identical bytes
//! 2. **Uniqueness**: Each value has exactly one valid encoding
//! 3. **Completeness**: All values can be encoded and decoded
//!
//! ## Encoding Rules
//!
//! Uses [postcard](https://docs.rs/postcard), a maintained serde-backed binary
//! format that guarantees deterministic encoding. Key properties:
//!
//! - **Integers**: Variable-length encoding (varint), little-endian
//! - **Sequences**: Length-prefixed with varint length
//! - **Structs**: Fields in declaration order, no field tags
//! - **Enums**: Variant index (varint) followed by variant data
//! - **Options**: 0x00 for None, 0x01 followed by value for Some
//! - **Maps**: NOT SUPPORTED for canonical encoding (iteration order undefined)
//!
//! ## Why Not RLP?
//!
//! Despite the crate name (`workstream-rlp`), we use postcard instead of
//! Ethereum's RLP because:
//!
//! - RLP crates have had security issues and maintenance gaps
//! - Postcard is actively maintained and serde-native
//! - The encoding is equally deterministic
//! - Better Rust integration (no custom derive macros needed)
//!
//! ## Why Not bincode?
//!
//! bincode was considered but rejected due to:
//! - RUSTSEC-2025-0141: Unmaintained crate
//! - Non-deterministic encoding in some configurations
//!
//! ## Usage
//!
//! All consensus types should use `Rlp::encode` for hashing and signatures:
//!
//! ```ignore
//! use workstream_rlp::Rlp;
//!
//! let tx = Transaction { ... };
//! let bytes = Rlp::encode(&tx)?;
//! let hash = Hash::sha256(&bytes);
//! ```

use serde::{de::DeserializeOwned, Serialize};
use workstream_core::hash::{Hash, H256};
use workstream_core::{Error, Result};

/// Canonical binary serialization.
///
/// Wraps postcard for deterministic encode/decode operations.
pub struct Rlp;

impl Rlp {
    /// Encode a value to canonical bytes.
    ///
    /// The encoding is deterministic: encoding the same value twice
    /// always produces identical bytes.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        postcard::to_allocvec(value).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Decode bytes to a value.
    ///
    /// Returns an error if the bytes don't represent a valid encoding
    /// of the target type.
    pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        postcard::from_bytes(bytes).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Compute the canonical hash of a value.
    ///
    /// This is the standard way to hash consensus types for signing,
    /// content addressing, and Merkle tree construction.
    pub fn hash<T: Serialize>(value: &T) -> Result<H256> {
        let bytes = Self::encode(value)?;
        Ok(Hash::sha256(&bytes))
    }

    /// Encode and return both bytes and hash.
    ///
    /// Efficient when you need both the encoding and its hash.
    pub fn encode_and_hash<T: Serialize>(value: &T) -> Result<(Vec<u8>, H256)> {
        let bytes = Self::encode(value)?;
        let hash = Hash::sha256(&bytes);
        Ok((bytes, hash))
    }
}

/// Marker trait for types that have canonical serialization.
///
/// Types implementing this trait guarantee:
/// - No HashMap/HashSet fields (use BTreeMap/BTreeSet instead)
/// - No floating-point fields
/// - All nested types also implement CanonicalSerialize
///
/// This trait is a documentation marker; the actual encoding uses serde.
pub trait CanonicalSerialize: Serialize + DeserializeOwned {
    /// Return the canonical encoding of this value.
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Rlp::encode(self)
    }

    /// Return the canonical hash of this value.
    fn canonical_hash(&self) -> Result<H256> {
        Rlp::hash(self)
    }
}

// Blanket implementation for types that are Serialize + DeserializeOwned
// Note: In practice, only types with deterministic field ordering should use this.
// HashMap/HashSet will compile but produce non-deterministic results.

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestStruct {
        a: u64,
        b: String,
        c: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum TestEnum {
        Unit,
        Newtype(u32),
        Tuple(u8, u16),
        Struct { x: i32, y: i32 },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Nested {
        inner: TestStruct,
        map: BTreeMap<String, u64>,
        opt: Option<u8>,
    }

    #[test]
    fn encode_decode_roundtrip() {
        let value = TestStruct {
            a: 42,
            b: "hello".to_string(),
            c: vec![1, 2, 3],
        };

        let bytes = Rlp::encode(&value).unwrap();
        let decoded: TestStruct = Rlp::decode(&bytes).unwrap();

        assert_eq!(value, decoded);
    }

    #[test]
    fn encoding_is_deterministic() {
        let value = TestStruct {
            a: 12345,
            b: "deterministic".to_string(),
            c: vec![255, 0, 128],
        };

        let bytes1 = Rlp::encode(&value).unwrap();
        let bytes2 = Rlp::encode(&value).unwrap();

        assert_eq!(bytes1, bytes2, "encoding must be deterministic");
    }

    #[test]
    fn hash_is_deterministic() {
        let value = TestStruct {
            a: 999,
            b: "hash me".to_string(),
            c: vec![],
        };

        let hash1 = Rlp::hash(&value).unwrap();
        let hash2 = Rlp::hash(&value).unwrap();

        assert_eq!(hash1, hash2, "hash must be deterministic");
    }

    #[test]
    fn different_values_different_hashes() {
        let v1 = TestStruct {
            a: 1,
            b: "one".to_string(),
            c: vec![],
        };
        let v2 = TestStruct {
            a: 2,
            b: "two".to_string(),
            c: vec![],
        };

        let h1 = Rlp::hash(&v1).unwrap();
        let h2 = Rlp::hash(&v2).unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn enum_variants_encode_uniquely() {
        let variants = [
            TestEnum::Unit,
            TestEnum::Newtype(42),
            TestEnum::Tuple(1, 2),
            TestEnum::Struct { x: 10, y: 20 },
        ];

        let encodings: Vec<_> = variants.iter().map(|v| Rlp::encode(v).unwrap()).collect();

        // All encodings should be different
        for i in 0..encodings.len() {
            for j in (i + 1)..encodings.len() {
                assert_ne!(
                    encodings[i], encodings[j],
                    "variants {} and {} should encode differently",
                    i, j
                );
            }
        }
    }

    #[test]
    fn nested_structures() {
        let mut map = BTreeMap::new();
        map.insert("key1".to_string(), 100);
        map.insert("key2".to_string(), 200);

        let value = Nested {
            inner: TestStruct {
                a: 1,
                b: "nested".to_string(),
                c: vec![0],
            },
            map,
            opt: Some(42),
        };

        let bytes = Rlp::encode(&value).unwrap();
        let decoded: Nested = Rlp::decode(&bytes).unwrap();

        assert_eq!(value, decoded);
    }

    #[test]
    fn btreemap_is_deterministic() {
        // BTreeMap iteration is deterministic (sorted by key)
        let mut map1 = BTreeMap::new();
        map1.insert("b", 2);
        map1.insert("a", 1);
        map1.insert("c", 3);

        let mut map2 = BTreeMap::new();
        map2.insert("c", 3);
        map2.insert("a", 1);
        map2.insert("b", 2);

        let bytes1 = Rlp::encode(&map1).unwrap();
        let bytes2 = Rlp::encode(&map2).unwrap();

        assert_eq!(bytes1, bytes2, "BTreeMap encoding must be deterministic");
    }

    #[test]
    fn option_encoding() {
        let some_val: Option<u32> = Some(42);
        let none_val: Option<u32> = None;

        let some_bytes = Rlp::encode(&some_val).unwrap();
        let none_bytes = Rlp::encode(&none_val).unwrap();

        assert_ne!(some_bytes, none_bytes);

        let decoded_some: Option<u32> = Rlp::decode(&some_bytes).unwrap();
        let decoded_none: Option<u32> = Rlp::decode(&none_bytes).unwrap();

        assert_eq!(decoded_some, Some(42));
        assert_eq!(decoded_none, None);
    }

    #[test]
    fn varint_encoding() {
        // Postcard uses varint encoding for integers
        let small: u64 = 127;
        let large: u64 = 10_000_000_000;

        let small_bytes = Rlp::encode(&small).unwrap();
        let large_bytes = Rlp::encode(&large).unwrap();

        // Small values should use fewer bytes (varint property)
        assert!(small_bytes.len() < large_bytes.len());
    }

    #[test]
    fn empty_collections() {
        let empty_vec: Vec<u8> = vec![];
        let empty_map: BTreeMap<String, u64> = BTreeMap::new();

        let vec_bytes = Rlp::encode(&empty_vec).unwrap();
        let map_bytes = Rlp::encode(&empty_map).unwrap();

        assert!(!vec_bytes.is_empty()); // Still has length prefix
        assert!(!map_bytes.is_empty());

        let decoded_vec: Vec<u8> = Rlp::decode(&vec_bytes).unwrap();
        let decoded_map: BTreeMap<String, u64> = Rlp::decode(&map_bytes).unwrap();

        assert!(decoded_vec.is_empty());
        assert!(decoded_map.is_empty());
    }

    #[test]
    fn encode_and_hash_consistency() {
        let value = TestStruct {
            a: 777,
            b: "test".to_string(),
            c: vec![1, 2, 3],
        };

        let (bytes, hash1) = Rlp::encode_and_hash(&value).unwrap();
        let hash2 = Rlp::hash(&value).unwrap();
        let hash3 = Hash::sha256(&bytes);

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn invalid_bytes_fail_decode() {
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result: Result<TestStruct> = Rlp::decode(&garbage);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod consensus_type_tests {
    use super::*;
    use workstream_core::hash::H256;
    use workstream_core::types::*;

    #[test]
    fn nonce_roundtrip() {
        let nonce = Nonce { key_id: 1, seq: 42 };

        let bytes = Rlp::encode(&nonce).unwrap();
        let decoded: Nonce = Rlp::decode(&bytes).unwrap();

        assert_eq!(nonce.key_id, decoded.key_id);
        assert_eq!(nonce.seq, decoded.seq);
    }

    #[test]
    fn nonce_determinism() {
        let nonce = Nonce {
            key_id: 5,
            seq: 100,
        };

        let h1 = Rlp::hash(&nonce).unwrap();
        let h2 = Rlp::hash(&nonce).unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn fee_spec_roundtrip() {
        let fee = FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 1,
            max_fee: 1000,
        };

        let bytes = Rlp::encode(&fee).unwrap();
        let decoded: FeeSpec = Rlp::decode(&bytes).unwrap();

        assert_eq!(fee.asset_id, decoded.asset_id);
        assert_eq!(fee.max_fee, decoded.max_fee);
    }

    #[test]
    fn action_type_roundtrip() {
        // Test a selection of action types
        let action_types = [
            ActionType::ActorRegister,
            ActionType::ProjectCreate,
            ActionType::PolicyCompile,
        ];

        for at in action_types {
            let bytes = Rlp::encode(&at).unwrap();
            let decoded: ActionType = Rlp::decode(&bytes).unwrap();
            assert_eq!(
                std::mem::discriminant(&at),
                std::mem::discriminant(&decoded)
            );
        }
    }

    #[test]
    fn state_root_roundtrip() {
        let root = StateRoot::new(H256::from_bytes([1u8; 32]), H256::from_bytes([2u8; 32]));

        let bytes = Rlp::encode(&root).unwrap();
        let decoded: StateRoot = Rlp::decode(&bytes).unwrap();

        assert_eq!(root.smt_root, decoded.smt_root);
        assert_eq!(root.mmr_root, decoded.mmr_root);
    }

    #[test]
    fn state_root_determinism() {
        let root = StateRoot::new(H256::from_bytes([10u8; 32]), H256::from_bytes([20u8; 32]));

        let h1 = Rlp::hash(&root).unwrap();
        let h2 = Rlp::hash(&root).unwrap();

        assert_eq!(h1, h2, "StateRoot hash must be deterministic");
    }

    #[test]
    fn block_header_roundtrip() {
        let header = BlockHeader {
            number: 100,
            parent_hash: H256::from_bytes([1u8; 32]),
            timestamp: 1234567890,
            tx_root: H256::from_bytes([4u8; 32]),
            state_root: StateRoot::new(H256::from_bytes([2u8; 32]), H256::from_bytes([3u8; 32])),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::ZERO,
            proof_system_version: 1,
            proof: None,
        };

        let bytes = Rlp::encode(&header).unwrap();
        let decoded: BlockHeader = Rlp::decode(&bytes).unwrap();

        assert_eq!(header.number, decoded.number);
        assert_eq!(header.parent_hash, decoded.parent_hash);
        assert_eq!(header.timestamp, decoded.timestamp);
    }

    #[test]
    fn different_headers_different_hashes() {
        let header1 = BlockHeader {
            number: 1,
            parent_hash: H256::ZERO,
            timestamp: 0,
            tx_root: H256::ZERO,
            state_root: StateRoot::new(H256::ZERO, H256::ZERO),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::ZERO,
            proof_system_version: 1,
            proof: None,
        };

        let header2 = BlockHeader {
            number: 2,
            ..header1.clone()
        };

        let h1 = Rlp::hash(&header1).unwrap();
        let h2 = Rlp::hash(&header2).unwrap();

        assert_ne!(h1, h2, "different blocks must have different hashes");
    }
}
