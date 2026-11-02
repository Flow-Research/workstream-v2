//! Merkle structures for WorkStream state.
//!
//! Placeholder-but-functional versions pending the real SMT (#34/#35) and
//! MMR (#36) per `docs/design/smt-mmr.md`. These provide honest semantic
//! behavior — real key-value storage below a canonical commitment root, and
//! append-only records — so the STF (#15), sequencer (#16), and node (#32)
//! can be built and tested. Internals will be replaced; the public API stays.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use workstream_core::hash::{Hash, H256};
use workstream_core::Result;

/// Deterministic commitment over an empty entry set.
const SMT_EMPTY: &[u8] = b"WS:v1:KVS:EMPTY";
/// Domain tag for the KV-set root.
const SMT_ROOT_TAG: &[u8] = b"WS:v1:KVS";
/// Deterministic commitment over an empty record log.
const MMR_EMPTY: &[u8] = b"WSMMR:v1:EMPTY";
/// Domain tag for the size-bound record-log root.
const MMR_ROOT_TAG: &[u8] = b"WSMMR:v1:PEAKS";

/// Root over a sorted key-value set: H(tag ‖ le_count ‖ Σ (key ‖ H(value))).
fn kv_root(entries: &BTreeMap<H256, Vec<u8>>) -> H256 {
    if entries.is_empty() {
        return Hash::sha256(SMT_EMPTY);
    }
    let mut data: Vec<u8> = Vec::with_capacity(8 + entries.len() * 64);
    data.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (k, v) in entries.iter() {
        data.extend_from_slice(k.as_bytes());
        data.extend_from_slice(Hash::sha256(v).as_bytes());
    }
    Hash::sha256_concat(&[SMT_ROOT_TAG, &data])
}

/// Size-bound root over an append-only list of leaf hashes:
/// H(tag ‖ le_count ‖ Σ leaf_hash).
fn record_root(leaves: &[H256]) -> H256 {
    if leaves.is_empty() {
        return Hash::sha256(MMR_EMPTY);
    }
    let mut data: Vec<u8> = Vec::with_capacity(8 + leaves.len() * 32);
    data.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    for leaf in leaves {
        data.extend_from_slice(leaf.as_bytes());
    }
    Hash::sha256_concat(&[MMR_ROOT_TAG, &data])
}

/// Sparse Merkle Tree for mutable lifecycle objects.
///
/// MVP implementation: flat key-value store with a deterministic canonical
/// root over the sorted entry set (BTreeMap keeps iteration order stable, so
/// the same entry set always produces the same root). The real compressed
/// SMT (#34) replaces the internals behind this unchanged API.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SparseMerkleTree {
    entries: BTreeMap<H256, Vec<u8>>,
    root: H256,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        SparseMerkleTree {
            entries: BTreeMap::new(),
            root: kv_root(&BTreeMap::new()),
        }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or overwrite the value stored under `key`.
    /// The full key material is hashed to the key space internally.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let key_hash = Hash::sha256(key);
        self.entries.insert(key_hash, value.to_vec());
        self.root = kv_root(&self.entries);
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_hash = Hash::sha256(key);
        Ok(self.entries.get(&key_hash).cloned())
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Merkle Mountain Range for append-only immutable records.
///
/// MVP implementation: holds the leaf hash list; the root is a
/// deterministic, size-bound commitment over all leaves (the same shape the
/// final MMR (#36) bag). Only appends exist; records never change.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleMountainRange {
    leaf_hashes: Vec<H256>,
    root: H256,
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        MerkleMountainRange {
            leaf_hashes: Vec::new(),
            root: record_root(&[]),
        }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    /// Append a record and return its zero-based index.
    pub fn append(&mut self, leaf: &[u8]) -> Result<u64> {
        let index = self.leaf_hashes.len() as u64;
        self.leaf_hashes.push(Hash::sha256(leaf));
        self.root = record_root(&self.leaf_hashes);
        Ok(index)
    }

    pub fn size(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smt_empty_root_is_deterministic() {
        assert_eq!(
            SparseMerkleTree::new().root(),
            SparseMerkleTree::new().root()
        );
        // Distinct from any populated tree.
        let mut tree = SparseMerkleTree::new();
        tree.update(b"k", b"v").unwrap();
        assert_ne!(tree.root(), SparseMerkleTree::new().root());
    }

    #[test]
    fn smt_get_set_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        assert_eq!(tree.get(b"missing").unwrap(), None);

        tree.update(b"key-1", b"value-1").unwrap();
        assert_eq!(tree.get(b"key-1").unwrap(), Some(b"value-1".to_vec()));

        // Overwrite
        tree.update(b"key-1", b"value-2").unwrap();
        assert_eq!(tree.get(b"key-1").unwrap(), Some(b"value-2".to_vec()));
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn smt_root_depends_on_content_and_keys() {
        let mut a = SparseMerkleTree::new();
        a.update(b"k", b"v1").unwrap();
        let mut b = SparseMerkleTree::new();
        b.update(b"k", b"v2").unwrap();
        assert_ne!(a.root(), b.root());

        let mut c = SparseMerkleTree::new();
        c.update(b"k2", b"v1").unwrap();
        assert_ne!(a.root(), c.root());

        // Reinsertion of the same content in a fresh tree reproduces the root.
        let mut d = SparseMerkleTree::new();
        d.update(b"k", b"v1").unwrap();
        assert_eq!(a.root(), d.root());

        // Insertion order does not matter for the root commitment.
        let mut e = SparseMerkleTree::new();
        e.update(b"a", b"1").unwrap();
        e.update(b"b", b"2").unwrap();
        let mut f = SparseMerkleTree::new();
        f.update(b"b", b"2").unwrap();
        f.update(b"a", b"1").unwrap();
        assert_eq!(e.root(), f.root());
    }

    #[test]
    fn mmr_append_assigns_indices_and_size_bounds_root() {
        let mut mmr = MerkleMountainRange::new();
        assert_eq!(mmr.size(), 0);

        let i0 = mmr.append(b"record-0").unwrap();
        let i1 = mmr.append(b"record-1").unwrap();
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
        assert_eq!(mmr.size(), 2);

        // Root changes with each append and depends on content.
        let root_2 = mmr.root();
        let i2 = mmr.append(b"record-2").unwrap();
        assert_eq!(i2, 2);
        assert_ne!(mmr.root(), root_2);

        // An identical MMR construction reproduces the root.
        let mut mmr2 = MerkleMountainRange::new();
        mmr2.append(b"record-0").unwrap();
        mmr2.append(b"record-1").unwrap();
        mmr2.append(b"record-2").unwrap();
        assert_eq!(mmr2.root(), mmr.root());
    }

    #[test]
    fn mmr_empty_root_is_deterministic() {
        assert_eq!(
            MerkleMountainRange::new().root(),
            MerkleMountainRange::new().root()
        );
    }
}
