//! Merkle structures for WorkStream state.
//!
//! This module provides the high-level state structures used by workstream-state:
//! - `SparseMerkleTree`: Authenticated key-value store backed by a real compressed SMT
//! - `MerkleMountainRange`: Append-only record log (placeholder, real impl in #36)
//!
//! The SMT implementation follows `docs/design/smt-mmr.md`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use workstream_core::hash::H256;
use workstream_core::Result;

use crate::smt::{hash_key, hash_value, MemoryNodeStore, NodeStore, SmTree, SmtNode, TREE_DEPTH};

/// Sparse Merkle Tree for mutable lifecycle objects.
///
/// Wraps the core `SmTree` and provides value storage. The tree commits to
/// value hashes; actual values are stored in a separate map for retrieval.
/// This separation enables efficient proofs (small witnesses) while
/// supporting full value retrieval for application logic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SparseMerkleTree {
    /// The underlying SMT storing key → value_hash mappings.
    tree: SmTree<MemoryNodeStore>,
    /// Value storage: value_hash → value bytes.
    values: HashMap<H256, Vec<u8>>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        SparseMerkleTree {
            tree: SmTree::new(),
            values: HashMap::new(),
        }
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> H256 {
        self.tree.root()
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Insert or update a key-value pair.
    ///
    /// The key is hashed to the 256-bit key space. The value is stored
    /// separately and its hash is committed to the tree.
    ///
    /// Returns a typed fail-closed error if the tree cannot be updated within
    /// its fixed depth (SEC-005).
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let key_hash = hash_key(key);
        let value_hash = hash_value(value);

        // Update the tree first; on error the tree is left un-mutated, so a
        // failed update cannot leave a half-applied state behind.
        self.tree.update(&key_hash, value_hash)?;

        // Store the value
        self.values.insert(value_hash, value.to_vec());

        Ok(())
    }

    /// Retrieve a value by key.
    ///
    /// Returns `None` if the key doesn't exist.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_hash = hash_key(key);

        match self.tree.get(&key_hash) {
            Some(value_hash) => Ok(self.values.get(&value_hash).cloned()),
            None => Ok(None),
        }
    }

    /// Insert or update using an already-hashed key (the tree's internal key
    /// identity), for durable-state reconstruction from a snapshot.
    pub fn update_hashed(&mut self, key: &H256, value: &[u8]) -> Result<()> {
        let value_hash = hash_value(value);
        self.tree.update(key, value_hash)?;
        self.values.insert(value_hash, value.to_vec());
        Ok(())
    }

    /// Delete a key from the tree.
    ///
    /// Note: The value remains in storage (for historical access / proofs).
    /// A future GC pass can reclaim unreferenced values.
    pub fn delete(&mut self, key: &[u8]) -> Result<bool> {
        let key_hash = hash_key(key);
        let existed = self.tree.get(&key_hash).is_some();
        if existed {
            self.tree.delete(&key_hash);
        }
        Ok(existed)
    }

    /// Access the underlying tree (for proof generation in #35).
    pub fn tree(&self) -> &SmTree<MemoryNodeStore> {
        &self.tree
    }

    /// All live key → value entries currently committed in the tree, keyed
    /// by the tree's internal (content-hashed) key identity.
    ///
    /// Walks the fixed-depth (256-bit) compressed tree from the root so the
    /// snapshot captures exactly the live state; deleted keys are excluded.
    /// The walk mirrors the tree's internal lookup direction (MSB-first bit
    /// indexing).
    pub fn entries(&self) -> Vec<(H256, Vec<u8>)> {
        let mut out = Vec::new();
        if self.tree.is_empty() {
            return out;
        }
        let root = self.tree.root();
        self.walk(root, 0, [0u8; 32], &mut out);
        out
    }

    /// Depth-first traversal of the compressed tree collecting live leaves.
    ///
    /// `key` accumulates the path bits (MSB-first) down to the leaf, which
    /// reconstructs the full key at depth == tree depth.
    fn walk(&self, node_hash: H256, depth: usize, key: [u8; 32], out: &mut Vec<(H256, Vec<u8>)>) {
        let Some(node) = self.tree.store().get(&node_hash) else {
            // Absent subtree: nothing live below this node.
            return;
        };
        match node {
            SmtNode::Leaf { key, value_hash } => {
                out.push((
                    key,
                    self.values.get(&value_hash).cloned().unwrap_or_default(),
                ));
            }
            SmtNode::Inner { left, right } => {
                if depth >= TREE_DEPTH {
                    return; // Should not happen with a valid tree
                }
                let byte_idx = depth / 8;
                let bit_idx = 7 - (depth % 8);
                let mut key_right = key;
                key_right[byte_idx] |= 1 << bit_idx;
                self.walk(left, depth + 1, key, out);
                self.walk(right, depth + 1, key_right, out);
            }
        }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Merkle Mountain Range for append-only immutable records.
///
/// Wraps the core `MmrTree` to provide the API expected by workstream-state.
/// The underlying implementation uses proper peaks and size-bound root hashing
/// per `docs/design/smt-mmr.md`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleMountainRange {
    tree: crate::mmr::MmrTree,
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        MerkleMountainRange {
            tree: crate::mmr::MmrTree::new(),
        }
    }

    /// Get the current root.
    pub fn root(&self) -> H256 {
        self.tree.root()
    }

    /// Number of records in the log.
    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    /// Check if the MMR is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Append a record and return its index.
    pub fn append(&mut self, record: &[u8]) -> Result<u64> {
        Ok(self.tree.append(record))
    }

    /// Generate a proof for the record at the given index.
    pub fn prove(&self, index: u64) -> Result<crate::mmr::MmrProof> {
        self.tree.prove(index)
    }

    /// All appended leaves as `(leaf index, payload hash)`, in append order.
    ///
    /// This is the complete durability surface for the append-only log: the
    /// sequence of payload hashes, keyed by absolute leaf index, is exactly
    /// what a snapshot must round-trip to reproduce the same MMR root.
    pub fn entries(&self) -> Vec<(u64, H256)> {
        self.tree.entries()
    }

    /// Rebuild an MMR from `(leaf index, payload hash)` entries.
    ///
    /// Entries must be supplied in ascending leaf order starting at index 0;
    /// the deterministic merge sequence is then reproduced exactly.
    pub fn from_entries(entries: &[(u64, H256)]) -> Self {
        MerkleMountainRange {
            tree: crate::mmr::MmrTree::from_entries(entries),
        }
    }

    /// Access the underlying tree (for advanced operations).
    pub fn tree(&self) -> &crate::mmr::MmrTree {
        &self.tree
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
        let tree1 = SparseMerkleTree::new();
        let tree2 = SparseMerkleTree::new();
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn smt_insert_and_retrieve() {
        let mut tree = SparseMerkleTree::new();
        let key = b"test-key";
        let value = b"test-value";

        assert_eq!(tree.get(key).unwrap(), None);

        tree.update(key, value).unwrap();
        assert_eq!(tree.get(key).unwrap(), Some(value.to_vec()));
    }

    #[test]
    fn smt_update_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();

        tree.update(b"key", b"value").unwrap();
        assert_ne!(tree.root(), empty_root);
    }

    #[test]
    fn smt_update_overwrites() {
        let mut tree = SparseMerkleTree::new();
        let key = b"key";

        tree.update(key, b"value1").unwrap();
        assert_eq!(tree.get(key).unwrap(), Some(b"value1".to_vec()));

        tree.update(key, b"value2").unwrap();
        assert_eq!(tree.get(key).unwrap(), Some(b"value2".to_vec()));
    }

    #[test]
    fn smt_multiple_keys() {
        let mut tree = SparseMerkleTree::new();

        for i in 0..10 {
            let key = format!("key-{}", i);
            let value = format!("value-{}", i);
            tree.update(key.as_bytes(), value.as_bytes()).unwrap();
        }

        for i in 0..10 {
            let key = format!("key-{}", i);
            let value = format!("value-{}", i);
            assert_eq!(
                tree.get(key.as_bytes()).unwrap(),
                Some(value.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn smt_root_independent_of_insert_order() {
        let mut tree_a = SparseMerkleTree::new();
        tree_a.update(b"a", b"1").unwrap();
        tree_a.update(b"b", b"2").unwrap();

        let mut tree_b = SparseMerkleTree::new();
        tree_b.update(b"b", b"2").unwrap();
        tree_b.update(b"a", b"1").unwrap();

        assert_eq!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn smt_delete() {
        let mut tree = SparseMerkleTree::new();
        tree.update(b"key", b"value").unwrap();
        assert!(tree.get(b"key").unwrap().is_some());

        tree.delete(b"key").unwrap();
        assert!(tree.get(b"key").unwrap().is_none());
    }

    #[test]
    fn mmr_empty_root_is_deterministic() {
        let mmr1 = MerkleMountainRange::new();
        let mmr2 = MerkleMountainRange::new();
        assert_eq!(mmr1.root(), mmr2.root());
    }

    #[test]
    fn mmr_append_returns_indices() {
        let mut mmr = MerkleMountainRange::new();
        assert_eq!(mmr.size(), 0);

        assert_eq!(mmr.append(b"record-0").unwrap(), 0);
        assert_eq!(mmr.append(b"record-1").unwrap(), 1);
        assert_eq!(mmr.append(b"record-2").unwrap(), 2);
        assert_eq!(mmr.size(), 3);
    }

    #[test]
    fn mmr_root_changes_on_append() {
        let mut mmr = MerkleMountainRange::new();
        let empty_root = mmr.root();

        mmr.append(b"record").unwrap();
        assert_ne!(mmr.root(), empty_root);
    }

    #[test]
    fn mmr_deterministic_replay() {
        let mut mmr1 = MerkleMountainRange::new();
        let mut mmr2 = MerkleMountainRange::new();

        for i in 0..5 {
            let record = format!("record-{}", i);
            mmr1.append(record.as_bytes()).unwrap();
            mmr2.append(record.as_bytes()).unwrap();
        }

        assert_eq!(mmr1.root(), mmr2.root());
    }
}
