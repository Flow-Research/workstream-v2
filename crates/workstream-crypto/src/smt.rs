//! Sparse Merkle Tree implementation for WorkStream (issue #34).
//!
//! A fixed-depth (256-bit) compressed sparse Merkle tree following the design
//! in `docs/design/smt-mmr.md`. Key properties:
//!
//! - **Compressed**: Empty subtrees are represented by a constant hash, not
//!   materialized nodes. This keeps proof sizes logarithmic in the number of
//!   occupied keys rather than the tree depth.
//!
//! - **Content-addressed storage**: Nodes are keyed by their hash, enabling
//!   historical root access and efficient deduplication.
//!
//! - **Domain-separated hashing**: Leaf and inner node preimages use distinct
//!   tags to prevent second-preimage attacks across node types.
//!
//! - **Deterministic**: All operations produce identical results given
//!   identical inputs, suitable for zkVM execution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use workstream_core::hash::{Hash, H256};
// Note: Error and Result reserved for proof operations in #35

// Domain tags per the design doc
const TAG_EMPTY: &[u8] = b"WSMT:v1:EMPTY";
const TAG_LEAF: &[u8] = b"WSMT:v1:L";
const TAG_INNER: &[u8] = b"WSMT:v1:N";
const TAG_KEY: &[u8] = b"WSMT:v1:K";

/// Tree depth (256 bits for H256 keys).
const TREE_DEPTH: usize = 256;

/// Hash of an empty subtree (computed once, reused everywhere).
fn empty_hash() -> H256 {
    Hash::sha256(TAG_EMPTY)
}

/// A node in the sparse Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmtNode {
    /// Leaf node containing a key-value pair.
    Leaf {
        /// The full 256-bit key.
        key: H256,
        /// Hash of the stored value.
        value_hash: H256,
    },
    /// Inner node with left and right child hashes.
    Inner {
        /// Hash of the left child (or EMPTY if absent).
        left: H256,
        /// Hash of the right child (or EMPTY if absent).
        right: H256,
    },
}

impl SmtNode {
    /// Compute the hash of this node using domain-separated hashing.
    pub fn hash(&self) -> H256 {
        match self {
            SmtNode::Leaf { key, value_hash } => {
                Hash::sha256_concat(&[TAG_LEAF, key.as_bytes(), value_hash.as_bytes()])
            }
            SmtNode::Inner { left, right } => {
                Hash::sha256_concat(&[TAG_INNER, left.as_bytes(), right.as_bytes()])
            }
        }
    }
}

/// Get the bit at position `depth` in a 256-bit key (0 = MSB).
#[inline]
fn get_bit(key: &H256, depth: usize) -> bool {
    debug_assert!(depth < 256);
    let byte_idx = depth / 8;
    let bit_idx = 7 - (depth % 8); // MSB first
    (key.as_bytes()[byte_idx] >> bit_idx) & 1 == 1
}

/// Find the first bit position where two keys differ.
fn first_differing_bit(a: &H256, b: &H256) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    for i in 0..32 {
        if a_bytes[i] != b_bytes[i] {
            let xor = a_bytes[i] ^ b_bytes[i];
            // leading_zeros gives position from MSB, which is what we want
            return i * 8 + xor.leading_zeros() as usize;
        }
    }
    256 // Keys are identical
}

/// Content-addressed node storage.
pub trait NodeStore {
    /// Retrieve a node by its hash.
    fn get(&self, hash: &H256) -> Option<SmtNode>;

    /// Store a node and return its hash.
    fn put(&mut self, node: SmtNode) -> H256;
}

/// In-memory node store backed by a HashMap.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryNodeStore {
    nodes: HashMap<H256, SmtNode>,
}

impl MemoryNodeStore {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl NodeStore for MemoryNodeStore {
    fn get(&self, hash: &H256) -> Option<SmtNode> {
        self.nodes.get(hash).cloned()
    }

    fn put(&mut self, node: SmtNode) -> H256 {
        let hash = node.hash();
        self.nodes.insert(hash, node);
        hash
    }
}

/// Sparse Merkle Tree with configurable node storage.
///
/// The tree uses 256-bit keys (H256) and stores value hashes in leaves.
/// Empty subtrees are represented by a constant hash, not stored nodes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmTree<S = MemoryNodeStore> {
    store: S,
    /// Root hash, or None if the tree is empty.
    root: Option<H256>,
    /// Cached empty hash for efficiency.
    #[serde(skip, default = "empty_hash")]
    empty: H256,
}

impl<S: NodeStore + Default> Default for SmTree<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: NodeStore + Default> SmTree<S> {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self::with_store(S::default())
    }
}

impl<S: NodeStore> SmTree<S> {
    /// Create a tree with a custom store.
    pub fn with_store(store: S) -> Self {
        SmTree {
            store,
            root: None,
            empty: empty_hash(),
        }
    }

    /// Get the current root hash.
    ///
    /// Returns the empty hash if the tree contains no entries.
    pub fn root(&self) -> H256 {
        self.root.unwrap_or(self.empty)
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Get the value hash for a key, if it exists.
    pub fn get(&self, key: &H256) -> Option<H256> {
        let root = self.root?;
        self.get_at(root, key, 0)
    }

    /// Recursive get traversing the tree.
    fn get_at(&self, node_hash: H256, key: &H256, depth: usize) -> Option<H256> {
        if node_hash == self.empty {
            return None;
        }

        let node = self.store.get(&node_hash)?;
        match node {
            SmtNode::Leaf {
                key: leaf_key,
                value_hash,
            } => {
                if &leaf_key == key {
                    Some(value_hash)
                } else {
                    None
                }
            }
            SmtNode::Inner { left, right } => {
                if depth >= TREE_DEPTH {
                    return None; // Should not happen with valid tree
                }
                if get_bit(key, depth) {
                    self.get_at(right, key, depth + 1)
                } else {
                    self.get_at(left, key, depth + 1)
                }
            }
        }
    }

    /// Insert or update a key-value pair.
    ///
    /// Returns the new root hash.
    pub fn update(&mut self, key: &H256, value_hash: H256) -> H256
    where
        S: NodeStore,
    {
        let new_root = match self.root {
            None => {
                // First insert: create a leaf
                let leaf = SmtNode::Leaf {
                    key: *key,
                    value_hash,
                };
                self.store.put(leaf)
            }
            Some(root) => self.update_at(root, key, value_hash, 0),
        };
        self.root = Some(new_root);
        new_root
    }

    /// Recursive update traversing the tree.
    fn update_at(&mut self, node_hash: H256, key: &H256, value_hash: H256, depth: usize) -> H256
    where
        S: NodeStore,
    {
        if node_hash == self.empty {
            // Empty subtree: insert a leaf
            let leaf = SmtNode::Leaf {
                key: *key,
                value_hash,
            };
            return self.store.put(leaf);
        }

        let node = self.store.get(&node_hash).expect("node must exist");
        match node {
            SmtNode::Leaf {
                key: leaf_key,
                value_hash: _,
            } => {
                if leaf_key == *key {
                    // Update existing leaf
                    let new_leaf = SmtNode::Leaf {
                        key: *key,
                        value_hash,
                    };
                    self.store.put(new_leaf)
                } else {
                    // Collision: split into inner nodes until keys diverge
                    self.split_leaf(leaf_key, node_hash, key, value_hash, depth)
                }
            }
            SmtNode::Inner { left, right } => {
                if depth >= TREE_DEPTH {
                    panic!("exceeded tree depth");
                }
                let (new_left, new_right) = if get_bit(key, depth) {
                    let new_right = self.update_at(right, key, value_hash, depth + 1);
                    (left, new_right)
                } else {
                    let new_left = self.update_at(left, key, value_hash, depth + 1);
                    (new_left, right)
                };
                let inner = SmtNode::Inner {
                    left: new_left,
                    right: new_right,
                };
                self.store.put(inner)
            }
        }
    }

    /// Split a leaf node when a new key collides with an existing one.
    fn split_leaf(
        &mut self,
        existing_key: H256,
        existing_hash: H256,
        new_key: &H256,
        new_value_hash: H256,
        depth: usize,
    ) -> H256
    where
        S: NodeStore,
    {
        // Find where the keys diverge
        let diverge_at = first_differing_bit(&existing_key, new_key);
        debug_assert!(
            diverge_at >= depth,
            "diverge point must be at or after current depth"
        );

        // Create inner nodes down to the divergence point
        let new_leaf = SmtNode::Leaf {
            key: *new_key,
            value_hash: new_value_hash,
        };
        let new_leaf_hash = self.store.put(new_leaf);

        // Build up from the divergence point
        let (left, right) = if get_bit(new_key, diverge_at) {
            (existing_hash, new_leaf_hash)
        } else {
            (new_leaf_hash, existing_hash)
        };

        let mut current = self.store.put(SmtNode::Inner { left, right });

        // Build inner nodes from diverge_at back up to depth
        for d in (depth..diverge_at).rev() {
            let (left, right) = if get_bit(&existing_key, d) {
                (self.empty, current)
            } else {
                (current, self.empty)
            };
            current = self.store.put(SmtNode::Inner { left, right });
        }

        current
    }

    /// Delete a key from the tree.
    ///
    /// Returns the new root hash, or None if the tree is now empty.
    pub fn delete(&mut self, key: &H256) -> Option<H256>
    where
        S: NodeStore,
    {
        let root = self.root?;
        let (new_root, _) = self.delete_at(root, key, 0);
        self.root = if new_root == self.empty {
            None
        } else {
            Some(new_root)
        };
        self.root
    }

    /// Recursive delete returning (new_subtree_hash, was_deleted).
    fn delete_at(&mut self, node_hash: H256, key: &H256, depth: usize) -> (H256, bool)
    where
        S: NodeStore,
    {
        if node_hash == self.empty {
            return (self.empty, false);
        }

        let node = self.store.get(&node_hash).expect("node must exist");
        match node {
            SmtNode::Leaf {
                key: leaf_key,
                value_hash: _,
            } => {
                if leaf_key == *key {
                    (self.empty, true)
                } else {
                    (node_hash, false)
                }
            }
            SmtNode::Inner { left, right } => {
                if depth >= TREE_DEPTH {
                    return (node_hash, false);
                }

                let (new_left, new_right, deleted) = if get_bit(key, depth) {
                    let (new_right, deleted) = self.delete_at(right, key, depth + 1);
                    (left, new_right, deleted)
                } else {
                    let (new_left, deleted) = self.delete_at(left, key, depth + 1);
                    (new_left, right, deleted)
                };

                if !deleted {
                    return (node_hash, false);
                }

                // Contract: if one child is empty and the other is a leaf, promote the leaf
                self.maybe_contract(new_left, new_right)
            }
        }
    }

    /// Contract an inner node if possible (one child empty, other is leaf).
    fn maybe_contract(&mut self, left: H256, right: H256) -> (H256, bool)
    where
        S: NodeStore,
    {
        let left_empty = left == self.empty;
        let right_empty = right == self.empty;

        if left_empty && right_empty {
            return (self.empty, true);
        }

        // Check if we can contract (promote a lone leaf)
        let lone_child = if left_empty {
            Some(right)
        } else if right_empty {
            Some(left)
        } else {
            None
        };

        if let Some(child_hash) = lone_child {
            if let Some(SmtNode::Leaf { .. }) = self.store.get(&child_hash) {
                // Promote the leaf directly
                return (child_hash, true);
            }
        }

        // Can't contract; create new inner node
        let inner = SmtNode::Inner { left, right };
        (self.store.put(inner), true)
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// Hash a raw key to the 256-bit key space.
///
/// This ensures arbitrary-length keys are uniformly distributed.
pub fn hash_key(raw_key: &[u8]) -> H256 {
    Hash::sha256_concat(&[TAG_KEY, raw_key])
}

/// Hash a value to produce the value_hash stored in leaves.
pub fn hash_value(value: &[u8]) -> H256 {
    Hash::sha256(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_deterministic_root() {
        let tree1: SmTree = SmTree::new();
        let tree2: SmTree = SmTree::new();
        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.root(), empty_hash());
    }

    #[test]
    fn single_insert_changes_root() {
        let mut tree: SmTree = SmTree::new();
        let empty_root = tree.root();

        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);
        tree.update(&key, value_hash);

        assert_ne!(tree.root(), empty_root);
        assert!(!tree.is_empty());
    }

    #[test]
    fn get_returns_inserted_value() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);

        assert_eq!(tree.get(&key), None);
        tree.update(&key, value_hash);
        assert_eq!(tree.get(&key), Some(value_hash));
    }

    #[test]
    fn update_overwrites_value() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let v1 = H256::from_bytes([2u8; 32]);
        let v2 = H256::from_bytes([3u8; 32]);

        tree.update(&key, v1);
        assert_eq!(tree.get(&key), Some(v1));

        tree.update(&key, v2);
        assert_eq!(tree.get(&key), Some(v2));
    }

    #[test]
    fn multiple_inserts_all_retrievable() {
        let mut tree: SmTree = SmTree::new();
        let entries: Vec<(H256, H256)> = (0..10)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = i;
                let mut val = [0u8; 32];
                val[0] = i + 100;
                (H256::from_bytes(key), H256::from_bytes(val))
            })
            .collect();

        for (k, v) in &entries {
            tree.update(k, *v);
        }

        for (k, v) in &entries {
            assert_eq!(tree.get(k), Some(*v), "key {:?} not found", k);
        }
    }

    #[test]
    fn delete_removes_key() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);

        tree.update(&key, value_hash);
        assert_eq!(tree.get(&key), Some(value_hash));

        tree.delete(&key);
        assert_eq!(tree.get(&key), None);
    }

    #[test]
    fn delete_last_key_returns_empty_root() {
        let mut tree: SmTree = SmTree::new();
        let empty_root = tree.root();

        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);
        tree.update(&key, value_hash);
        assert_ne!(tree.root(), empty_root);

        tree.delete(&key);
        assert_eq!(tree.root(), empty_root);
        assert!(tree.is_empty());
    }

    #[test]
    fn root_depends_on_content_not_order() {
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree_a: SmTree = SmTree::new();
        tree_a.update(&k1, v1);
        tree_a.update(&k2, v2);

        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k2, v2);
        tree_b.update(&k1, v1);

        assert_eq!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn different_keys_produce_different_roots() {
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v = H256::from_bytes([10u8; 32]);

        let mut tree_a: SmTree = SmTree::new();
        tree_a.update(&k1, v);

        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k2, v);

        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn different_values_produce_different_roots() {
        let k = H256::from_bytes([1u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree_a: SmTree = SmTree::new();
        tree_a.update(&k, v1);

        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k, v2);

        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn collision_handling() {
        // Two keys that share a long prefix
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1[31] = 0b00000001; // Differ only in last bit
        k2[31] = 0b00000000;

        let key1 = H256::from_bytes(k1);
        let key2 = H256::from_bytes(k2);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree: SmTree = SmTree::new();
        tree.update(&key1, v1);
        tree.update(&key2, v2);

        assert_eq!(tree.get(&key1), Some(v1));
        assert_eq!(tree.get(&key2), Some(v2));
    }

    #[test]
    fn hash_key_is_deterministic() {
        let raw = b"test-key";
        assert_eq!(hash_key(raw), hash_key(raw));

        let raw2 = b"other-key";
        assert_ne!(hash_key(raw), hash_key(raw2));
    }

    #[test]
    fn hash_value_is_deterministic() {
        let val = b"test-value";
        assert_eq!(hash_value(val), hash_value(val));
    }

    #[test]
    fn leaf_and_inner_hashes_differ() {
        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);

        let leaf = SmtNode::Leaf { key, value_hash };
        let inner = SmtNode::Inner {
            left: key,
            right: value_hash,
        };

        // Even with same bytes in different positions, hashes must differ
        // due to domain separation
        assert_ne!(leaf.hash(), inner.hash());
    }

    #[test]
    fn delete_with_contraction() {
        // Insert two keys, delete one, verify the other remains
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree: SmTree = SmTree::new();
        tree.update(&k1, v1);
        tree.update(&k2, v2);

        let root_before = tree.root();
        tree.delete(&k1);
        let root_after = tree.root();

        assert_ne!(root_before, root_after);
        assert_eq!(tree.get(&k1), None);
        assert_eq!(tree.get(&k2), Some(v2));
    }

    #[test]
    fn stress_test_many_operations() {
        let mut tree: SmTree = SmTree::new();
        let n = 100;

        // Insert n keys
        for i in 0..n {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let key = H256::from_bytes(key_bytes);

            let mut val_bytes = [0u8; 32];
            val_bytes[0..8].copy_from_slice(&((i + 1000) as u64).to_le_bytes());
            let val = H256::from_bytes(val_bytes);

            tree.update(&key, val);
        }

        // Verify all keys exist
        for i in 0..n {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let key = H256::from_bytes(key_bytes);
            assert!(tree.get(&key).is_some(), "key {} not found", i);
        }

        // Delete half
        for i in (0..n).step_by(2) {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let key = H256::from_bytes(key_bytes);
            tree.delete(&key);
        }

        // Verify correct keys remain
        for i in 0..n {
            let mut key_bytes = [0u8; 32];
            key_bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let key = H256::from_bytes(key_bytes);

            if i % 2 == 0 {
                assert_eq!(tree.get(&key), None, "deleted key {} still exists", i);
            } else {
                assert!(tree.get(&key).is_some(), "key {} should exist", i);
            }
        }
    }

    #[test]
    fn get_bit_correctness() {
        // MSB of first byte = bit 0
        let mut bytes = [0u8; 32];
        bytes[0] = 0b10000000;
        let key = H256::from_bytes(bytes);
        assert!(get_bit(&key, 0));
        assert!(!get_bit(&key, 1));

        // LSB of first byte = bit 7
        bytes[0] = 0b00000001;
        let key = H256::from_bytes(bytes);
        assert!(!get_bit(&key, 0));
        assert!(get_bit(&key, 7));

        // First bit of second byte = bit 8
        bytes[0] = 0;
        bytes[1] = 0b10000000;
        let key = H256::from_bytes(bytes);
        assert!(!get_bit(&key, 7));
        assert!(get_bit(&key, 8));
    }

    #[test]
    fn first_differing_bit_correctness() {
        let a = H256::from_bytes([0u8; 32]);
        let b = H256::from_bytes([0u8; 32]);
        assert_eq!(first_differing_bit(&a, &b), 256); // identical

        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 0b10000000; // MSB set
        let b = H256::from_bytes(b_bytes);
        assert_eq!(first_differing_bit(&a, &b), 0);

        b_bytes[0] = 0b00000001; // LSB of first byte set
        let b = H256::from_bytes(b_bytes);
        assert_eq!(first_differing_bit(&a, &b), 7);

        b_bytes[0] = 0;
        b_bytes[1] = 0b10000000; // MSB of second byte
        let b = H256::from_bytes(b_bytes);
        assert_eq!(first_differing_bit(&a, &b), 8);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_h256()(bytes in prop::array::uniform32(any::<u8>())) -> H256 {
            H256::from_bytes(bytes)
        }
    }

    proptest! {
        #[test]
        fn insert_then_get_returns_value(
            key in arb_h256(),
            value in arb_h256()
        ) {
            let mut tree: SmTree = SmTree::new();
            tree.update(&key, value);
            prop_assert_eq!(tree.get(&key), Some(value));
        }

        #[test]
        fn delete_then_get_returns_none(
            key in arb_h256(),
            value in arb_h256()
        ) {
            let mut tree: SmTree = SmTree::new();
            tree.update(&key, value);
            tree.delete(&key);
            prop_assert_eq!(tree.get(&key), None);
        }

        #[test]
        fn root_is_deterministic(
            pairs in prop::collection::vec((arb_h256(), arb_h256()), 0..20)
        ) {
            // Two trees with same inserts produce same root
            let mut tree_a: SmTree = SmTree::new();
            let mut tree_b: SmTree = SmTree::new();

            for (k, v) in &pairs {
                tree_a.update(k, *v);
                tree_b.update(k, *v);
            }

            prop_assert_eq!(tree_a.root(), tree_b.root());
        }

        #[test]
        fn root_independent_of_order(
            mut pairs in prop::collection::vec((arb_h256(), arb_h256()), 2..10)
        ) {
            // Insert in forward and reverse order
            let mut tree_fwd: SmTree = SmTree::new();
            for (k, v) in &pairs {
                tree_fwd.update(k, *v);
            }

            let mut tree_rev: SmTree = SmTree::new();
            pairs.reverse();
            for (k, v) in &pairs {
                tree_rev.update(k, *v);
            }

            prop_assert_eq!(tree_fwd.root(), tree_rev.root());
        }

        #[test]
        fn different_keys_different_roots(
            k1 in arb_h256(),
            k2 in arb_h256(),
            v in arb_h256()
        ) {
            prop_assume!(k1 != k2);

            let mut tree_a: SmTree = SmTree::new();
            tree_a.update(&k1, v);

            let mut tree_b: SmTree = SmTree::new();
            tree_b.update(&k2, v);

            prop_assert_ne!(tree_a.root(), tree_b.root());
        }

        #[test]
        fn different_values_different_roots(
            k in arb_h256(),
            v1 in arb_h256(),
            v2 in arb_h256()
        ) {
            prop_assume!(v1 != v2);

            let mut tree_a: SmTree = SmTree::new();
            tree_a.update(&k, v1);

            let mut tree_b: SmTree = SmTree::new();
            tree_b.update(&k, v2);

            prop_assert_ne!(tree_a.root(), tree_b.root());
        }
    }
}
