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
use workstream_core::{Error, Result};

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

// ============================================================================
// Proof Types (#35)
// ============================================================================

/// Type of SMT proof.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmtProofKind {
    /// Proves a key exists with a specific value.
    Inclusion,
    /// Proves a key does not exist in the tree.
    NonExistence,
}

/// SMT membership/non-membership proof.
///
/// The proof contains the sibling hashes along the path from the leaf (or
/// termination point) to the root. For inclusion proofs, verification
/// recomputes the root from the leaf. For non-existence proofs, verification
/// shows either an empty subtree or a different leaf at the query path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmtProof {
    /// Type of proof (inclusion or non-existence).
    pub kind: SmtProofKind,
    /// The key being proven.
    pub key: H256,
    /// For inclusion: the value hash. For non-existence: None or the
    /// conflicting leaf's value hash if path leads to a different leaf.
    pub value_hash: Option<H256>,
    /// For non-existence proofs ending at a different leaf: that leaf's key.
    pub leaf_key: Option<H256>,
    /// Sibling hashes from leaf/termination toward root (bottom-up).
    pub siblings: Vec<H256>,
    /// Direction bits: false = left, true = right (corresponding to siblings).
    /// Bit i indicates which side the sibling at position i is on.
    pub directions: Vec<bool>,
    /// Depth at which the proof terminates (for non-existence proofs that
    /// hit empty or a leaf early).
    pub depth: usize,
}

impl SmtProof {
    /// Verify this proof against a root hash.
    ///
    /// Returns `true` if the proof is valid for the given root.
    pub fn verify(&self, root: H256) -> bool {
        verify_smt_proof(root, self)
    }
}

/// Verify an SMT proof against a root hash.
///
/// This is a standalone function that doesn't require access to the tree.
/// It recomputes the root from the proof and compares.
pub fn verify_smt_proof(root: H256, proof: &SmtProof) -> bool {
    let empty = empty_hash();

    // Depth must not exceed the tree's fixed depth.
    if proof.depth > TREE_DEPTH {
        return false;
    }

    // Siblings and directions must have the same length.
    if proof.siblings.len() != proof.directions.len() {
        return false;
    }

    // The number of siblings/directions equals the number of inner nodes traversed,
    // which is exactly proof.depth (the depth at which the path terminates).
    if proof.siblings.len() != proof.depth {
        return false;
    }

    // Directions are stored bottom-up by collect_proof_path: index 0 is the deepest
    // inner node (depth = proof.depth - 1), and index len-1 is the root (depth = 0).
    // Validate each direction matches the key's bit at that depth.
    for (i, &went_right) in proof.directions.iter().enumerate() {
        let bit_depth = proof.depth - 1 - i;
        if went_right != get_bit(&proof.key, bit_depth) {
            return false;
        }
    }

    // Compute the hash at the termination point
    let mut current = match proof.kind {
        SmtProofKind::Inclusion => {
            // Must have a value hash for inclusion proofs.
            let value_hash = match proof.value_hash {
                Some(vh) => vh,
                None => return false,
            };
            SmtNode::Leaf {
                key: proof.key,
                value_hash,
            }
            .hash()
        }
        SmtProofKind::NonExistence => {
            match (proof.leaf_key, proof.value_hash) {
                // Path ends at empty subtree.
                (None, None) => empty,
                // Path ends at a different leaf: the conflicting key must share the
                // first proof.depth bits with the query key (the path prefix).
                (Some(leaf_key), Some(value_hash)) => {
                    if leaf_key == proof.key {
                        return false;
                    }
                    for i in 0..proof.depth {
                        if get_bit(&leaf_key, i) != get_bit(&proof.key, i) {
                            return false;
                        }
                    }
                    SmtNode::Leaf {
                        key: leaf_key,
                        value_hash,
                    }
                    .hash()
                }
                // Invalid combination.
                _ => return false,
            }
        }
    };

    // Walk up the tree using siblings (bottom-up order).
    for (sibling, &went_right) in proof.siblings.iter().zip(proof.directions.iter()) {
        // went_right indicates which direction we took at this level.
        // If we went right, we're on the right side; sibling is on left.
        let (left, right) = if went_right {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        current = SmtNode::Inner { left, right }.hash();
    }

    current == root
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
    /// Returns the new root hash, or a typed fail-closed error if the tree
    /// cannot be traversed within its fixed depth (SEC-005).
    pub fn update(&mut self, key: &H256, value_hash: H256) -> Result<H256>
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
                Ok(self.store.put(leaf))
            }
            Some(root) => self.update_at(root, key, value_hash, 0),
        }?;
        self.root = Some(new_root);
        Ok(new_root)
    }

    /// Recursive update traversing the tree.
    ///
    /// Returns a typed error instead of panicking on depth overflow so the
    /// consensus-critical path fails closed (SEC-005).
    fn update_at(
        &mut self,
        node_hash: H256,
        key: &H256,
        value_hash: H256,
        depth: usize,
    ) -> Result<H256>
    where
        S: NodeStore,
    {
        if node_hash == self.empty {
            // Empty subtree: insert a leaf
            let leaf = SmtNode::Leaf {
                key: *key,
                value_hash,
            };
            return Ok(self.store.put(leaf));
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
                    Ok(self.store.put(new_leaf))
                } else {
                    // Collision: split into inner nodes until keys diverge
                    self.split_leaf(leaf_key, node_hash, key, value_hash, depth)
                }
            }
            SmtNode::Inner { left, right } => {
                // Fixed-depth tree: a descent past the depth limit is a typed,
                // fail-closed error — never a panic in a consensus path (SEC-005).
                if depth >= TREE_DEPTH {
                    return Err(Error::DepthLimitExceeded);
                }
                let (new_left, new_right) = if get_bit(key, depth) {
                    let new_right = self.update_at(right, key, value_hash, depth + 1)?;
                    (left, new_right)
                } else {
                    let new_left = self.update_at(left, key, value_hash, depth + 1)?;
                    (new_left, right)
                };
                let inner = SmtNode::Inner {
                    left: new_left,
                    right: new_right,
                };
                Ok(self.store.put(inner))
            }
        }
    }

    /// Split a leaf node when a new key collides with an existing one.
    ///
    /// Returns the new subtree hash, or a typed error if the split cannot be
    /// performed within the tree's depth budget.
    fn split_leaf(
        &mut self,
        existing_key: H256,
        existing_hash: H256,
        new_key: &H256,
        new_value_hash: H256,
        depth: usize,
    ) -> Result<H256>
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

        Ok(current)
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

    /// Generate a proof for a key.
    ///
    /// Returns an inclusion proof if the key exists, or a non-existence proof
    /// if it doesn't. The proof can be verified against the current root.
    pub fn prove(&self, key: &H256) -> Result<SmtProof> {
        let root = match self.root {
            None => {
                // Empty tree: non-existence proof with no siblings
                return Ok(SmtProof {
                    kind: SmtProofKind::NonExistence,
                    key: *key,
                    value_hash: None,
                    leaf_key: None,
                    siblings: vec![],
                    directions: vec![],
                    depth: 0,
                });
            }
            Some(r) => r,
        };

        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let (kind, value_hash, leaf_key, depth) =
            self.collect_proof_path(root, key, 0, &mut siblings, &mut directions)?;

        Ok(SmtProof {
            kind,
            key: *key,
            value_hash,
            leaf_key,
            siblings,
            directions,
            depth,
        })
    }

    /// Recursively collect the proof path.
    fn collect_proof_path(
        &self,
        node_hash: H256,
        key: &H256,
        depth: usize,
        siblings: &mut Vec<H256>,
        directions: &mut Vec<bool>,
    ) -> Result<(SmtProofKind, Option<H256>, Option<H256>, usize)> {
        if node_hash == self.empty {
            // Hit empty subtree: non-existence
            return Ok((SmtProofKind::NonExistence, None, None, depth));
        }

        let node = self
            .store
            .get(&node_hash)
            .ok_or_else(|| Error::State(format!("missing node: {}", node_hash)))?;

        match node {
            SmtNode::Leaf {
                key: leaf_key,
                value_hash,
            } => {
                if leaf_key == *key {
                    // Found the key: inclusion proof
                    Ok((SmtProofKind::Inclusion, Some(value_hash), None, depth))
                } else {
                    // Different leaf at this position: non-existence
                    Ok((
                        SmtProofKind::NonExistence,
                        Some(value_hash),
                        Some(leaf_key),
                        depth,
                    ))
                }
            }
            SmtNode::Inner { left, right } => {
                if depth >= TREE_DEPTH {
                    return Err(Error::DepthLimitExceeded);
                }

                let go_right = get_bit(key, depth);
                let (child, sibling) = if go_right {
                    (right, left)
                } else {
                    (left, right)
                };

                // Recurse into the child
                let result =
                    self.collect_proof_path(child, key, depth + 1, siblings, directions)?;

                // Add sibling to proof (bottom-up, so we push after recursion)
                siblings.push(sibling);
                directions.push(go_right);

                Ok(result)
            }
        }
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
        tree.update(&key, value_hash).unwrap();
        assert_ne!(tree.root(), empty_root);
        assert!(!tree.is_empty());
    }

    #[test]
    fn get_returns_inserted_value() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value_hash = H256::from_bytes([2u8; 32]);

        assert_eq!(tree.get(&key), None);
        tree.update(&key, value_hash).unwrap();
        assert_eq!(tree.get(&key), Some(value_hash));
    }

    #[test]
    fn update_overwrites_value() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let v1 = H256::from_bytes([2u8; 32]);
        let v2 = H256::from_bytes([3u8; 32]);

        tree.update(&key, v1).unwrap();
        assert_eq!(tree.get(&key), Some(v1));

        tree.update(&key, v2).unwrap();
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
            tree.update(k, *v).unwrap();
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

        tree.update(&key, value_hash).unwrap();
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
        tree.update(&key, value_hash).unwrap();
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
        tree_a.update(&k1, v1).unwrap();
        tree_a.update(&k2, v2).unwrap();
        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k2, v2).unwrap();
        tree_b.update(&k1, v1).unwrap();
        assert_eq!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn different_keys_produce_different_roots() {
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v = H256::from_bytes([10u8; 32]);

        let mut tree_a: SmTree = SmTree::new();
        tree_a.update(&k1, v).unwrap();
        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k2, v).unwrap();
        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn different_values_produce_different_roots() {
        let k = H256::from_bytes([1u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree_a: SmTree = SmTree::new();
        tree_a.update(&k, v1).unwrap();
        let mut tree_b: SmTree = SmTree::new();
        tree_b.update(&k, v2).unwrap();
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
        tree.update(&key1, v1).unwrap();
        tree.update(&key2, v2).unwrap();
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
        tree.update(&k1, v1).unwrap();
        tree.update(&k2, v2).unwrap();
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

            tree.update(&key, val).unwrap();
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

    // ========================================================================
    // Fail-closed depth handling (SEC-005 / issue #73)
    // ========================================================================

    /// Store that can host arbitrarily deep (crafted) inner-node chains.
    #[derive(Clone, Debug, Default)]
    struct ChainNodeStore {
        nodes: HashMap<H256, SmtNode>,
    }

    impl NodeStore for ChainNodeStore {
        fn get(&self, hash: &H256) -> Option<SmtNode> {
            self.nodes.get(hash).cloned()
        }
        fn put(&mut self, node: SmtNode) -> H256 {
            let hash = node.hash();
            self.nodes.insert(hash, node);
            hash
        }
    }

    /// A key whose bits are all zero always takes the "left" branch, so a
    /// crafted deep inner-node chain drives the descent to the depth limit.
    fn zero_key() -> H256 {
        H256::from_bytes([0u8; 32])
    }

    #[test]
    fn depth_overflow_is_typed_fail_closed_error() {
        // Build a chain of Inner nodes reaching depth == TREE_DEPTH, then
        // surface it as the tree root and attempt an update through it.
        let mut store = ChainNodeStore::default();
        let empty = SmTree::<ChainNodeStore>::new().root();

        // Deepest node: an Inner examined exactly at the depth limit.
        let mut node_hash = store.put(SmtNode::Inner {
            left: H256::ZERO,
            right: empty,
        });

        // Wrap in Inner nodes up to the root (depth 0).
        for _ in 0..256 {
            let parent = SmtNode::Inner {
                left: node_hash,
                right: empty,
            };
            node_hash = store.put(parent);
        }

        let mut tree: SmTree<ChainNodeStore> = SmTree::with_store(store);
        tree.root = Some(node_hash);

        let err = tree
            .update(&zero_key(), H256::from_bytes([2u8; 32]))
            .unwrap_err();
        assert!(
            matches!(err, Error::DepthLimitExceeded),
            "expected a typed depth-limit error, got {err:?}"
        );
        assert_eq!(err.code(), workstream_core::ErrorCode::E1002);

        // Fail-closed: the error is fatal-classified and the root was not
        // mutated — the transition is rejected, not panicked on.
        assert!(err.is_fatal());
        assert!(!err.is_retryable());
        assert_eq!(tree.root(), node_hash);
        assert!(!tree.is_empty());
    }

    // ========================================================================
    // Proof Tests
    // ========================================================================

    #[test]
    fn proof_empty_tree_non_existence() {
        let tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);

        let proof = tree.prove(&key).unwrap();
        assert_eq!(proof.kind, SmtProofKind::NonExistence);
        assert!(proof.siblings.is_empty());
        assert!(proof.verify(tree.root()));
    }

    #[test]
    fn proof_inclusion_single_key() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value = H256::from_bytes([2u8; 32]);
        tree.update(&key, value).unwrap();
        let proof = tree.prove(&key).unwrap();
        assert_eq!(proof.kind, SmtProofKind::Inclusion);
        assert_eq!(proof.value_hash, Some(value));
        assert!(proof.verify(tree.root()));
    }

    #[test]
    fn proof_non_existence_key_not_present() {
        let mut tree: SmTree = SmTree::new();
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        tree.update(&k1, v1).unwrap();
        // Prove k2 doesn't exist
        let proof = tree.prove(&k2).unwrap();
        assert_eq!(proof.kind, SmtProofKind::NonExistence);
        assert!(proof.verify(tree.root()));

        // The original key should still have an inclusion proof
        let proof_k1 = tree.prove(&k1).unwrap();
        assert_eq!(proof_k1.kind, SmtProofKind::Inclusion);
        assert!(proof_k1.verify(tree.root()));
    }

    #[test]
    fn proof_with_multiple_keys() {
        let mut tree: SmTree = SmTree::new();
        let keys: Vec<H256> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                H256::from_bytes(bytes)
            })
            .collect();
        let values: Vec<H256> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i + 100;
                H256::from_bytes(bytes)
            })
            .collect();

        for (k, v) in keys.iter().zip(values.iter()) {
            tree.update(k, *v).unwrap();
        }

        let root = tree.root();

        // All keys should have valid inclusion proofs
        for (k, v) in keys.iter().zip(values.iter()) {
            let proof = tree.prove(k).unwrap();
            assert_eq!(proof.kind, SmtProofKind::Inclusion);
            assert_eq!(proof.value_hash, Some(*v));
            assert!(proof.verify(root), "proof for key {:?} failed", k);
        }

        // A non-existent key should have a valid non-existence proof
        let missing = H256::from_bytes([99u8; 32]);
        let proof = tree.prove(&missing).unwrap();
        assert_eq!(proof.kind, SmtProofKind::NonExistence);
        assert!(proof.verify(root));
    }

    #[test]
    fn proof_invalid_root_fails() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value = H256::from_bytes([2u8; 32]);
        tree.update(&key, value).unwrap();
        let proof = tree.prove(&key).unwrap();

        // Verify against wrong root
        let wrong_root = H256::from_bytes([99u8; 32]);
        assert!(!proof.verify(wrong_root));
    }

    #[test]
    fn proof_tampered_value_fails() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value = H256::from_bytes([2u8; 32]);
        tree.update(&key, value).unwrap();
        let mut proof = tree.prove(&key).unwrap();
        let root = tree.root();

        // Tamper with the value
        proof.value_hash = Some(H256::from_bytes([99u8; 32]));
        assert!(!proof.verify(root));
    }

    #[test]
    fn proof_tampered_sibling_fails() {
        let mut tree: SmTree = SmTree::new();
        // Insert two keys to create inner nodes
        let k1 = H256::from_bytes([0u8; 32]);
        let k2 = H256::from_bytes([
            0b10000000u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        tree.update(&k1, H256::from_bytes([1u8; 32])).unwrap();
        tree.update(&k2, H256::from_bytes([2u8; 32])).unwrap();
        let mut proof = tree.prove(&k1).unwrap();
        let root = tree.root();

        // Valid proof
        assert!(proof.verify(root));

        // Tamper with a sibling
        if !proof.siblings.is_empty() {
            proof.siblings[0] = H256::from_bytes([99u8; 32]);
            assert!(!proof.verify(root));
        }
    }

    #[test]
    fn proof_collision_keys() {
        // Two keys that share a long prefix
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1[31] = 0b00000001;
        k2[31] = 0b00000000;

        let key1 = H256::from_bytes(k1);
        let key2 = H256::from_bytes(k2);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        let mut tree: SmTree = SmTree::new();
        tree.update(&key1, v1).unwrap();
        tree.update(&key2, v2).unwrap();
        let root = tree.root();

        // Both should have valid inclusion proofs
        let p1 = tree.prove(&key1).unwrap();
        let p2 = tree.prove(&key2).unwrap();
        assert_eq!(p1.kind, SmtProofKind::Inclusion);
        assert_eq!(p2.kind, SmtProofKind::Inclusion);
        assert!(p1.verify(root));
        assert!(p2.verify(root));

        // Proofs should have siblings (they share a path)
        assert!(!p1.siblings.is_empty() || !p2.siblings.is_empty());
    }

    #[test]
    fn proof_after_delete() {
        let mut tree: SmTree = SmTree::new();
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v = H256::from_bytes([10u8; 32]);

        tree.update(&k1, v).unwrap();
        tree.update(&k2, v).unwrap();
        // Delete k1
        tree.delete(&k1);
        let root = tree.root();

        // k1 should have non-existence proof
        let proof = tree.prove(&k1).unwrap();
        assert_eq!(proof.kind, SmtProofKind::NonExistence);
        assert!(proof.verify(root));

        // k2 should still have inclusion proof
        let proof = tree.prove(&k2).unwrap();
        assert_eq!(proof.kind, SmtProofKind::Inclusion);
        assert!(proof.verify(root));
    }

    #[test]
    fn forged_non_existence_proof_rejected() {
        // An attacker takes a valid inclusion proof for key L and tries to use it
        // as a non-existence proof for a different key K. The verifier must reject this.
        let mut tree: SmTree = SmTree::new();
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);
        let v2 = H256::from_bytes([20u8; 32]);

        tree.update(&k1, v1).unwrap();
        tree.update(&k2, v2).unwrap();
        let root = tree.root();

        // Get the valid inclusion proof for k1
        let inclusion_proof = tree.prove(&k1).unwrap();
        assert_eq!(inclusion_proof.kind, SmtProofKind::Inclusion);

        // Forge a non-existence proof: claim k2 doesn't exist by reusing k1's path
        // with leaf_key = Some(k1) and value_hash = Some(v1).
        let forged = SmtProof {
            kind: SmtProofKind::NonExistence,
            key: k2, // query for a different key
            value_hash: Some(v1),
            leaf_key: Some(k1), // point to k1 as the conflicting leaf
            siblings: inclusion_proof.siblings.clone(),
            directions: inclusion_proof.directions.clone(),
            depth: inclusion_proof.depth,
        };

        // The verifier must reject this because k1's path does not share the
        // first `depth` bits with k2 (they diverge at bit 0).
        assert!(
            !verify_smt_proof(root, &forged),
            "forged non-existence proof must be rejected"
        );
    }

    #[test]
    fn forged_empty_non_existence_rejected() {
        // An attacker tries to forge an (None, None) non-existence proof using
        // siblings/directions from a valid inclusion path for a different key.
        let mut tree: SmTree = SmTree::new();
        let k1 = H256::from_bytes([1u8; 32]);
        let k2 = H256::from_bytes([2u8; 32]);
        let v1 = H256::from_bytes([10u8; 32]);

        tree.update(&k1, v1).unwrap();
        let root = tree.root();

        // Get the valid inclusion proof for k1
        let inclusion_proof = tree.prove(&k1).unwrap();

        // Forge an empty non-existence proof for k2 using k1's path
        let forged = SmtProof {
            kind: SmtProofKind::NonExistence,
            key: k2, // query for a different key
            value_hash: None,
            leaf_key: None,
            siblings: inclusion_proof.siblings.clone(),
            directions: inclusion_proof.directions.clone(),
            depth: inclusion_proof.depth,
        };

        // The verifier must reject this because directions don't match k2's bits.
        assert!(
            !verify_smt_proof(root, &forged),
            "forged empty non-existence must be rejected"
        );
    }

    #[test]
    fn tampered_depth_rejected() {
        let mut tree: SmTree = SmTree::new();
        let key = H256::from_bytes([1u8; 32]);
        let value = H256::from_bytes([2u8; 32]);
        tree.update(&key, value).unwrap();
        let mut proof = tree.prove(&key).unwrap();
        let root = tree.root();

        // Tamper with depth to mismatch sibling count
        proof.depth += 1;
        assert!(
            !verify_smt_proof(root, &proof),
            "tampered depth must be rejected"
        );
    }

    #[test]
    fn tampered_direction_rejected() {
        let mut tree: SmTree = SmTree::new();
        // Insert two keys to create inner nodes (so proof has siblings)
        let k1 = H256::from_bytes([0u8; 32]);
        let k2 = H256::from_bytes([
            0b10000000u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        tree.update(&k1, H256::from_bytes([1u8; 32])).unwrap();
        tree.update(&k2, H256::from_bytes([2u8; 32])).unwrap();
        let mut proof = tree.prove(&k1).unwrap();
        let root = tree.root();

        // Tamper with a direction bit
        if !proof.directions.is_empty() {
            proof.directions[0] = !proof.directions[0];
            assert!(
                !verify_smt_proof(root, &proof),
                "tampered direction must be rejected"
            );
        }
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
            tree.update(&key, value).unwrap();
            prop_assert_eq!(tree.get(&key), Some(value));
        }

        #[test]
        fn delete_then_get_returns_none(
            key in arb_h256(),
            value in arb_h256()
        ) {
            let mut tree: SmTree = SmTree::new();
            tree.update(&key, value).unwrap();
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
                tree_a.update(k, *v).unwrap();
                tree_b.update(k, *v).unwrap();
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
                tree_fwd.update(k, *v).unwrap();
            }

            let mut tree_rev: SmTree = SmTree::new();
            pairs.reverse();
            for (k, v) in &pairs {
                tree_rev.update(k, *v).unwrap();
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
            tree_a.update(&k1, v).unwrap();
            let mut tree_b: SmTree = SmTree::new();
            tree_b.update(&k2, v).unwrap();
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
            tree_a.update(&k, v1).unwrap();
            let mut tree_b: SmTree = SmTree::new();
            tree_b.update(&k, v2).unwrap();
            prop_assert_ne!(tree_a.root(), tree_b.root());
        }

        #[test]
        fn inclusion_proof_always_valid(
            key in arb_h256(),
            value in arb_h256()
        ) {
            let mut tree: SmTree = SmTree::new();
            tree.update(&key, value).unwrap();
            let proof = tree.prove(&key).unwrap();
            prop_assert_eq!(proof.kind, SmtProofKind::Inclusion);
            prop_assert!(proof.verify(tree.root()));
        }

        #[test]
        fn non_existence_proof_for_missing_key(
            inserted in arb_h256(),
            missing in arb_h256(),
            value in arb_h256()
        ) {
            prop_assume!(inserted != missing);

            let mut tree: SmTree = SmTree::new();
            tree.update(&inserted, value).unwrap();
            let proof = tree.prove(&missing).unwrap();
            prop_assert_eq!(proof.kind, SmtProofKind::NonExistence);
            prop_assert!(proof.verify(tree.root()));
        }

        #[test]
        fn all_proofs_valid_multi_key(
            pairs in prop::collection::vec((arb_h256(), arb_h256()), 1..15)
        ) {
            let mut tree: SmTree = SmTree::new();
            for (k, v) in &pairs {
                tree.update(k, *v).unwrap();
            }

            let root = tree.root();
            for (k, _) in &pairs {
                let proof = tree.prove(k).unwrap();
                prop_assert_eq!(proof.kind, SmtProofKind::Inclusion);
                prop_assert!(proof.verify(root), "proof failed for key {:?}", k);
            }
        }
    }
}
