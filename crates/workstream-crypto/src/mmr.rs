//! Merkle Mountain Range implementation for WorkStream (issue #36).
//!
//! An append-only authenticated log following the design in `docs/design/smt-mmr.md`.
//! Key properties:
//!
//! - **Append-only**: Leaves are immutable once added; only appends are allowed.
//!
//! - **Peaks structure**: The MMR is a forest of perfect binary trees ("peaks").
//!   When appending, peaks of equal height are merged.
//!
//! - **Size-bound root**: The root commits to the size `n`, preventing proof
//!   replay at different indices or sizes.
//!
//! - **Domain-separated hashing**: Leaf and inner node preimages use distinct
//!   tags to prevent second-preimage attacks.
//!
//! - **Deterministic**: All operations produce identical results given
//!   identical inputs, suitable for zkVM execution.

use serde::{Deserialize, Serialize};
use workstream_core::hash::{Hash, H256};
use workstream_core::{Error, Result};

// Domain tags per the design doc
const TAG_EMPTY: &[u8] = b"WSMMR:v1:EMPTY";
const TAG_LEAF: &[u8] = b"WSMMR:v1:L";
const TAG_INNER: &[u8] = b"WSMMR:v1:N";
const TAG_ROOT: &[u8] = b"WSMMR:v1:PEAKS";

/// Hash of an empty MMR.
fn empty_root() -> H256 {
    Hash::sha256(TAG_EMPTY)
}

/// Hash a leaf at a given index.
fn hash_leaf(index: u64, payload_hash: H256) -> H256 {
    Hash::sha256_concat(&[TAG_LEAF, &index.to_le_bytes(), payload_hash.as_bytes()])
}

/// Hash an inner node from two children.
fn hash_inner(left: H256, right: H256) -> H256 {
    Hash::sha256_concat(&[TAG_INNER, left.as_bytes(), right.as_bytes()])
}

/// Compute the root by bagging peaks (right-to-left) with size binding.
fn bag_peaks(peaks: &[H256], size: u64) -> H256 {
    if peaks.is_empty() {
        return empty_root();
    }

    // Right-to-left fold: start from rightmost peak, bag toward left
    let mut acc = peaks[peaks.len() - 1];
    for peak in peaks.iter().rev().skip(1) {
        acc = hash_inner(*peak, acc);
    }

    // Final root includes the size for replay protection
    Hash::sha256_concat(&[TAG_ROOT, &size.to_le_bytes(), acc.as_bytes()])
}

/// Get the heights of all peaks for a given size n.
///
/// The peaks correspond to the set bits in the binary representation of n.
/// Returns heights in left-to-right order (highest to lowest).
fn peak_heights(n: u64) -> Vec<u32> {
    let mut heights = Vec::new();
    for i in (0..64).rev() {
        if (n >> i) & 1 == 1 {
            heights.push(i);
        }
    }
    heights
}

/// A node in the MMR (either a leaf or inner node).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MmrNode {
    Leaf { index: u64, payload_hash: H256 },
    Inner { left: H256, right: H256 },
}

impl MmrNode {
    pub fn hash(&self) -> H256 {
        match self {
            MmrNode::Leaf {
                index,
                payload_hash,
            } => hash_leaf(*index, *payload_hash),
            MmrNode::Inner { left, right } => hash_inner(*left, *right),
        }
    }
}

/// Stored element: either a leaf's payload hash or a full path from leaf to its peak.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LeafEntry {
    /// Original payload hash.
    payload_hash: H256,
    /// Sibling hashes from leaf to peak (bottom-up).
    siblings: Vec<H256>,
}

/// Merkle Mountain Range — an append-only authenticated log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MmrTree {
    /// Current peaks (one per set bit in `size`), left-to-right (highest first).
    peaks: Vec<H256>,
    /// Number of leaves appended.
    size: u64,
    /// Leaf data for proof generation.
    #[serde(skip)]
    leaf_data: Vec<LeafEntry>,
}

impl Default for MmrTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MmrTree {
    /// Create an empty MMR.
    pub fn new() -> Self {
        MmrTree {
            peaks: Vec::new(),
            size: 0,
            leaf_data: Vec::new(),
        }
    }

    /// Get the current root hash.
    ///
    /// The root is the bagged hash of all peaks, bound to the current size.
    pub fn root(&self) -> H256 {
        bag_peaks(&self.peaks, self.size)
    }

    /// Get the number of leaves in the MMR.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Check if the MMR is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Append a leaf and return its index.
    ///
    /// The payload is hashed, then combined with the index for the leaf hash.
    pub fn append(&mut self, payload: &[u8]) -> u64 {
        let payload_hash = Hash::sha256(payload);
        self.append_hash(payload_hash)
    }

    /// Append a pre-hashed payload.
    pub fn append_hash(&mut self, payload_hash: H256) -> u64 {
        let index = self.size;

        // Create leaf node
        let leaf_hash = hash_leaf(index, payload_hash);

        // Start building the path for this leaf
        let mut leaf_siblings = Vec::new();

        // Merge with equal-height peaks
        let mut current = leaf_hash;
        let new_size = index + 1;

        // Track how many leaves are in the right subtree being built
        let mut right_subtree_start = index;
        let mut right_subtree_leaves = 1u64;

        // Number of merges = trailing 1s in the index
        let mut temp = index;

        while temp & 1 == 1 && !self.peaks.is_empty() {
            let left = self.peaks.pop().unwrap();

            // All leaves in the RIGHT subtree (including new leaf) need LEFT peak as sibling
            leaf_siblings.push(left);
            for i in right_subtree_start..index {
                self.leaf_data[i as usize].siblings.push(left);
            }

            // All leaves in the LEFT subtree need 'current' (right subtree hash) as sibling
            let left_subtree_start = right_subtree_start - right_subtree_leaves;
            for i in left_subtree_start..right_subtree_start {
                self.leaf_data[i as usize].siblings.push(current);
            }

            current = hash_inner(left, current);

            // Update right subtree bounds (now includes both left and right)
            right_subtree_start = left_subtree_start;
            right_subtree_leaves *= 2;

            temp >>= 1;
        }

        // Store the leaf entry with its siblings so far
        self.leaf_data.push(LeafEntry {
            payload_hash,
            siblings: leaf_siblings,
        });

        self.peaks.push(current);
        self.size = new_size;
        index
    }

    /// Generate a proof for the leaf at the given index.
    ///
    /// Returns an error if the index is out of bounds.
    pub fn prove(&self, index: u64) -> Result<MmrProof> {
        if index >= self.size {
            return Err(Error::State(format!(
                "index {} out of bounds (size {})",
                index, self.size
            )));
        }

        let entry = &self.leaf_data[index as usize];

        // Determine which peak this leaf is in
        let heights = peak_heights(self.size);
        let mut leaf_offset = 0u64;
        let mut peak_idx = 0;
        let mut local_index = index;

        for (i, &h) in heights.iter().enumerate() {
            let peak_leaves = 1u64 << h;
            if index < leaf_offset + peak_leaves {
                peak_idx = i;
                local_index = index - leaf_offset;
                break;
            }
            leaf_offset += peak_leaves;
        }

        // Build directions from the local index bits
        let peak_height = heights[peak_idx] as usize;
        let mut directions = Vec::with_capacity(peak_height);
        for level in 0..peak_height {
            let is_right = (local_index >> level) & 1 == 1;
            directions.push(is_right);
        }

        // Collect other peaks for bagging
        let other_peaks: Vec<H256> = self
            .peaks
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != peak_idx)
            .map(|(_, &h)| h)
            .collect();

        Ok(MmrProof {
            index,
            size: self.size,
            siblings: entry.siblings.clone(),
            directions,
            peak_idx,
            other_peaks,
        })
    }
}

// Implement PartialEq manually since leaf_data is not serialized
impl PartialEq for LeafEntry {
    fn eq(&self, other: &Self) -> bool {
        self.payload_hash == other.payload_hash && self.siblings == other.siblings
    }
}

impl Eq for LeafEntry {}

/// MMR membership proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MmrProof {
    /// Leaf index being proven.
    pub index: u64,
    /// MMR size at time of proof (for verification).
    pub size: u64,
    /// Sibling hashes from leaf to peak (bottom-up).
    pub siblings: Vec<H256>,
    /// Direction bits: false = we're on left, true = we're on right.
    pub directions: Vec<bool>,
    /// Index of the peak containing this leaf (for bagging).
    pub peak_idx: usize,
    /// Other peaks (for bagging to root).
    pub other_peaks: Vec<H256>,
}

impl MmrProof {
    /// Verify this proof against a root hash and payload.
    pub fn verify(&self, root: H256, payload: &[u8]) -> bool {
        let payload_hash = Hash::sha256(payload);
        self.verify_hash(root, payload_hash)
    }

    /// Verify with a pre-hashed payload.
    pub fn verify_hash(&self, root: H256, payload_hash: H256) -> bool {
        verify_mmr_proof(root, self, payload_hash)
    }
}

/// Verify an MMR proof against a root hash.
///
/// This is a standalone function that doesn't require access to the tree.
pub fn verify_mmr_proof(root: H256, proof: &MmrProof, payload_hash: H256) -> bool {
    // Bounds checks: index must be within the claimed size, and size > 0.
    if proof.size == 0 || proof.index >= proof.size {
        return false;
    }

    // Recompute the leaf hash
    let mut current = hash_leaf(proof.index, payload_hash);

    // Walk up through siblings to get the peak hash
    if proof.siblings.len() != proof.directions.len() {
        return false;
    }

    for (sibling, &is_right) in proof.siblings.iter().zip(proof.directions.iter()) {
        let (left, right) = if is_right {
            (*sibling, current)
        } else {
            (current, *sibling)
        };
        current = hash_inner(left, right);
    }

    // Current now holds the peak hash. Reconstruct the full peak list.
    let heights = peak_heights(proof.size);
    if proof.peak_idx >= heights.len() {
        return false;
    }

    // Validate that the number of other_peaks matches what's expected.
    let expected_other = heights.len().saturating_sub(1);
    if proof.other_peaks.len() != expected_other {
        return false;
    }

    // Reconstruct peaks array
    let mut peaks = Vec::with_capacity(heights.len());
    let mut other_idx = 0;

    for i in 0..heights.len() {
        if i == proof.peak_idx {
            peaks.push(current);
        } else {
            if other_idx >= proof.other_peaks.len() {
                return false;
            }
            peaks.push(proof.other_peaks[other_idx]);
            other_idx += 1;
        }
    }

    // Bag peaks and compare to expected root
    let computed_root = bag_peaks(&peaks, proof.size);
    computed_root == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mmr_has_deterministic_root() {
        let mmr1 = MmrTree::new();
        let mmr2 = MmrTree::new();
        assert_eq!(mmr1.root(), mmr2.root());
        assert_eq!(mmr1.root(), empty_root());
    }

    #[test]
    fn append_returns_indices() {
        let mut mmr = MmrTree::new();
        assert_eq!(mmr.size(), 0);

        assert_eq!(mmr.append(b"leaf-0"), 0);
        assert_eq!(mmr.append(b"leaf-1"), 1);
        assert_eq!(mmr.append(b"leaf-2"), 2);
        assert_eq!(mmr.append(b"leaf-3"), 3);
        assert_eq!(mmr.size(), 4);
    }

    #[test]
    fn root_changes_on_append() {
        let mut mmr = MmrTree::new();
        let empty_root = mmr.root();

        mmr.append(b"leaf-0");
        assert_ne!(mmr.root(), empty_root);

        let root1 = mmr.root();
        mmr.append(b"leaf-1");
        assert_ne!(mmr.root(), root1);
    }

    #[test]
    fn deterministic_replay() {
        let mut mmr1 = MmrTree::new();
        let mut mmr2 = MmrTree::new();

        for i in 0..10 {
            let data = format!("record-{}", i);
            mmr1.append(data.as_bytes());
            mmr2.append(data.as_bytes());
        }

        assert_eq!(mmr1.root(), mmr2.root());
    }

    #[test]
    fn peak_heights_computation() {
        // 0 = 0b0 -> no peaks
        assert!(peak_heights(0).is_empty());

        // 1 = 0b1 -> [0] (one peak of height 0)
        assert_eq!(peak_heights(1), vec![0]);

        // 2 = 0b10 -> [1] (one peak of height 1)
        assert_eq!(peak_heights(2), vec![1]);

        // 3 = 0b11 -> [1, 0] (height 1 and height 0)
        assert_eq!(peak_heights(3), vec![1, 0]);

        // 7 = 0b111 -> [2, 1, 0]
        assert_eq!(peak_heights(7), vec![2, 1, 0]);

        // 8 = 0b1000 -> [3]
        assert_eq!(peak_heights(8), vec![3]);
    }

    #[test]
    fn proof_single_leaf() {
        let mut mmr = MmrTree::new();
        mmr.append(b"only-leaf");

        let root = mmr.root();
        let proof = mmr.prove(0).unwrap();

        assert_eq!(proof.index, 0);
        assert_eq!(proof.size, 1);
        assert!(proof.siblings.is_empty()); // Single leaf = no siblings
        assert!(proof.verify(root, b"only-leaf"));
    }

    #[test]
    fn proof_two_leaves() {
        let mut mmr = MmrTree::new();
        mmr.append(b"leaf-0");
        mmr.append(b"leaf-1");

        let root = mmr.root();

        // Proof for leaf 0
        let proof0 = mmr.prove(0).unwrap();
        assert!(proof0.verify(root, b"leaf-0"), "proof for leaf 0 failed");

        // Proof for leaf 1
        let proof1 = mmr.prove(1).unwrap();
        assert!(proof1.verify(root, b"leaf-1"), "proof for leaf 1 failed");
    }

    #[test]
    fn proof_three_leaves() {
        let mut mmr = MmrTree::new();
        mmr.append(b"leaf-0");
        mmr.append(b"leaf-1");
        mmr.append(b"leaf-2");

        let root = mmr.root();

        for i in 0..3 {
            let data = format!("leaf-{}", i);
            let proof = mmr.prove(i).unwrap();
            assert!(
                proof.verify(root, data.as_bytes()),
                "proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn proof_four_leaves() {
        let mut mmr = MmrTree::new();
        for i in 0..4 {
            mmr.append(format!("leaf-{}", i).as_bytes());
        }

        let root = mmr.root();

        for i in 0..4 {
            let data = format!("leaf-{}", i);
            let proof = mmr.prove(i).unwrap();
            assert!(
                proof.verify(root, data.as_bytes()),
                "proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn proof_multiple_leaves() {
        let mut mmr = MmrTree::new();
        let data: Vec<_> = (0..7).map(|i| format!("leaf-{}", i)).collect();

        for d in &data {
            mmr.append(d.as_bytes());
        }

        let root = mmr.root();

        for (i, d) in data.iter().enumerate() {
            let proof = mmr.prove(i as u64).unwrap();
            assert!(
                proof.verify(root, d.as_bytes()),
                "proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn proof_invalid_payload_fails() {
        let mut mmr = MmrTree::new();
        mmr.append(b"correct-data");

        let root = mmr.root();
        let proof = mmr.prove(0).unwrap();

        assert!(!proof.verify(root, b"wrong-data"));
    }

    #[test]
    fn proof_invalid_root_fails() {
        let mut mmr = MmrTree::new();
        mmr.append(b"data");

        let wrong_root = H256::from_bytes([99u8; 32]);
        let proof = mmr.prove(0).unwrap();

        assert!(!proof.verify(wrong_root, b"data"));
    }

    #[test]
    fn proof_out_of_bounds_fails() {
        let mut mmr = MmrTree::new();
        mmr.append(b"leaf");

        assert!(mmr.prove(1).is_err());
        assert!(mmr.prove(100).is_err());
    }

    #[test]
    fn proof_size_binding() {
        let mut mmr = MmrTree::new();
        mmr.append(b"leaf-0");
        mmr.append(b"leaf-1");

        let root_at_2 = mmr.root();
        let proof = mmr.prove(0).unwrap();

        // Proof valid at size 2
        assert!(proof.verify(root_at_2, b"leaf-0"));

        // Add another leaf
        mmr.append(b"leaf-2");
        let root_at_3 = mmr.root();

        // Proof from size 2 should NOT verify against root at size 3
        assert!(!proof.verify(root_at_3, b"leaf-0"));
    }

    #[test]
    fn stress_test_many_appends() {
        let mut mmr = MmrTree::new();

        // Append 100 leaves
        for i in 0..100 {
            let data = format!("leaf-{:04}", i);
            let idx = mmr.append(data.as_bytes());
            assert_eq!(idx, i as u64);
        }

        let root = mmr.root();

        // Verify all proofs
        for i in 0..100 {
            let data = format!("leaf-{:04}", i);
            let proof = mmr.prove(i as u64).unwrap();
            assert!(
                proof.verify(root, data.as_bytes()),
                "proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn leaf_and_inner_hashes_differ() {
        let payload = H256::from_bytes([1u8; 32]);

        let leaf = MmrNode::Leaf {
            index: 0,
            payload_hash: payload,
        };

        let inner = MmrNode::Inner {
            left: payload,
            right: payload,
        };

        // Domain separation ensures different hashes
        assert_ne!(leaf.hash(), inner.hash());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn all_proofs_valid(
            leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..50), 1..20)
        ) {
            let mut mmr = MmrTree::new();
            for leaf in &leaves {
                mmr.append(leaf);
            }

            let root = mmr.root();
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = mmr.prove(i as u64).unwrap();
                prop_assert!(
                    proof.verify(root, leaf),
                    "proof failed for leaf {}", i
                );
            }
        }

        #[test]
        fn tampered_payload_fails(
            leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..50), 2..10),
            tamper_idx in 0usize..10,
            tamper_byte in any::<u8>()
        ) {
            let tamper_idx = tamper_idx % leaves.len();

            let mut mmr = MmrTree::new();
            for leaf in &leaves {
                mmr.append(leaf);
            }

            let root = mmr.root();
            let proof = mmr.prove(tamper_idx as u64).unwrap();

            // Create tampered data
            let mut tampered = leaves[tamper_idx].clone();
            if !tampered.is_empty() {
                tampered[0] = tampered[0].wrapping_add(tamper_byte.saturating_add(1));
                prop_assert!(!proof.verify(root, &tampered));
            }
        }

        #[test]
        fn deterministic_root(
            leaves in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..30), 0..15)
        ) {
            let mut mmr1 = MmrTree::new();
            let mut mmr2 = MmrTree::new();

            for leaf in &leaves {
                mmr1.append(leaf);
                mmr2.append(leaf);
            }

            prop_assert_eq!(mmr1.root(), mmr2.root());
        }
    }
}
