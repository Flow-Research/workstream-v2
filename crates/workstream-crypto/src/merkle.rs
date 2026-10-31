use serde::{Deserialize, Serialize};
use workstream_core::hash::{Hash, H256};
use workstream_core::Result;

/// Sparse Merkle Tree for mutable lifecycle objects
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    root: H256,
    // Simplified implementation for starter
    nodes: std::collections::HashMap<H256, H256>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        SparseMerkleTree {
            root: H256::ZERO,
            nodes: std::collections::HashMap::new(),
        }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn update(&mut self, _key: &[u8], _value: &[u8]) -> Result<()> {
        // Simplified - would do full SMT update
        self.root = Hash::sha256_concat(&[self.root.as_bytes(), b"smt_update"]);
        Ok(())
    }

    pub fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Merkle Mountain Range for append-only immutable records
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleMountainRange {
    root: H256,
    size: u64,
}

impl MerkleMountainRange {
    pub fn new() -> Self {
        MerkleMountainRange {
            root: H256::ZERO,
            size: 0,
        }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn append(&mut self, leaf: &[u8]) -> Result<u64> {
        let leaf_hash = Hash::sha256(leaf);
        self.root = Hash::sha256_concat(&[self.root.as_bytes(), leaf_hash.as_bytes()]);
        self.size += 1;
        Ok(self.size - 1)
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Default for MerkleMountainRange {
    fn default() -> Self {
        Self::new()
    }
}
