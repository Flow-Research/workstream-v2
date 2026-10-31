//! State management for WorkStream
//!
//! Two-structure model:
//! - Sparse Merkle Tree for mutable lifecycle objects
//! - Merkle Mountain Range for append-only immutable records

use serde::{Deserialize, Serialize};
use workstream_core::{hash::H256, types::StateRoot, Error, Result};
use workstream_crypto::{MerkleMountainRange, SparseMerkleTree};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub smt: SparseMerkleTree,
    pub mmr: MerkleMountainRange,
    pub version: u64,
}

impl State {
    pub fn new() -> Self {
        State {
            smt: SparseMerkleTree::new(),
            mmr: MerkleMountainRange::new(),
            version: 0,
        }
    }

    pub fn root(&self) -> StateRoot {
        StateRoot::new(self.smt.root(), self.mmr.root())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.smt.get(key)
    }

    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.smt.update(key, value)
    }

    pub fn append_record(&mut self, record: &[u8]) -> Result<u64> {
        self.mmr.append(record)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
