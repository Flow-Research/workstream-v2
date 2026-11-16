//! State management for WorkStream
//!
//! Two-structure model:
//! - Sparse Merkle Tree for mutable lifecycle objects
//! - Merkle Mountain Range for append-only immutable records

use std::path::Path;

use serde::{Deserialize, Serialize};
use workstream_core::hash::H256;
use workstream_core::types::{BlockHeader, StateRoot};
use workstream_core::{Error, Result};
use workstream_crypto::{MerkleMountainRange, SparseMerkleTree};

/// Durable snapshot of a [`State`]: the SMT live entries plus their root and
/// the MMR leaf sequence, together with the last applied block header (None
/// while the chain is at genesis). Enough to rebuild an identical state after
/// a restart.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StateSnapshot {
    pub version: u64,
    pub smt_root: H256,
    pub smt_entries: Vec<(H256, Vec<u8>)>,
    pub mmr_leaves: Vec<(u64, H256)>,
    pub last_header: Option<BlockHeader>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub smt: SparseMerkleTree,
    pub mmr: MerkleMountainRange,
    pub version: u64,
    /// Hash-bearing location of the chain: the last applied block header, if
    /// any (`None` while the chain is at genesis). Restored by
    /// [`State::load_from_dir`] so a restart resumes at the same tip.
    pub last_header: Option<BlockHeader>,
}

impl State {
    pub fn new() -> Self {
        State {
            smt: SparseMerkleTree::new(),
            mmr: MerkleMountainRange::new(),
            version: 0,
            last_header: None,
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

    /// Capture a durable snapshot of the current state.
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            version: self.version,
            smt_root: self.smt.root(),
            smt_entries: self.smt.entries(),
            mmr_leaves: self.mmr.entries(),
            last_header: self.last_header.clone(),
        }
    }

    /// Persist the state snapshot to `<dir>/state.json`.
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        let snapshot = self.snapshot();
        std::fs::create_dir_all(dir).map_err(|e| Error::Io(e.to_string()))?;
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| Error::Serialization(e.to_string()))?,
        )
        .map_err(|e| Error::Io(e.to_string()))
    }

    /// Load the state snapshot previously written by [`State::save_to_dir`].
    ///
    /// Rebuilds the SMT from its live entries and the MMR from its leaf
    /// sequence, verifying that the recomputed SMT root matches the captured
    /// root before returning the state.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let path = dir.join("state.json");
        let bytes = std::fs::read(&path).map_err(|e| Error::Io(e.to_string()))?;
        let snapshot: StateSnapshot =
            serde_json::from_slice(&bytes).map_err(|e| Error::Serialization(e.to_string()))?;
        let mut state = State::new();
        for (key, value) in snapshot.smt_entries {
            state.smt.update_hashed(&key, &value)?;
        }
        if state.smt.root() != snapshot.smt_root {
            return Err(Error::State(format!(
                "snapshot smt root mismatch: expected {:?}, got {:?}",
                snapshot.smt_root,
                state.smt.root()
            )));
        }
        state.mmr = MerkleMountainRange::from_entries(&snapshot.mmr_leaves);
        state.version = snapshot.version;
        state.last_header = snapshot.last_header;
        Ok(state)
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("workstream-state-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn state_snapshot_round_trips_through_disk() {
        let dir = temp_dir("roundtrip");
        let mut state = State::new();
        state.set(b"actor:1", b"sponsor").unwrap();
        state.set(b"actor:2", b"worker").unwrap();
        state.set(b"task:abc", b"award:7").unwrap();
        state.append_record(b"record-0").unwrap();
        state.append_record(b"record-1").unwrap();
        state.version = 3;
        state.last_header = Some(BlockHeader {
            number: 2,
            parent_hash: H256::ZERO,
            timestamp: 0,
            tx_root: H256::ZERO,
            state_root: StateRoot::new(H256::ZERO, H256::ZERO),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::ZERO,
            proof_system_version: 0,
            proof: None,
        });

        state.save_to_dir(&dir).unwrap();

        let mut loaded = State::load_from_dir(&dir).unwrap();
        assert_eq!(loaded.version, state.version);
        assert_eq!(loaded.root(), state.root());
        assert_eq!(
            loaded.get(b"actor:1").unwrap().unwrap(),
            b"sponsor".to_vec()
        );
        assert_eq!(loaded.get(b"actor:2").unwrap().unwrap(), b"worker".to_vec());
        assert_eq!(
            loaded.get(b"task:abc").unwrap().unwrap(),
            b"award:7".to_vec()
        );
        assert_eq!(loaded.mmr.size(), 2);
        assert_eq!(loaded.append_record(b"record-2").unwrap(), 2);
        assert_eq!(loaded.mmr.size(), 3);
        assert_eq!(loaded.last_header, state.last_header);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_snapshot_of_empty_state_round_trips() {
        let dir = temp_dir("empty");
        let state = State::new();
        state.save_to_dir(&dir).unwrap();
        let loaded = State::load_from_dir(&dir).unwrap();
        assert_eq!(loaded.root(), state.root());
        assert!(loaded.get(b"missing").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_missing_snapshot_fails_closed() {
        let dir = temp_dir("missing");
        let err = State::load_from_dir(&dir).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
