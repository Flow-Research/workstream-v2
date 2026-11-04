//! Cryptographic primitives for WorkStream
//!
//! Implements SHA-256 everywhere as per design: content addressing,
//! Merkle trees, commitments, all use SHA-256/SHA-3

pub mod commitment;
pub mod hash;
pub mod merkle;
pub mod mmr;
pub mod signature;
pub mod smt;

pub use mmr::{verify_mmr_proof, MmrNode, MmrProof, MmrTree};
pub use smt::{
    hash_key, hash_value, verify_smt_proof, MemoryNodeStore, NodeStore, SmTree, SmtNode, SmtProof,
    SmtProofKind,
};

pub use commitment::*;
pub use hash::*;
pub use merkle::*;
pub use signature::*;
