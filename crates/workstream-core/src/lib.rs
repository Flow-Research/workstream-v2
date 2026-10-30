//! Core types and traits for WorkStream zkRollup
//! 
//! This crate defines the fundamental types used throughout the system:
//! - Hashes, addresses, identifiers
//! - Block and transaction types
//! - Core traits (State, STFTrait, etc.)
//! - Error types

pub mod error;
pub mod hash;
pub mod types;

pub use error::{Error, Result};
pub use hash::{Hash, Hashable, H256};
pub use types::*;
