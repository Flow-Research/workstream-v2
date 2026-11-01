//! Core types and traits for WorkStream zkRollup
//!
//! This crate defines the fundamental types used throughout the system:
//! - Hashes, addresses, identifiers
//! - Block and transaction types
//! - Core traits (State, STFTrait, etc.)
//! - Error types

pub mod config;
pub mod error;
pub mod hash;
pub mod types;

pub use error::{Error, ErrorCategory, ErrorCode, Result};
pub use hash::{Hash, Hashable, H256};
pub use types::*;

pub mod traits;

pub mod logging;
