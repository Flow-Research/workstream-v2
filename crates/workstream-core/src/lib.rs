//! Core types and traits for WorkStream zkRollup
//!
//! This crate defines the fundamental types used throughout the system:
//! - Hashes, addresses, identifiers
//! - Block and transaction types
//! - Core traits (State, STFTrait, etc.)
//! - Error types

pub mod account;
#[cfg(not(target_os = "zkvm"))]
pub mod bridge;
pub mod config;
pub mod error;
pub mod fork;
pub mod hash;
pub mod privacy;
pub mod types;

pub use account::{Account, AccountKind, AccountStatus, Scope, ValidatorRef, ValidatorSet};
#[cfg(not(target_os = "zkvm"))]
pub use bridge::{BridgeEscrow, BridgePool};
pub use error::{Error, ErrorCategory, ErrorCode, Result};
pub use fork::{ForkActivationHook, ForkConfig, ForkSchedule, GuestHash, NoopForkHook};
pub use hash::{Hash, Hashable, H256};
pub use types::*;

pub mod traits;

pub mod logging;
