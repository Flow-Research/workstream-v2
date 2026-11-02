//! Fork gating infrastructure
//!
//! WorkStream hard forks activate at fixed block heights, mirroring Ethereum's
//! upgrade model. All fork resolution is a pure function of block height and
//! the fork schedule — deterministic and consensus-critical.
//!
//! Rules (from the design reference):
//! - No mid-block forks: the active fork is resolved per block by height
//! - Pre-fork enforcement: post-fork behavior is rejected before activation
//! - Headers carry `fork_id` + `guest_hash` and are validated against the schedule
//! - Genesis must define the initial fork (activation_height 0)
//! - Governance-driven activation is exposed through a deterministic hook trait

use serde::{Deserialize, Serialize};

use crate::hash::H256;
use crate::types::{BlockHeader, BlockNumber};
use crate::{Error, Result};

/// Identifier for the approved zkVM guest program image of a fork
pub type GuestHash = H256;

/// Well-known feature flags for gating behavior by fork
pub mod features {
    /// Task lifecycle operations (TaskCreate..TaskStart)
    pub const TASK_LIFECYCLE: &str = "task-lifecycle";
    /// Submission, review and acceptance operations
    pub const SUBMISSION_REVIEW: &str = "submission-review";
    /// Reputation operations
    pub const REPUTATION: &str = "reputation";
    /// Governance upgrade operations
    pub const GOVERNANCE: &str = "governance";
}

/// A single hard fork definition
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkConfig {
    /// Numeric fork identifier (strictly increasing across the schedule)
    pub fork_id: u64,
    /// Human-readable name
    pub name: String,
    /// First block height at which this fork is active
    pub activation_height: BlockNumber,
    /// Approved zkVM guest image hash for this fork
    pub guest_hash: GuestHash,
    /// Minimum proof system version accepted under this fork
    pub min_proof_system: u32,
    /// Feature flags enabled by this fork
    pub features: Vec<String>,
}

impl ForkConfig {
    /// Whether this fork is active at the given block height
    pub fn is_active_at(&self, height: BlockNumber) -> bool {
        height >= self.activation_height
    }

    /// Whether the given feature flag is enabled under this fork
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// Validate fork definition
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::Fork(format!(
                "fork {} has an empty name",
                self.fork_id
            )));
        }
        if self.min_proof_system == 0 {
            return Err(Error::Fork(format!(
                "fork {} ({}) min_proof_system must be >= 1",
                self.fork_id, self.name
            )));
        }
        if self.guest_hash == H256::default() {
            return Err(Error::Fork(format!(
                "fork {} ({}) has a zero guest_hash",
                self.fork_id, self.name
            )));
        }
        if self.features.iter().any(|f| f.is_empty()) {
            return Err(Error::Fork(format!(
                "fork {} ({}) has an empty feature flag",
                self.fork_id, self.name
            )));
        }
        Ok(())
    }
}

/// An ordered, validated fork schedule for a chain
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Chain this schedule applies to
    pub chain_id: u64,
    /// Forks sorted by activation height, ascending
    pub forks: Vec<ForkConfig>,
}

impl ForkSchedule {
    /// Build a schedule, sorting by activation height and validating ordering.
    /// Rejects schedules that could lead to ambiguous fork resolution.
    pub fn new(chain_id: u64, mut forks: Vec<ForkConfig>) -> Result<Self> {
        forks.sort_by_key(|f| f.activation_height);
        let schedule = Self { chain_id, forks };
        schedule.validate()?;
        Ok(schedule)
    }

    /// Validate the whole schedule
    pub fn validate(&self) -> Result<()> {
        if self.forks.is_empty() {
            return Err(Error::Fork("fork schedule is empty".to_string()));
        }
        // Genesis fork must activate at height 0
        if self.forks[0].activation_height != 0 {
            return Err(Error::Fork(
                "first fork must activate at height 0 (genesis)".to_string(),
            ));
        }

        let mut last_height = 0u64;
        let mut last_id = 0u64;
        let mut first = true;
        for fork in &self.forks {
            fork.validate()?;
            if !first {
                // Activation heights and ids must be strictly increasing:
                // two forks at the same height would make resolution ambiguous
                if fork.activation_height <= last_height {
                    return Err(Error::Fork(format!(
                        "fork {} activates at height {} which is not after {}",
                        fork.fork_id, fork.activation_height, last_height
                    )));
                }
                if fork.fork_id <= last_id {
                    return Err(Error::Fork(format!(
                        "fork ids must be strictly increasing, found {} after {}",
                        fork.fork_id, last_id
                    )));
                }
            }
            last_height = fork.activation_height;
            last_id = fork.fork_id;
            first = false;
        }
        Ok(())
    }

    /// The genesis fork (always the first entry)
    pub fn genesis_fork(&self) -> &ForkConfig {
        &self.forks[0]
    }

    /// Resolve the active fork for a block height.
    /// Deterministic: latest fork whose activation height is <= the given height.
    pub fn active_fork_at(&self, height: BlockNumber) -> Option<&ForkConfig> {
        self.forks.iter().rev().find(|f| f.is_active_at(height))
    }

    /// Whether a guest hash is approved for the given fork id
    pub fn is_approved_guest(&self, fork_id: u64, guest_hash: &GuestHash) -> bool {
        self.forks
            .iter()
            .any(|f| f.fork_id == fork_id && &f.guest_hash == guest_hash)
    }

    /// The fork that will activate next after the given height, if any
    pub fn next_fork_after(&self, height: BlockNumber) -> Option<&ForkConfig> {
        self.forks.iter().find(|f| f.activation_height > height)
    }
}

impl Default for ForkSchedule {
    /// A single-fork genesis schedule (fork 1, no features)
    fn default() -> Self {
        ForkSchedule {
            chain_id: 1,
            forks: vec![ForkConfig {
                fork_id: 1,
                name: "genesis".to_string(),
                activation_height: 0,
                guest_hash: H256::default(),
                min_proof_system: 1,
                features: vec![],
            }],
        }
    }
}

/// Validate a block header against a fork schedule.
///
/// Rejects headers with an unknown `fork_id`, a `guest_hash` not approved for
/// the resolved fork, or a proof system version below the fork minimum.
/// Consensus-critical: every node must run this before accepting a block.
pub fn validate_header_fork(header: &BlockHeader, schedule: &ForkSchedule) -> Result<()> {
    let fork = schedule
        .active_fork_at(header.number)
        .ok_or_else(|| Error::Fork(format!("no active fork for block height {}", header.number)))?;

    if header.fork_id != fork.fork_id {
        return Err(Error::Fork(format!(
            "block {} has fork_id {} but active fork at height {} is {} ({})",
            header.number, header.fork_id, header.number, fork.fork_id, fork.name
        )));
    }

    if header.guest_hash != fork.guest_hash {
        return Err(Error::Fork(format!(
            "block {} guest_hash not approved for fork {} ({})",
            header.number, fork.fork_id, fork.name
        )));
    }

    if header.proof_system_version < fork.min_proof_system {
        return Err(Error::Fork(format!(
            "block {} proof_system_version {} is below fork {} minimum {}",
            header.number, header.proof_system_version, fork.fork_id, fork.min_proof_system
        )));
    }

    Ok(())
}

/// Governance hook invoked exactly once when a fork activates
/// (i.e. before processing the first block at `activation_height`).
///
/// Implementations MUST be deterministic: no wall clocks, randomness, or I/O.
/// Used for state migrations and other activation-time bookkeeping.
pub trait ForkActivationHook {
    /// Called for the block at a fork's activation height, before execution
    fn on_activation(&self, fork: &ForkConfig, height: BlockNumber) -> Result<()>;
}

/// No-op hook for chains without activation-time migrations
#[derive(Clone, Debug, Default)]
pub struct NoopForkHook;

impl ForkActivationHook for NoopForkHook {
    fn on_activation(&self, _fork: &ForkConfig, _height: BlockNumber) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::types::{Proof, StateRoot};

    fn guest_hash(seed: u8) -> GuestHash {
        Hash::sha256(&[seed; 32])
    }

    fn test_schedule() -> ForkSchedule {
        ForkSchedule::new(
            1,
            vec![
                ForkConfig {
                    fork_id: 1,
                    name: "genesis".to_string(),
                    activation_height: 0,
                    guest_hash: guest_hash(1),
                    min_proof_system: 1,
                    features: vec![],
                },
                ForkConfig {
                    fork_id: 2,
                    name: "tasks".to_string(),
                    activation_height: 100,
                    guest_hash: guest_hash(2),
                    min_proof_system: 2,
                    features: vec![features::TASK_LIFECYCLE.to_string()],
                },
                ForkConfig {
                    fork_id: 3,
                    name: "reputation".to_string(),
                    activation_height: 200,
                    guest_hash: guest_hash(3),
                    min_proof_system: 2,
                    features: vec![
                        features::TASK_LIFECYCLE.to_string(),
                        features::REPUTATION.to_string(),
                    ],
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn test_fork_config_validation() {
        let mut fork = ForkConfig {
            fork_id: 1,
            name: "x".to_string(),
            activation_height: 0,
            guest_hash: guest_hash(1),
            min_proof_system: 1,
            features: vec![],
        };
        assert!(fork.validate().is_ok());

        fork.name = String::new();
        assert!(fork.validate().is_err());
        fork.name = "x".to_string();

        fork.min_proof_system = 0;
        assert!(fork.validate().is_err());
        fork.min_proof_system = 1;

        fork.guest_hash = H256::default();
        assert!(fork.validate().is_err());
        fork.guest_hash = guest_hash(1);

        fork.features = vec![String::new()];
        assert!(fork.validate().is_err());
    }

    #[test]
    fn test_schedule_requires_genesis_at_zero() {
        let fork = ForkConfig {
            fork_id: 1,
            name: "x".to_string(),
            activation_height: 50,
            guest_hash: guest_hash(1),
            min_proof_system: 1,
            features: vec![],
        };
        let result = ForkSchedule::new(1, vec![fork]);
        assert!(result.is_err());
    }

    #[test]
    fn test_schedule_rejects_empty() {
        assert!(ForkSchedule::new(1, vec![]).is_err());
    }

    #[test]
    fn test_schedule_rejects_same_height() {
        let forks = vec![
            ForkConfig {
                fork_id: 1,
                name: "a".to_string(),
                activation_height: 0,
                guest_hash: guest_hash(1),
                min_proof_system: 1,
                features: vec![],
            },
            ForkConfig {
                fork_id: 2,
                name: "b".to_string(),
                activation_height: 0,
                guest_hash: guest_hash(2),
                min_proof_system: 1,
                features: vec![],
            },
        ];
        assert!(ForkSchedule::new(1, forks).is_err());
    }

    #[test]
    fn test_schedule_rejects_non_increasing_ids() {
        let forks = vec![
            ForkConfig {
                fork_id: 2,
                name: "a".to_string(),
                activation_height: 0,
                guest_hash: guest_hash(1),
                min_proof_system: 1,
                features: vec![],
            },
            ForkConfig {
                fork_id: 1,
                name: "b".to_string(),
                activation_height: 50,
                guest_hash: guest_hash(2),
                min_proof_system: 1,
                features: vec![],
            },
        ];
        assert!(ForkSchedule::new(1, forks).is_err());
    }

    #[test]
    fn test_schedule_sorts_by_height() {
        let schedule = ForkSchedule::new(
            1,
            vec![
                ForkConfig {
                    fork_id: 3,
                    name: "c".to_string(),
                    activation_height: 200,
                    guest_hash: guest_hash(3),
                    min_proof_system: 2,
                    features: vec![],
                },
                ForkConfig {
                    fork_id: 1,
                    name: "a".to_string(),
                    activation_height: 0,
                    guest_hash: guest_hash(1),
                    min_proof_system: 1,
                    features: vec![],
                },
                ForkConfig {
                    fork_id: 2,
                    name: "b".to_string(),
                    activation_height: 100,
                    guest_hash: guest_hash(2),
                    min_proof_system: 2,
                    features: vec![],
                },
            ],
        )
        .unwrap();
        assert_eq!(schedule.forks[0].fork_id, 1);
        assert_eq!(schedule.forks[1].fork_id, 2);
        assert_eq!(schedule.forks[2].fork_id, 3);
    }

    #[test]
    fn test_active_fork_at_boundaries() {
        let schedule = test_schedule();

        // Before genesis fork's own height there is nothing (genesis is at 0, so unreachable)
        assert_eq!(schedule.active_fork_at(0).unwrap().fork_id, 1);
        assert_eq!(schedule.active_fork_at(99).unwrap().fork_id, 1);
        // Exact activation boundary switches to the new fork
        assert_eq!(schedule.active_fork_at(100).unwrap().fork_id, 2);
        assert_eq!(schedule.active_fork_at(199).unwrap().fork_id, 2);
        assert_eq!(schedule.active_fork_at(200).unwrap().fork_id, 3);
        assert_eq!(schedule.active_fork_at(1_000_000).unwrap().fork_id, 3);
    }

    #[test]
    fn test_genesis_fork() {
        let schedule = test_schedule();
        assert_eq!(schedule.genesis_fork().fork_id, 1);
        assert_eq!(schedule.genesis_fork().activation_height, 0);
    }

    #[test]
    fn test_approved_guest() {
        let schedule = test_schedule();
        assert!(schedule.is_approved_guest(2, &guest_hash(2)));
        assert!(!schedule.is_approved_guest(2, &guest_hash(1)));
        assert!(!schedule.is_approved_guest(99, &guest_hash(2)));
    }

    #[test]
    fn test_next_fork_after() {
        let schedule = test_schedule();
        assert_eq!(schedule.next_fork_after(0).unwrap().fork_id, 2);
        assert_eq!(schedule.next_fork_after(150).unwrap().fork_id, 3);
        assert!(schedule.next_fork_after(300).is_none());
    }

    #[test]
    fn test_has_feature() {
        let schedule = test_schedule();
        let fork2 = schedule.active_fork_at(100).unwrap();
        assert!(fork2.has_feature(features::TASK_LIFECYCLE));
        assert!(!fork2.has_feature(features::REPUTATION));

        let fork3 = schedule.active_fork_at(200).unwrap();
        assert!(fork3.has_feature(features::REPUTATION));
    }

    fn header(
        number: BlockNumber,
        fork_id: u64,
        guest: GuestHash,
        proof_version: u32,
    ) -> BlockHeader {
        BlockHeader {
            number,
            parent_hash: H256::default(),
            timestamp: number,
            tx_root: H256::default(),
            state_root: StateRoot::new(H256::default(), H256::default()),
            da_ref: H256::default(),
            fork_id,
            guest_hash: guest,
            proof_system_version: proof_version,
            proof: Some(Proof {
                proof_data: vec![],
                proof_type: crate::types::ProofType::ZkVm,
            }),
        }
    }

    #[test]
    fn test_validate_header_fork_ok() {
        let schedule = test_schedule();
        let h = header(150, 2, guest_hash(2), 2);
        assert!(validate_header_fork(&h, &schedule).is_ok());
    }

    #[test]
    fn test_validate_header_fork_wrong_fork_id() {
        let schedule = test_schedule();
        let h = header(150, 1, guest_hash(2), 2);
        assert!(validate_header_fork(&h, &schedule).is_err());
    }

    #[test]
    fn test_validate_header_fork_wrong_guest() {
        let schedule = test_schedule();
        let h = header(150, 2, guest_hash(1), 2);
        assert!(validate_header_fork(&h, &schedule).is_err());
    }

    #[test]
    fn test_validate_header_fork_proof_too_low() {
        let schedule = test_schedule();
        let h = header(150, 2, guest_hash(2), 1);
        assert!(validate_header_fork(&h, &schedule).is_err());
    }

    #[test]
    fn test_validate_header_fork_unknown_height() {
        // Hand-constructed (invalid) schedule where no fork is active at height 50.
        // Defensive path: validate_header_fork must reject rather than panic.
        let schedule = ForkSchedule {
            chain_id: 1,
            forks: vec![ForkConfig {
                fork_id: 1,
                name: "a".to_string(),
                activation_height: 100,
                guest_hash: guest_hash(1),
                min_proof_system: 1,
                features: vec![],
            }],
        };
        let h = header(50, 1, guest_hash(1), 1);
        assert!(validate_header_fork(&h, &schedule).is_err());
    }

    #[test]
    fn test_noop_hook() {
        let schedule = test_schedule();
        let hook = NoopForkHook;
        assert!(hook
            .on_activation(schedule.active_fork_at(100).unwrap(), 100)
            .is_ok());
    }

    #[test]
    fn test_deterministic_resolution() {
        // Same inputs -> same output, repeatedly (pure function)
        let schedule = test_schedule();
        for _ in 0..100 {
            assert_eq!(schedule.active_fork_at(150).unwrap().fork_id, 2);
            assert_eq!(schedule.active_fork_at(50).unwrap().fork_id, 1);
        }
    }
}
