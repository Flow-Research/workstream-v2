//! Authorization policy for the WorkStream STF (issue #22).
//!
//! This module is the **single source of truth** for "who may do what":
//! every handler routes its authorization checks through the functions
//! below, so the RBAC rules live in one auditable place instead of being
//! re-derived (and re-drifted) per handler.
//!
//! The model is deliberately small and deterministic:
//! - an actor has exactly one [`ActorRole`] (`Sponsor` or `Worker`),
//! - a sponsor may issue capability **grants to workers** (`actor.grant`),
//! - each grant records its sponsor, and therefore authorizes work only
//!   under that sponsor's projects and tasks (sponsor scoping — a grant
//!   from sponsor A can never authorize work on sponsor B's task),
//! - sponsor actions (grant/create) require the `Sponsor` role,
//! - worker actions (claim/start/submit) require the `Worker` role plus
//!   the capability granted by the task's own sponsor,
//! - payments/acceptance are authorized by task ownership (identity:
//!   `task.sponsor`), not by capabilities.
//!
//! Consensus safety: all predicates are pure functions of the actor
//! record and the payload/target ids — no clocks, randomness, or I/O.

use workstream_core::hash::H256;
use workstream_core::{Error, Result};

use crate::handlers::{ActorRecord, ActorRole, Capability};

/// Require the actor to hold a specific role.
///
/// Every handler must gate its action with the appropriate role check;
/// `deny` describes the action for error surfacing ("claim task" etc.) so
/// denial messages stay human-readable without leaking policy mechanics.
pub(crate) fn require_role(record: &ActorRecord, role: ActorRole, action: &str) -> Result<()> {
    if record.role != role {
        return Err(Error::Unauthorized(format!(
            "{action} requires the {role:?} role (account holds {role_found:?})",
            role_found = record.role
        )));
    }
    Ok(())
}

/// Require the `Sponsor` role.
pub(crate) fn require_sponsor(record: &ActorRecord, action: &str) -> Result<()> {
    require_role(record, ActorRole::Sponsor, action)
}

/// Require the `Worker` role.
pub(crate) fn require_worker(record: &ActorRecord, action: &str) -> Result<()> {
    require_role(record, ActorRole::Worker, action)
}

/// Require the actor to hold `capability` **granted by `grantor`**.
///
/// Sponsor scoping is the point of this check: capability grants are only
/// valid for work under the granting sponsor's projects and tasks, so
/// task-scoped actions (claim/submit) always pass the *task's* sponsor.
pub(crate) fn require_grant(
    record: &ActorRecord,
    capability: Capability,
    grantor: &H256,
    action: &str,
) -> Result<()> {
    let held = record
        .grants
        .iter()
        .any(|g| g.capability == capability && &g.grantor == grantor);
    if !held {
        return Err(Error::Unauthorized(format!(
            "{action} requires the {capability:?} capability granted by sponsor {grantor}"
        )));
    }
    Ok(())
}

/// A worker may only receive capability grants (never a sponsor).
pub(crate) fn require_grantable_grantee(record: &ActorRecord) -> Result<()> {
    require_role(record, ActorRole::Worker, "receive a capability grant")
}
