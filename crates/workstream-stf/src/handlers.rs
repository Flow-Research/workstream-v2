//! Minimal MVP STF handlers (issue #15).
//!
//! Covers the smallest end-to-end flow of the M0.5 milestone:
//! actor register/grant, project create, task create/claim/start,
//! submission create, and final acceptance.
//!
//! Determinism rules:
//! - Ids are derived from domain-tagged hashes of their content
//!   (`derive_*` below), never from clocks or counters in memory.
//! - All state objects are postcard-encoded into the key-value state.
//! - Handlers are pure transitions over `State`; no I/O, no randomness.

use serde::{Deserialize, Serialize};
use workstream_core::hash::{Hash, H256};
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_state::State;

use crate::authz;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const K_ACTOR: &[u8] = b"WS:v1:k:actor:";
const K_PROJECT: &[u8] = b"WS:v1:k:project:";
const K_TASK: &[u8] = b"WS:v1:k:task:";
const K_SUBMISSION: &[u8] = b"WS:v1:k:submission:";
/// Guide versions of a project: documents whose versions carry the
/// project's operating instructions and (via activation) its policies.
const K_GUIDE: &[u8] = b"WS:v1:k:guide:";
/// Per-project pointer to the exactly-one active guide version.
const K_GUIDE_ACTIVE: &[u8] = b"WS:v1:k:guide-active:";
/// Per-project head of the ingested guide version lineage (latest u32).
const K_GUIDE_HEAD: &[u8] = b"WS:v1:k:guide-head:";
/// Per-(account, key_id) replay-protection counter. The stored value is the
/// NEXT expected sequence number for that account/key (0 when unused).
const K_NONCE: &[u8] = b"WS:v1:k:nonce:";
/// Nullifier set: domain-derived commitments recording that a one-time
/// action has been performed, independent of any mutable record status.
const K_NULLIFIER: &[u8] = b"WS:v1:k:nullifier:";

fn kv_key(domain: &[u8], id: &H256) -> Vec<u8> {
    let mut key = domain.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

/// Nonce counter is keyed by both the account and its signing-key id so that
/// distinct keys (e.g. a hot vs. cold key) advance independent sequences.
fn nonce_key(account: &H256, key_id: u16) -> Vec<u8> {
    let mut key = K_NONCE.to_vec();
    key.extend_from_slice(account.as_bytes());
    key.extend_from_slice(&key_id.to_be_bytes());
    key
}

/// Domain tag that separates nullifier derivations from every other hash
/// in the system.
const NULLIFIER_TAG: &[u8] = b"WS:v1:nullifier:";

/// Nullifier family for task claims (`task.claim`): a task can be claimed
/// exactly once — ever — by anyone.
pub const NULLIFIER_CLAIM: &[u8] = b"WS:v1:nf:claim:";

/// Nullifier family for final acceptances (`accept.final`): a submission
/// can be accepted exactly once — ever.
pub const NULLIFIER_ACCEPT: &[u8] = b"WS:v1:nf:accept:";

/// A nullifier is derived from its family and its target id under the
/// system-wide nullifier tag, so two different one-time action types can
/// never collide on the same id.
fn nullifier_hash(family: &[u8], target: &H256) -> H256 {
    Hash::sha256_concat(&[NULLIFIER_TAG, family, target.as_bytes()])
}

/// Nullifier set storage key.
fn nullifier_key(n: &H256) -> Vec<u8> {
    kv_key(K_NULLIFIER, n)
}

// ---------------------------------------------------------------------------
// State records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActorRole {
    Sponsor,
    Worker,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    ClaimWork,
    SubmitWork,
}

/// A capability grant issued to a worker, recording the sponsor that
/// authorized it. The `grantor` scopes the grant: it authorizes work only
/// under the granting sponsor's projects and tasks (see `authz`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub capability: Capability,
    pub grantor: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRecord {
    pub account: AccountId,
    pub role: ActorRole,
    /// Capabilities granted to this actor, each bound to its granting
    /// sponsor. Invariant: non-empty only when `role == Worker` — the
    /// grant path (`actor.grant`) refuses all other targets.
    pub grants: Vec<Grant>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRecord {
    pub owner: AccountId,
    pub title: String,
}

/// One ingested guide version of a project. Guides are content-addressed
/// (the record lives under the version's derived id) and immutable once
/// ingested; activation is tracked by a separate per-project pointer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuideRecord {
    pub project: ProjectId,
    pub version: u32,
    pub content_hash: H256,
    pub ingested_by: AccountId,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    /// Newly created, not yet reviewed by the project owner.
    Draft,
    /// Owner-screened under the project's active guide (stamped).
    Screened,
    /// Screened and released for claiming, with a recorded reason.
    Released,
    Claimed,
    Started,
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    pub project: ProjectId,
    pub sponsor: AccountId,
    pub title: String,
    pub award: u128,
    pub status: TaskStatus,
    pub assignee: Option<AccountId>,
    /// The active guide version stamped by the owner's screening. From
    /// then on the task is lineage-pinned: later re-activations of the
    /// project's guide do NOT move this stamp (see `handle_task_screen`).
    pub screened_under: Option<GuideId>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubmissionStatus {
    Pending,
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub task: TaskId,
    pub author: AccountId,
    pub content_hash: H256,
    pub status: SubmissionStatus,
}

/// The append-only record written to the MMR when a submission is accepted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptanceRecord {
    pub submission: SubmissionId,
    pub task: TaskId,
    pub accepted_by: AccountId,
}

/// The audit record behind a consumed nullifier: which action family
/// burned it, against which target, performed by whom. The stored key is
/// derivable from `family` and `target`; keeping both in the record makes
/// SMT introspection readable without key parsing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierRecord {
    pub family: Vec<u8>,
    pub target: H256,
    pub by: AccountId,
}

// ---------------------------------------------------------------------------
// Action payloads (postcard-encoded inside `Action.payload`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRegisterPayload {
    pub role: ActorRole,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorGrantPayload {
    pub grantee: AccountId,
    pub capability: Capability,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectCreatePayload {
    pub title: String,
}

/// guide.ingest: attach one new, strictly increasing guide version
/// (content-committed) to a project.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuideIngestPayload {
    pub project: ProjectId,
    pub version: u32,
    pub content_hash: H256,
}

/// guide.activate: point a project at one of its ingested guide versions.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuideActivatePayload {
    pub project: ProjectId,
    pub guide: GuideId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskCreatePayload {
    pub project: ProjectId,
    pub title: String,
    pub award: u128,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskIdPayload {
    pub task: TaskId,
}

/// task.screen: owner review of a drafted task, stamping the project's
/// active guide version onto it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskScreenPayload {
    pub task: TaskId,
}

/// task.release: move a screened task to ready, with an audit reason.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskReleasePayload {
    pub task: TaskId,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionCreatePayload {
    pub task: TaskId,
    pub content_hash: H256,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionIdPayload {
    pub submission: SubmissionId,
}

// ---------------------------------------------------------------------------
// Id derivation (deterministic)
// ---------------------------------------------------------------------------

const D_PROJECT: &[u8] = b"WS:v1:id:project:";
const D_TASK: &[u8] = b"WS:v1:id:task:";
const D_SUBMISSION: &[u8] = b"WS:v1:id:submission:";
const D_GUIDE: &[u8] = b"WS:v1:id:guide:";

/// Deterministic project id: H(tag ‖ owner ‖ title).
pub fn derive_project(owner: &H256, title: &str) -> ProjectId {
    Hash::sha256_concat(&[D_PROJECT, owner.as_bytes(), title.as_bytes()])
}

/// Deterministic task id: H(tag ‖ project ‖ title).
pub fn derive_task(project: &H256, title: &str) -> TaskId {
    Hash::sha256_concat(&[D_TASK, project.as_bytes(), title.as_bytes()])
}

/// Deterministic submission id: H(tag ‖ task ‖ content_hash).
pub fn derive_submission(task: &H256, content_hash: &H256) -> SubmissionId {
    Hash::sha256_concat(&[D_SUBMISSION, task.as_bytes(), content_hash.as_bytes()])
}

/// Deterministic guide version id: H(tag ‖ project ‖ version ‖ content_hash).
///
/// Content-addressed: the id commits to the exact version bytes' hash, so
/// a re-ingest of the same version with different content is detectable by
/// id alone.
pub fn derive_guide(project: &H256, version: u32, content_hash: &H256) -> GuideId {
    let version_bytes = version.to_be_bytes();
    Hash::sha256_concat(&[
        D_GUIDE,
        project.as_bytes(),
        &version_bytes,
        content_hash.as_bytes(),
    ])
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn decode_payload<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T> {
    postcard::from_bytes(payload)
        .map_err(|e| Error::Serialization(format!("action payload decode: {e}")))
}

fn load_actor(state: &State, account: &H256) -> Result<ActorRecord> {
    decode_from_state(state, K_ACTOR, account, "actor")?
        .ok_or_else(|| Error::NotFound(format!("actor {}", account)))
}

fn store_actor(state: &mut State, record: &ActorRecord) -> Result<()> {
    let bytes = postcard::to_allocvec(record)
        .map_err(|e| Error::Serialization(format!("actor record encode: {e}")))?;
    state.set(&kv_key(K_ACTOR, &record.account), &bytes)
}

/// Write a task record under its id. Pub(crate) so tests can simulate
/// out-of-band state rewrites (e.g. a hypothetical status-regression bug)
/// when proving nullifier guarantees.
pub(crate) fn store_task(state: &mut State, task: TaskId, record: &TaskRecord) -> Result<()> {
    let bytes = postcard::to_allocvec(record)
        .map_err(|e| Error::Serialization(format!("task record encode: {e}")))?;
    state.set(&kv_key(K_TASK, &task), &bytes)
}

/// Write a submission record under its id (see [`store_task`]).
pub(crate) fn store_submission(
    state: &mut State,
    submission: SubmissionId,
    record: &SubmissionRecord,
) -> Result<()> {
    let bytes = postcard::to_allocvec(record)
        .map_err(|e| Error::Serialization(format!("submission record encode: {e}")))?;
    state.set(&kv_key(K_SUBMISSION, &submission), &bytes)
}

fn event(event_type: &str, data: &[u8]) -> Result<Event> {
    Ok(Event {
        event_type: event_type.to_string(),
        data: data.to_vec(),
        block_number: 0, // patched by execute_block to the real height
        tx_index: 0,     // patched by execute_block to the real index
    })
}

// ---------------------------------------------------------------------------
// Record readers (used by the sequencer #16, node #32, and e2e tests #33)
// ---------------------------------------------------------------------------

fn decode_from_state<T: serde::de::DeserializeOwned>(
    state: &State,
    domain: &[u8],
    id: &H256,
    what: &str,
) -> Result<Option<T>> {
    state
        .get(&kv_key(domain, id))?
        .map(|bytes| {
            postcard::from_bytes::<T>(&bytes)
                .map_err(|e| Error::Serialization(format!("{what} record decode: {e}")))
        })
        .transpose()
}

/// Write a guide version record under its id (see [`store_task`]).
pub(crate) fn store_guide(state: &mut State, guide: GuideId, record: &GuideRecord) -> Result<()> {
    let bytes = postcard::to_allocvec(record)
        .map_err(|e| Error::Serialization(format!("guide record encode: {e}")))?;
    state.set(&kv_key(K_GUIDE, &guide), &bytes)
}

/// The highest ingested guide version of a project (`None` when it has no
/// guides yet). Guide lineage is strictly ordered, so this doubles as the
/// "versions must arrive in order" bookkeeping.
pub(crate) fn latest_guide_version(state: &State, project: &H256) -> Result<Option<u32>> {
    let head_key = {
        let mut key = K_GUIDE_HEAD.to_vec();
        key.extend_from_slice(project.as_bytes());
        key
    };
    match state.get(&head_key)? {
        Some(bytes) => postcard::from_bytes::<u32>(&bytes)
            .map(Some)
            .map_err(|e| Error::Serialization(format!("guide head decode: {e}"))),
        None => Ok(None),
    }
}

/// Advance (or initialize) a project's guide head after a successful
/// ingest. `pub(crate)` like the other store helpers.
pub(crate) fn set_guide_head(state: &mut State, project: &H256, version: u32) -> Result<()> {
    let bytes = postcard::to_allocvec(&version)
        .map_err(|e| Error::Serialization(format!("guide head encode: {e}")))?;
    let mut key = K_GUIDE_HEAD.to_vec();
    key.extend_from_slice(project.as_bytes());
    state.set(&key, &bytes)
}

/// Read an actor record.
pub fn get_actor(state: &State, account: &H256) -> Result<Option<ActorRecord>> {
    decode_from_state(state, K_ACTOR, account, "actor")
}

/// Read a project record.
pub fn get_project(state: &State, project: &H256) -> Result<Option<ProjectRecord>> {
    decode_from_state(state, K_PROJECT, project, "project")
}

/// Read a task record.
pub fn get_task(state: &State, task: &H256) -> Result<Option<TaskRecord>> {
    decode_from_state(state, K_TASK, task, "task")
}

/// Read a submission record.
pub fn get_submission(state: &State, submission: &H256) -> Result<Option<SubmissionRecord>> {
    decode_from_state(state, K_SUBMISSION, submission, "submission")
}

/// Read a guide version record.
pub fn get_guide(state: &State, guide: &H256) -> Result<Option<GuideRecord>> {
    decode_from_state(state, K_GUIDE, guide, "guide")
}

/// Read the active guide version id of a project, if any was activated.
pub fn get_active_guide(state: &State, project: &H256) -> Result<Option<GuideId>> {
    match state.get(&kv_key(K_GUIDE_ACTIVE, project))? {
        Some(bytes) => postcard::from_bytes::<GuideId>(&bytes)
            .map(Some)
            .map_err(|e| Error::Serialization(format!("active guide decode: {e}"))),
        None => Ok(None),
    }
}

/// The next expected sequence number for `(account, key_id)`.
/// Returns 0 when the account has not yet used this key.
pub fn get_nonce(state: &State, account: &H256, key_id: u16) -> Result<u64> {
    match state.get(&nonce_key(account, key_id))? {
        Some(bytes) => postcard::from_bytes::<u64>(&bytes)
            .map_err(|e| Error::Serialization(format!("nonce decode: {e}"))),
        None => Ok(0),
    }
}

/// Persist the next expected sequence number for `(account, key_id)`.
pub(crate) fn set_nonce(state: &mut State, account: &H256, key_id: u16, seq: u64) -> Result<()> {
    let bytes = postcard::to_allocvec(&seq)
        .map_err(|e| Error::Serialization(format!("nonce encode: {e}")))?;
    state.set(&nonce_key(account, key_id), &bytes)
}

/// Read the audit record of a consumed nullifier, if any.
pub fn get_nullifier(
    state: &State,
    family: &[u8],
    target: &H256,
) -> Result<Option<NullifierRecord>> {
    let n = nullifier_hash(family, target);
    match state.get(&nullifier_key(&n))? {
        Some(bytes) => postcard::from_bytes::<NullifierRecord>(&bytes)
            .map(Some)
            .map_err(|e| Error::Serialization(format!("nullifier decode: {e}"))),
        None => Ok(None),
    }
}

/// Atomically check and commit a nullifier for a one-time action.
///
/// The check and its commitment are a single state transition, not two
/// steps a caller could interleave: a handler that follows this pattern
/// cannot bind the same nullifier twice (double action), and cannot bind
/// only under a race-free schedule — this code is deterministic anyway.
///
/// Callers must invoke this only after all semantic checks of the action
/// have passed, so that binding never occurs for an action that then
/// fails (the nullifier is not undoable).
pub(crate) fn bind_nullifier(
    state: &mut State,
    family: &[u8],
    target: &H256,
    by: AccountId,
) -> Result<()> {
    let n = nullifier_hash(family, target);
    if state.get(&nullifier_key(&n))?.is_some() {
        return Err(Error::InvalidTransition(format!(
            "one-time action already performed (nullifier {})",
            n
        )));
    }
    let record = NullifierRecord {
        family: family.to_vec(),
        target: *target,
        by,
    };
    let bytes = postcard::to_allocvec(&record)
        .map_err(|e| Error::Serialization(format!("nullifier encode: {e}")))?;
    state.set(&nullifier_key(&n), &bytes)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// actor.register: create the actor with its role (one-time).
pub(crate) fn handle_actor_register(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: ActorRegisterPayload = decode_payload(payload)?;
    if state.get(&kv_key(K_ACTOR, &account))?.is_some() {
        return Err(Error::InvalidTransition(format!(
            "actor {} already registered",
            account
        )));
    }
    let record = ActorRecord {
        account,
        role: p.role,
        grants: Vec::new(),
    };
    store_actor(state, &record)?;
    event(
        "actor.registered",
        &postcard::to_allocvec(&(p.role, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// actor.grant: a sponsor grants a capability to a worker.
///
/// Grants are sponsor-scoped (issue #22): the record stores the granting
/// sponsor, so the capability authorizes work only under that sponsor's
/// tasks. A different sponsor may grant the same capability again — the
/// grants coexist as separate entries.
pub(crate) fn handle_actor_grant(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: ActorGrantPayload = decode_payload(payload)?;

    let grantor = load_actor(state, &account)?;
    authz::require_sponsor(&grantor, "grant a capability")?;

    let grantee = load_actor(state, &p.grantee)?;
    authz::require_grantable_grantee(&grantee)?;

    let already = grantee
        .grants
        .iter()
        .any(|g| g.capability == p.capability && g.grantor == account);
    if already {
        return Err(Error::InvalidTransition(format!(
            "worker {} already holds {:?} granted by {account}",
            p.grantee, p.capability
        )));
    }
    let mut granted = grantee;
    granted.grants.push(Grant {
        capability: p.capability,
        grantor: account,
    });
    store_actor(state, &granted)?;

    event(
        "actor.granted",
        &postcard::to_allocvec(&(p.grantee, p.capability))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// project.create: a sponsor owns a new project.
pub(crate) fn handle_project_create(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: ProjectCreatePayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "create a project")?;

    let project_id = derive_project(&account, &p.title);
    if state.get(&kv_key(K_PROJECT, &project_id))?.is_some() {
        return Err(Error::InvalidTransition(format!(
            "project already exists (owner {} title {:?})",
            account, p.title
        )));
    }
    let record = ProjectRecord {
        owner: account,
        title: p.title.clone(),
    };
    let bytes = postcard::to_allocvec(&record).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_PROJECT, &project_id), &bytes)?;

    event(
        "project.created",
        &postcard::to_allocvec(&(project_id, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// guide.ingest: the project owner attaches a new guide version.
///
/// Lineage rules (deterministic):
/// - versions strictly increase: the first version of a project is 1 and
///   every later one is previous + 1 (no skips, no re-ordering),
/// - a (project, version) pair is committed once; re-ingesting the same
///   version (with same or different content) is an invalid transition,
/// - the record is immutable once written.
pub(crate) fn handle_guide_ingest(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: GuideIngestPayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "ingest a guide")?;

    let project_bytes = state
        .get(&kv_key(K_PROJECT, &p.project))?
        .ok_or_else(|| Error::NotFound(format!("project {}", p.project)))?;
    let project: ProjectRecord = postcard::from_bytes(&project_bytes)
        .map_err(|e| Error::Serialization(format!("project record decode: {e}")))?;
    if project.owner != account {
        return Err(Error::Unauthorized(
            "only the project owner ingests guides".to_string(),
        ));
    }

    // p.version must be exactly `latest + 1` (1 when none ingested yet).
    let latest = latest_guide_version(state, &p.project)?;
    let expected = match latest {
        None => 1,
        Some(v) => v
            .checked_add(1)
            .ok_or_else(|| Error::InvalidTransition("guide version exhausted".to_string()))?,
    };
    if p.version != expected {
        return Err(Error::InvalidTransition(format!(
            "guide version must be {expected} (project has versions up to {latest:?})"
        )));
    }

    let guide_id = derive_guide(&p.project, p.version, &p.content_hash);
    if state.get(&kv_key(K_GUIDE, &guide_id))?.is_some() {
        return Err(Error::InvalidTransition(
            "guide version already ingested".to_string(),
        ));
    }
    let record = GuideRecord {
        project: p.project,
        version: p.version,
        content_hash: p.content_hash,
        ingested_by: account,
    };
    store_guide(state, guide_id, &record)?;
    set_guide_head(state, &p.project, p.version)?;

    event(
        "guide.ingested",
        &postcard::to_allocvec(&(guide_id, p.project, p.version))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// guide.activate: the project owner points the project at one of its
/// ingested guide versions.
///
/// The "exactly one active guide per project" invariant is enforced by the
/// pointer itself — activation replaces the previous pointer atomically;
/// at most one version is ever active, and none is until first activation.
pub(crate) fn handle_guide_activate(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: GuideActivatePayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "activate a guide")?;

    let project_bytes = state
        .get(&kv_key(K_PROJECT, &p.project))?
        .ok_or_else(|| Error::NotFound(format!("project {}", p.project)))?;
    let project: ProjectRecord = postcard::from_bytes(&project_bytes)
        .map_err(|e| Error::Serialization(format!("project record decode: {e}")))?;
    if project.owner != account {
        return Err(Error::Unauthorized(
            "only the project owner activates guides".to_string(),
        ));
    }

    let guide: GuideRecord = match get_guide(state, &p.guide)? {
        Some(g) => g,
        None => {
            return Err(Error::NotFound(format!("guide {}", p.guide)));
        }
    };
    if guide.project != p.project {
        return Err(Error::InvalidTransition(format!(
            "guide {} does not belong to project {}",
            p.guide, p.project
        )));
    }

    let bytes = postcard::to_allocvec(&p.guide)
        .map_err(|e| Error::Serialization(format!("active guide encode: {e}")))?;
    state.set(&kv_key(K_GUIDE_ACTIVE, &p.project), &bytes)?;

    event(
        "guide.activated",
        &postcard::to_allocvec(&(p.project, p.guide, guide.version))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.create: a sponsor creates a task under a project it owns.
pub(crate) fn handle_task_create(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: TaskCreatePayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "create a task")?;

    let project_bytes = state
        .get(&kv_key(K_PROJECT, &p.project))?
        .ok_or_else(|| Error::NotFound(format!("project {}", p.project)))?;
    let project: ProjectRecord = postcard::from_bytes(&project_bytes)
        .map_err(|e| Error::Serialization(format!("project record decode: {e}")))?;
    if project.owner != account {
        return Err(Error::Unauthorized(
            "only the project owner creates tasks".to_string(),
        ));
    }

    let task_id = derive_task(&p.project, &p.title);
    if state.get(&kv_key(K_TASK, &task_id))?.is_some() {
        return Err(Error::InvalidTransition(format!(
            "task already exists (project {} title {:?})",
            p.project, p.title
        )));
    }
    let record = TaskRecord {
        project: p.project,
        sponsor: account,
        title: p.title.clone(),
        award: p.award,
        status: TaskStatus::Draft,
        assignee: None,
        screened_under: None,
    };
    store_task(state, task_id, &record)?;

    event(
        "task.created",
        &postcard::to_allocvec(&(task_id, p.project))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.screen: the task's sponsor reviews a drafted task against their
/// project's guide.
///
/// Screening is what makes a task claimable-work: it requires an active
/// guide version and stamps that version onto the task. The stamp is
/// lineage-pinned — a later re-activation of the project's guide does not
/// move it — so claimants always know which guide a released task was
/// screened under.
pub(crate) fn handle_task_screen(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: TaskScreenPayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "screen a task")?;

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
    if task.sponsor != account {
        return Err(Error::Unauthorized(
            "only the task's sponsor screens it".to_string(),
        ));
    }
    if task.status != TaskStatus::Draft {
        return Err(Error::InvalidTransition(format!(
            "task {} is not screenable (status {:?})",
            p.task, task.status
        )));
    }

    let guide = get_active_guide(state, &task.project)?.ok_or_else(|| {
        Error::InvalidTransition("task cannot be screened: project has no active guide".to_string())
    })?;
    task.screened_under = Some(guide);
    task.status = TaskStatus::Screened;
    store_task(state, p.task, &task)?;

    event(
        "task.screened",
        &postcard::to_allocvec(&(p.task, guide))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.release: the task's sponsor moves a screened task to ready.
///
/// Rules: only screened tasks can be released, release is always an
/// explicit owner decision (never automatic), and it records a non-empty
/// reason that travels with the task record.
pub(crate) fn handle_task_release(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: TaskReleasePayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "release a task")?;

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
    if task.sponsor != account {
        return Err(Error::Unauthorized(
            "only the task's sponsor releases it".to_string(),
        ));
    }
    if task.status != TaskStatus::Screened {
        return Err(Error::InvalidTransition(format!(
            "task {} is not releasable (status {:?})",
            p.task, task.status
        )));
    }
    if p.reason.trim().is_empty() {
        return Err(Error::InvalidTransition(
            "release requires a non-empty reason".to_string(),
        ));
    }

    task.status = TaskStatus::Released;
    store_task(state, p.task, &task)?;

    event(
        "task.released",
        &postcard::to_allocvec(&(p.task, p.reason.clone()))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.claim: a worker claims a created task, authorized by that task's
/// own sponsor (sponsor-scoped grant — issue #22).
pub(crate) fn handle_task_claim(state: &mut State, account: H256, payload: &[u8]) -> Result<Event> {
    let p: TaskIdPayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_worker(&actor, "claim a task")?;

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;

    // The claim is only valid if the task's own sponsor delegated the
    // ClaimWork capability to this worker — a grant from any other
    // sponsor does not reach this task.
    authz::require_grant(&actor, Capability::ClaimWork, &task.sponsor, "claim a task")?;

    if task.status != TaskStatus::Released || task.assignee.is_some() {
        return Err(Error::InvalidTransition(format!(
            "task {} is not claimable (status {:?})",
            p.task, task.status
        )));
    }

    // One-time claim (issue #21): bind the claim nullifier after all
    // semantic checks and before any mutation. It is independent of the
    // status machine — even a future handler that re-opened a task could
    // not allow a second claim of it.
    bind_nullifier(state, NULLIFIER_CLAIM, &p.task, account)?;

    task.assignee = Some(account);
    task.status = TaskStatus::Claimed;
    store_task(state, p.task, &task)?;

    event(
        "task.claimed",
        &postcard::to_allocvec(&(p.task, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.start: the assigned claimant starts the claimed task.
pub(crate) fn handle_task_start(state: &mut State, account: H256, payload: &[u8]) -> Result<Event> {
    let p: TaskIdPayload = decode_payload(payload)?;

    // Even though the assignee-match below is the real authority, every
    // action routes through the policy: the actor must exist and be a
    // worker (uniform RBAC, issue #22).
    let actor = load_actor(state, &account)?;
    authz::require_worker(&actor, "start a task")?;

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
    if task.assignee != Some(account) {
        return Err(Error::Unauthorized(
            "only the assigned worker starts the task".to_string(),
        ));
    }
    if task.status != TaskStatus::Claimed {
        return Err(Error::InvalidTransition(format!(
            "task {} is not startable (status {:?})",
            p.task, task.status
        )));
    }
    task.status = TaskStatus::Started;
    store_task(state, p.task, &task)?;

    event(
        "task.started",
        &postcard::to_allocvec(&(p.task, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// submission.create: the assigned worker submits finished work, under a
/// `SubmitWork` grant issued by that task's own sponsor (issue #22).
pub(crate) fn handle_submission_create(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: SubmissionCreatePayload = decode_payload(payload)?;

    let author = load_actor(state, &account)?;
    authz::require_worker(&author, "submit work")?;

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;

    authz::require_grant(
        &author,
        Capability::SubmitWork,
        &task.sponsor,
        "submit work",
    )?;

    if task.assignee != Some(account) {
        return Err(Error::Unauthorized(
            "only the assigned worker submits".to_string(),
        ));
    }
    if task.status != TaskStatus::Started {
        return Err(Error::InvalidTransition(format!(
            "task {} is not accepting submissions (status {:?})",
            p.task, task.status
        )));
    }

    let submission_id = derive_submission(&p.task, &p.content_hash);
    if state.get(&kv_key(K_SUBMISSION, &submission_id))?.is_some() {
        return Err(Error::InvalidTransition(
            "submission already exists".to_string(),
        ));
    }
    let record = SubmissionRecord {
        task: p.task,
        author: account,
        content_hash: p.content_hash,
        status: SubmissionStatus::Pending,
    };
    store_submission(state, submission_id, &record)?;

    event(
        "submission.created",
        &postcard::to_allocvec(&(submission_id, p.task))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// accept.final: the task sponsor accepts the pending submission.
///
/// Effects: submission -> Accepted, task -> Completed, and an
/// `AcceptanceRecord` appended to the MMR (the immutable audit record).
///
/// Authority: the accepting account must be a registered sponsor acting
/// as the task's sponsor (identity check below) — payments are authorized
/// by task ownership, not capabilities (issue #22).
pub(crate) fn handle_accept_final(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: SubmissionIdPayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    authz::require_sponsor(&actor, "accept final")?;

    let submission_bytes = state
        .get(&kv_key(K_SUBMISSION, &p.submission))?
        .ok_or_else(|| Error::NotFound(format!("submission {}", p.submission)))?;
    let mut submission: SubmissionRecord = postcard::from_bytes(&submission_bytes)
        .map_err(|e| Error::Serialization(format!("submission record decode: {e}")))?;
    if submission.status != SubmissionStatus::Pending {
        return Err(Error::InvalidTransition(format!(
            "submission {} is not acceptable (status {:?})",
            p.submission, submission.status
        )));
    }

    let task_bytes = state
        .get(&kv_key(K_TASK, &submission.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", submission.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
    if task.sponsor != account {
        return Err(Error::Unauthorized(
            "only the task sponsor accepts final".to_string(),
        ));
    }
    if task.status != TaskStatus::Started {
        return Err(Error::InvalidTransition(format!(
            "task {} is not accepting final (status {:?})",
            submission.task, task.status
        )));
    }

    // One-time acceptance (issue #21): bind the nullifier after all checks
    // and before the MMR append and record updates. A submission can be
    // accepted exactly once — ever — regardless of how the submission or
    // task status machines evolve in future milestones.
    bind_nullifier(state, NULLIFIER_ACCEPT, &p.submission, account)?;

    // The immutable record goes into the MMR first (its hash depends on
    // the ids only, so ordering above is unchanged).
    let record = AcceptanceRecord {
        submission: p.submission,
        task: submission.task,
        accepted_by: account,
    };
    let record_bytes =
        postcard::to_allocvec(&record).map_err(|e| Error::Serialization(e.to_string()))?;
    let record_index = state.append_record(&record_bytes)? as u64;

    submission.status = SubmissionStatus::Accepted;
    store_submission(state, p.submission, &submission)?;

    task.status = TaskStatus::Completed;
    store_task(state, submission.task, &task)?;

    event(
        "accept.finalized",
        &postcard::to_allocvec(&(p.submission, submission.task, record_index))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}
