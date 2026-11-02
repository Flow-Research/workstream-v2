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

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const K_ACTOR: &[u8] = b"WS:v1:k:actor:";
const K_PROJECT: &[u8] = b"WS:v1:k:project:";
const K_TASK: &[u8] = b"WS:v1:k:task:";
const K_SUBMISSION: &[u8] = b"WS:v1:k:submission:";

fn kv_key(domain: &[u8], id: &H256) -> Vec<u8> {
    let mut key = domain.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRecord {
    pub account: AccountId,
    pub role: ActorRole,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRecord {
    pub owner: AccountId,
    pub title: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Created,
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

fn event(event_type: &str, data: &[u8]) -> Result<Event> {
    Ok(Event {
        event_type: event_type.to_string(),
        data: data.to_vec(),
        block_number: 0, // patched by execute_block to the real height
        tx_index: 0,     // patched by execute_block to the real index
    })
}

fn is_sponsor(record: &ActorRecord) -> bool {
    record.role == ActorRole::Sponsor
}

fn has_capability(record: &ActorRecord, capability: Capability) -> bool {
    record.capabilities.contains(&capability)
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
        capabilities: Vec::new(),
    };
    store_actor(state, &record)?;
    event(
        "actor.registered",
        &postcard::to_allocvec(&(p.role, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// actor.grant: a sponsor grants a capability to a worker.
pub(crate) fn handle_actor_grant(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: ActorGrantPayload = decode_payload(payload)?;

    let grantor = load_actor(state, &account)?;
    if !is_sponsor(&grantor) {
        return Err(Error::Unauthorized("only sponsors can grant".to_string()));
    }

    let mut grantee = load_actor(state, &p.grantee)?;
    if grantee.role != ActorRole::Worker {
        return Err(Error::InvalidTransition(
            "grants target workers".to_string(),
        ));
    }
    if has_capability(&grantee, p.capability) {
        return Err(Error::InvalidTransition(format!(
            "worker {} already has {:?}",
            p.grantee, p.capability
        )));
    }
    grantee.capabilities.push(p.capability);
    store_actor(state, &grantee)?;

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
    if !is_sponsor(&actor) {
        return Err(Error::Unauthorized(
            "only sponsors create projects".to_string(),
        ));
    }

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

/// task.create: a sponsor creates a task under a project it owns.
pub(crate) fn handle_task_create(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: TaskCreatePayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    if !is_sponsor(&actor) {
        return Err(Error::Unauthorized(
            "only sponsors create tasks".to_string(),
        ));
    }

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
        status: TaskStatus::Created,
        assignee: None,
    };
    let bytes = postcard::to_allocvec(&record).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_TASK, &task_id), &bytes)?;

    event(
        "task.created",
        &postcard::to_allocvec(&(task_id, p.project))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.claim: a worker with the ClaimWork capability claims a created task.
pub(crate) fn handle_task_claim(state: &mut State, account: H256, payload: &[u8]) -> Result<Event> {
    let p: TaskIdPayload = decode_payload(payload)?;

    let actor = load_actor(state, &account)?;
    if actor.role != ActorRole::Worker {
        return Err(Error::Unauthorized("only workers claim tasks".to_string()));
    }
    if !has_capability(&actor, Capability::ClaimWork) {
        return Err(Error::Unauthorized(
            "missing ClaimWork capability".to_string(),
        ));
    }

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let mut task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
    if task.status != TaskStatus::Created || task.assignee.is_some() {
        return Err(Error::InvalidTransition(format!(
            "task {} is not claimable (status {:?})",
            p.task, task.status
        )));
    }
    task.assignee = Some(account);
    task.status = TaskStatus::Claimed;
    let bytes = postcard::to_allocvec(&task).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_TASK, &p.task), &bytes)?;

    event(
        "task.claimed",
        &postcard::to_allocvec(&(p.task, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// task.start: the assigned claimant starts the claimed task.
pub(crate) fn handle_task_start(state: &mut State, account: H256, payload: &[u8]) -> Result<Event> {
    let p: TaskIdPayload = decode_payload(payload)?;

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
    let bytes = postcard::to_allocvec(&task).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_TASK, &p.task), &bytes)?;

    event(
        "task.started",
        &postcard::to_allocvec(&(p.task, account))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}

/// submission.create: the assigned worker submits finished work.
pub(crate) fn handle_submission_create(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: SubmissionCreatePayload = decode_payload(payload)?;

    let author = load_actor(state, &account)?;
    if !has_capability(&author, Capability::SubmitWork) {
        return Err(Error::Unauthorized(
            "missing SubmitWork capability".to_string(),
        ));
    }

    let task_bytes = state
        .get(&kv_key(K_TASK, &p.task))?
        .ok_or_else(|| Error::NotFound(format!("task {}", p.task)))?;
    let task: TaskRecord = postcard::from_bytes(&task_bytes)
        .map_err(|e| Error::Serialization(format!("task record decode: {e}")))?;
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
    let bytes = postcard::to_allocvec(&record).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_SUBMISSION, &submission_id), &bytes)?;

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
pub(crate) fn handle_accept_final(
    state: &mut State,
    account: H256,
    payload: &[u8],
) -> Result<Event> {
    let p: SubmissionIdPayload = decode_payload(payload)?;

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
    let submission_serialized =
        postcard::to_allocvec(&submission).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_SUBMISSION, &p.submission), &submission_serialized)?;

    task.status = TaskStatus::Completed;
    let task_serialized =
        postcard::to_allocvec(&task).map_err(|e| Error::Serialization(e.to_string()))?;
    state.set(&kv_key(K_TASK, &submission.task), &task_serialized)?;

    event(
        "accept.finalized",
        &postcard::to_allocvec(&(p.submission, submission.task, record_index))
            .map_err(|e| Error::Serialization(e.to_string()))?,
    )
}
