//! State Transition Function (STF) for WorkStream
//!
//! Deterministic state transition: stf(state, block) -> (new_state, events)
//! All logic must be deterministic - no wall clocks, no network calls, no randomness

use tracing::{debug, info};
use workstream_core::fork::{
    features, validate_header_fork, ForkActivationHook, ForkConfig, ForkSchedule, NoopForkHook,
};
use workstream_core::hash::Hash;
use workstream_core::{types::*, Error, Result};
use workstream_state::State;
use workstream_tx::TxValidator;

pub mod handlers;

pub use handlers::{
    AcceptanceRecord, ActorGrantPayload, ActorRecord, ActorRegisterPayload, ActorRole, Capability,
    ProjectCreatePayload, ProjectRecord, SubmissionCreatePayload, SubmissionIdPayload,
    SubmissionRecord, SubmissionStatus, TaskCreatePayload, TaskIdPayload, TaskRecord, TaskStatus,
};

/// Encode an action payload for inclusion in a transaction.
///
/// Canonical encoding for action payloads is postcard (serde-backed,
/// deterministic), consistent with the serialization policy adopted for all
/// consensus types.
pub fn encode_payload<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(value)
        .map_err(|e| Error::Serialization(format!("action payload encode: {e}")))
}

#[derive(Clone)]
pub struct StateTransitionFunction {
    tx_validator: TxValidator,
    /// Fork schedule governing rule activation by block height.
    /// Consensus-critical: must match on every node/prover.
    fork_schedule: ForkSchedule,
    /// Hook invoked when a fork activates (state migrations etc.)
    activation_hook: std::sync::Arc<dyn ForkActivationHook + Send + Sync>,
}

impl StateTransitionFunction {
    pub fn new() -> Self {
        StateTransitionFunction {
            tx_validator: TxValidator::new(),
            fork_schedule: ForkSchedule::default(),
            activation_hook: std::sync::Arc::new(NoopForkHook),
        }
    }

    /// Build an STF with a specific fork schedule
    pub fn with_schedule(fork_schedule: ForkSchedule) -> Result<Self> {
        fork_schedule.validate()?;
        Ok(StateTransitionFunction {
            tx_validator: TxValidator::new(),
            fork_schedule,
            activation_hook: std::sync::Arc::new(NoopForkHook),
        })
    }

    /// Build an STF with a fork schedule and activation hook.
    /// The hook MUST be deterministic (no clocks, randomness, or I/O).
    pub fn with_schedule_and_hook(
        fork_schedule: ForkSchedule,
        hook: std::sync::Arc<dyn ForkActivationHook + Send + Sync>,
    ) -> Result<Self> {
        fork_schedule.validate()?;
        Ok(StateTransitionFunction {
            tx_validator: TxValidator::new(),
            fork_schedule,
            activation_hook: hook,
        })
    }

    /// The fork schedule this STF enforces
    pub fn fork_schedule(&self) -> &ForkSchedule {
        &self.fork_schedule
    }

    /// Resolve the active fork for a block height (pure function of height + schedule)
    pub fn active_fork_at(&self, height: BlockNumber) -> Option<&ForkConfig> {
        self.fork_schedule.active_fork_at(height)
    }

    /// Execute a single transaction under the given fork context
    ///
    /// Contract: the caller (sequencer #16 / node #32) must only supply
    /// transactions that are valid for the current state. Handlers apply
    /// actions sequentially without rollback; a mid-transaction failure
    /// leaves earlier actions applied and must not occur inside executed
    /// blocks. Payload well-formedness is pre-checked here so malformed
    /// payloads abort before any state mutation.
    pub fn execute_tx(&self, state: &mut State, tx: &Transaction) -> Result<Vec<Event>> {
        debug!("Executing transaction for account {:?}", tx.account);

        // Validate transaction
        self.tx_validator.validate(tx)?;

        // Check nonce (simplified)
        // TODO: Implement nonce tracking

        // Pre-check: every action payload must decode for its action type
        for action in &tx.actions {
            self.decode_action_payload(action)?;
        }

        // Execute all actions atomically
        let mut events = Vec::new();
        for (idx, action) in tx.actions.iter().enumerate() {
            debug!("Executing action {}: {:?}", idx, action.action_type);
            let action_events = self.execute_action(state, tx, action)?;
            events.extend(action_events);
        }

        Ok(events)
    }

    /// Execute a single transaction under an explicit fork context.
    /// Actions requiring features not enabled by `fork` are rejected.
    pub fn execute_tx_with_fork(
        &self,
        state: &mut State,
        tx: &Transaction,
        fork: &ForkConfig,
    ) -> Result<Vec<Event>> {
        // Pre-fork enforcement: reject post-fork actions before activation
        for action in &tx.actions {
            self.check_action_gated(fork, action)?;
        }

        self.execute_tx(state, tx)
    }

    /// Enforce feature gating for a single action
    fn check_action_gated(&self, fork: &ForkConfig, action: &Action) -> Result<()> {
        if let Some(required) = required_feature_for(action.action_type) {
            if !fork.has_feature(required) {
                return Err(Error::Fork(format!(
                    "action {:?} requires feature {:?} not enabled in fork {} ({})",
                    action.action_type, required, fork.fork_id, fork.name
                )));
            }
        }
        Ok(())
    }

    /// Pre-check that an action's payload decodes for its action type.
    fn decode_action_payload(&self, action: &Action) -> Result<()> {
        use handlers as h;
        match action.action_type {
            ActionType::ActorRegister => decode::<h::ActorRegisterPayload>(action),
            ActionType::ActorGrant => decode::<h::ActorGrantPayload>(action),
            ActionType::ProjectCreate => decode::<h::ProjectCreatePayload>(action),
            ActionType::TaskCreate => decode::<h::TaskCreatePayload>(action),
            ActionType::TaskClaim | ActionType::TaskStart => decode::<h::TaskIdPayload>(action),
            ActionType::SubmissionCreate => decode::<h::SubmissionCreatePayload>(action),
            ActionType::AcceptFinal => decode::<h::SubmissionIdPayload>(action),
            // Types without MVP handlers yet: no payload preview is possible;
            // their (not-yet-supported) execution errors below.
            _ => Ok(()),
        }
    }

    /// Execute a single action
    fn execute_action(
        &self,
        state: &mut State,
        tx: &Transaction,
        action: &Action,
    ) -> Result<Vec<Event>> {
        let account = tx.account;
        let payload = action.payload.as_slice();
        let event = match action.action_type {
            ActionType::ActorRegister => handlers::handle_actor_register(state, account, payload)?,
            ActionType::ActorGrant => handlers::handle_actor_grant(state, account, payload)?,
            ActionType::ProjectCreate => handlers::handle_project_create(state, account, payload)?,
            ActionType::TaskCreate => handlers::handle_task_create(state, account, payload)?,
            ActionType::TaskClaim => handlers::handle_task_claim(state, account, payload)?,
            ActionType::TaskStart => handlers::handle_task_start(state, account, payload)?,
            ActionType::SubmissionCreate => {
                handlers::handle_submission_create(state, account, payload)?
            }
            ActionType::AcceptFinal => handlers::handle_accept_final(state, account, payload)?,
            other => {
                return Err(Error::Transaction(format!(
                    "action {:?} is not enabled in the MVP era",
                    other
                )));
            }
        };
        Ok(vec![event])
    }

    /// Execute a full block under fork rules.
    ///
    /// Consensus-critical flow:
    /// 1. Resolve the active fork by block height (no mid-block forks)
    /// 2. Validate the header's fork_id/guest_hash/proof_system_version
    /// 3. Fire the activation hook if this block activates a fork
    /// 4. Execute transactions with per-action feature gating
    pub fn execute_block(&self, state: &mut State, block: &Block) -> Result<Vec<Event>> {
        info!("Executing block #{}", block.header.number);

        // 1. Resolve active fork by height
        let fork = self.active_fork_at(block.header.number).ok_or_else(|| {
            Error::Fork(format!(
                "no active fork for block height {}",
                block.header.number
            ))
        })?;

        // 2. Header validation (rejects unknown fork_id / unapproved guest)
        validate_header_fork(&block.header, &self.fork_schedule)?;

        // 3. Activation hook at the exact boundary, before processing
        if block.header.number == fork.activation_height {
            self.activation_hook
                .on_activation(fork, block.header.number)?;
        }

        // 4. Execute transactions under this fork's rules; stamp each
        //    event with its real block position so event streams are
        //    addressable by (block, index) without recomputing them.
        let mut all_events = Vec::new();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let mut events = self.execute_tx_with_fork(state, tx, fork)?;
            for ev in events.iter_mut() {
                ev.block_number = block.header.number;
                ev.tx_index = tx_idx as TxIndex;
            }
            all_events.extend(events);
        }

        Ok(all_events)
    }
}

/// Decode an action payload as a specific typed payload.
fn decode<T: serde::de::DeserializeOwned>(action: &Action) -> Result<()> {
    postcard::from_bytes::<T>(&action.payload)
        .map(|_| ())
        .map_err(|e| Error::Serialization(format!("action payload decode: {e}")))
}

/// Map an action to the feature flag that gates it, if any.
///
/// Genesis-fork actions (identity, projects, core policy) are ungated.
/// Newer protocol behavior is gated by fork features per the upgrade design.
fn required_feature_for(action: ActionType) -> Option<&'static str> {
    match action {
        ActionType::TaskCreate
        | ActionType::TaskScreen
        | ActionType::TaskRelease
        | ActionType::TaskClaim
        | ActionType::TaskStart => Some(features::TASK_LIFECYCLE),

        ActionType::BundlePrepare
        | ActionType::BundleAdmit
        | ActionType::SubmissionCreate
        | ActionType::CheckRun
        | ActionType::RouteSubmission
        | ActionType::ReviewLease
        | ActionType::ReviewDecide
        | ActionType::RevisionPrepare
        | ActionType::AcceptFinal => Some(features::SUBMISSION_REVIEW),

        ActionType::ReputationProject => Some(features::REPUTATION),

        ActionType::GovUpgrade | ActionType::GovSetSequencer | ActionType::GovSetParameters => {
            Some(features::GOVERNANCE)
        }

        // Genesis-era actions: no feature requirement
        _ => None,
    }
}

impl Default for StateTransitionFunction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience schedule for the MVP era: genesis fork at height 0 enabling
/// `TASK_LIFECYCLE` and `SUBMISSION_REVIEW` so the M0.5 handlers run without
/// waiting on a later fork. Reused by sequencer/node/e2e work in this
/// milestone; its fork_id/name are consensus constants.
pub fn mvp_genesis_schedule() -> Result<ForkSchedule> {
    ForkSchedule::new(
        1,
        vec![ForkConfig {
            fork_id: 1,
            name: "genesis-mvp".to_string(),
            activation_height: 0,
            // Deterministic, constant guest marker for the MVP era.
            guest_hash: Hash::sha256(b"workstream/genesis-mvp/guest"),
            min_proof_system: 1,
            features: vec![
                features::TASK_LIFECYCLE.to_string(),
                features::SUBMISSION_REVIEW.to_string(),
            ],
        }],
    )
}

#[cfg(test)]
mod mvp_handler_tests {
    use super::*;
    use workstream_core::hash::H256;
    use workstream_tx::TxBuilder;

    const TITLE: &str = "alpha";

    fn sponsor() -> AccountId {
        H256::from_bytes([11u8; 32])
    }

    fn worker() -> AccountId {
        H256::from_bytes([22u8; 32])
    }

    fn sponsor2() -> AccountId {
        H256::from_bytes([33u8; 32])
    }

    fn worker2() -> AccountId {
        H256::from_bytes([44u8; 32])
    }

    fn content_hash(b: u8) -> H256 {
        H256::from_bytes([b; 32])
    }

    fn mvp_stf() -> StateTransitionFunction {
        StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap()
    }

    fn tx(acct: AccountId, seq: u64, t: ActionType, payload: Vec<u8>) -> Transaction {
        TxBuilder::new()
            .chain_id(1)
            .account(acct)
            .nonce(0, seq)
            .add_action(t, payload)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap()
    }

    fn register(acct: AccountId, role: ActorRole) -> Transaction {
        let payload = encode_payload(&ActorRegisterPayload { role }).unwrap();
        tx(acct, 0, ActionType::ActorRegister, payload)
    }

    fn grant(to: AccountId, cap: Capability) -> Transaction {
        let payload = encode_payload(&ActorGrantPayload {
            grantee: to,
            capability: cap,
        })
        .unwrap();
        tx(sponsor(), 0, ActionType::ActorGrant, payload)
    }

    fn create_project(
        stf: &StateTransitionFunction,
        state: &mut State,
        acct: AccountId,
    ) -> ProjectId {
        let payload = encode_payload(&ProjectCreatePayload {
            title: TITLE.to_string(),
        })
        .unwrap();
        let project_tx = tx(acct, 1, ActionType::ProjectCreate, payload);
        stf.execute_tx(state, &project_tx).unwrap();
        handlers::derive_project(&acct, TITLE)
    }

    fn create_task(
        stf: &StateTransitionFunction,
        state: &mut State,
        acct: AccountId,
        project: ProjectId,
    ) -> TaskId {
        let payload = encode_payload(&TaskCreatePayload {
            project,
            title: "task-one".to_string(),
            award: 100,
        })
        .unwrap();
        let task_tx = tx(acct, 2, ActionType::TaskCreate, payload);
        stf.execute_tx(state, &task_tx).unwrap();
        handlers::derive_task(&project, "task-one")
    }

    fn setup_task_ready() -> (StateTransitionFunction, State, ProjectId, TaskId) {
        let stf = mvp_stf();
        let mut state = State::new();

        // Sponsors + workers
        stf.execute_tx(&mut state, &register(sponsor(), ActorRole::Sponsor))
            .unwrap();
        stf.execute_tx(&mut state, &register(sponsor2(), ActorRole::Sponsor))
            .unwrap();
        stf.execute_tx(&mut state, &register(worker(), ActorRole::Worker))
            .unwrap();
        stf.execute_tx(&mut state, &register(worker2(), ActorRole::Worker))
            .unwrap();

        // Grant the worker capabilities
        stf.execute_tx(&mut state, &grant(worker(), Capability::ClaimWork))
            .unwrap();
        stf.execute_tx(&mut state, &grant(worker(), Capability::SubmitWork))
            .unwrap();
        stf.execute_tx(&mut state, &grant(worker2(), Capability::ClaimWork))
            .unwrap();
        stf.execute_tx(&mut state, &grant(worker2(), Capability::SubmitWork))
            .unwrap();

        // Project + task
        let project = create_project(&stf, &mut state, sponsor());
        let task = create_task(&stf, &mut state, sponsor(), project);
        (stf, state, project, task)
    }

    fn mvp_block(number: BlockNumber, parent: H256, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                number,
                parent_hash: parent,
                timestamp: number * 12,
                tx_root: H256::ZERO,
                state_root: StateRoot::new(H256::ZERO, H256::ZERO),
                da_ref: H256::ZERO,
                fork_id: 1,
                // Must match the guest marker defined in mvp_genesis_schedule()
                guest_hash: Hash::sha256(b"workstream/genesis-mvp/guest"),
                proof_system_version: 1,
                proof: None,
            },
            transactions: txs,
        }
    }

    fn claim_tx(task: TaskId) -> Transaction {
        tx(
            worker(),
            1,
            ActionType::TaskClaim,
            encode_payload(&TaskIdPayload { task }).unwrap(),
        )
    }

    fn start_tx(task: TaskId) -> Transaction {
        tx(
            worker(),
            2,
            ActionType::TaskStart,
            encode_payload(&TaskIdPayload { task }).unwrap(),
        )
    }

    fn submit_tx(task: TaskId, content: H256) -> Transaction {
        tx(
            worker(),
            3,
            ActionType::SubmissionCreate,
            encode_payload(&SubmissionCreatePayload {
                task,
                content_hash: content,
            })
            .unwrap(),
        )
    }

    fn accept_tx(submission: SubmissionId) -> Transaction {
        tx(
            sponsor(),
            3,
            ActionType::AcceptFinal,
            encode_payload(&SubmissionIdPayload { submission }).unwrap(),
        )
    }

    fn submission_id(task: TaskId, content: H256) -> SubmissionId {
        handlers::derive_submission(&task, &content)
    }

    #[test]
    fn full_happy_path_via_blocks() {
        let stf = mvp_stf();
        let mut state = State::new();
        let initial_root = state.root().hash();

        // Block 0: identity
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(sponsor(), ActorRole::Sponsor),
                        register(worker(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(&events[0].event_type, "actor.registered");
        assert_eq!(&events[1].event_type, "actor.registered");
        assert_eq!(events[0].block_number, 0);
        assert_eq!(events[0].tx_index, 0);
        assert_eq!(events[1].tx_index, 1);

        // Block 1: capability grants for the worker
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    1,
                    initial_root,
                    vec![
                        grant(worker(), Capability::ClaimWork),
                        grant(worker(), Capability::SubmitWork),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(&events[0].event_type, "actor.granted");
        assert_eq!(events[1].block_number, 1);
        assert_eq!(events[1].tx_index, 1);
        let root_after_grants = state.root().hash();

        // Block 2: project + task
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    2,
                    root_after_grants,
                    vec![tx(
                        sponsor(),
                        0,
                        ActionType::ProjectCreate,
                        encode_payload(&ProjectCreatePayload {
                            title: TITLE.to_string(),
                        })
                        .unwrap(),
                    )],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "project.created");
        let project: ProjectId = postcard::from_bytes(&events[0].data).unwrap();

        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    3,
                    parent_root,
                    vec![tx(
                        sponsor(),
                        1,
                        ActionType::TaskCreate,
                        encode_payload(&TaskCreatePayload {
                            project,
                            title: "task-one".to_string(),
                            award: 100,
                        })
                        .unwrap(),
                    )],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "task.created");
        let task: TaskId = postcard::from_bytes(&events[0].data).unwrap();

        // Block 3: claim + start
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(4, parent_root, vec![claim_tx(task), start_tx(task)]),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "task.claimed");
        assert_eq!(events[1].event_type, "task.started");
        let task_record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(task_record.status, TaskStatus::Started);
        assert_eq!(task_record.assignee, Some(worker()));

        // Block 4: submission
        let submission = submission_id(task, content_hash(9));
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(5, parent_root, vec![submit_tx(task, content_hash(9))]),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "submission.created");
        let sub_record = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        assert_eq!(sub_record.status, SubmissionStatus::Pending);
        assert_eq!(sub_record.task, task);

        // Block 5: accept final => MMR record + completed state
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(6, parent_root, vec![accept_tx(submission)]),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "accept.finalized");
        let (_, _, record_index): (SubmissionId, TaskId, u64) =
            postcard::from_bytes(&events[0].data).unwrap();
        assert_eq!(record_index, 0);

        let task_record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(task_record.status, TaskStatus::Completed);
        let sub_record = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        assert_eq!(sub_record.status, SubmissionStatus::Accepted);
        assert_eq!(state.mmr.size(), 1); // one immutable acceptance record

        // Final root differs from start and is deterministic
        assert_ne!(state.root().hash(), initial_root);
    }

    #[test]
    fn deterministic_replay() {
        // Two independent executions of the identical op sequence against the
        // same schedule must yield identical roots and events (no drift).
        let stf = mvp_stf();
        let mut state = State::new();
        let _ = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(sponsor(), ActorRole::Sponsor),
                        register(worker(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        let events_a = stf
            .execute_tx(&mut state, &grant(worker(), Capability::ClaimWork))
            .unwrap();
        let root_a = state.root().hash();

        let stf2 = mvp_stf();
        let mut state2 = State::new();
        let _ = stf2
            .execute_block(
                &mut state2,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(sponsor(), ActorRole::Sponsor),
                        register(worker(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        let events_b = stf2
            .execute_tx(&mut state2, &grant(worker(), Capability::ClaimWork))
            .unwrap();
        let root_b = state2.root().hash();

        assert_eq!(root_a, root_b);
        assert_eq!(events_a.len(), events_b.len());
    }

    #[test]
    fn register_twice_rejected() {
        let (stf, mut state, ..) = setup_task_ready();
        let result = stf.execute_tx(&mut state, &register(sponsor(), ActorRole::Sponsor));
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)), "got {err:?}");
    }

    #[test]
    fn worker_cannot_create_project() {
        let mut state = State::new();
        let stf = mvp_stf();
        stf.execute_tx(&mut state, &register(worker(), ActorRole::Worker))
            .unwrap();
        let payload = encode_payload(&ProjectCreatePayload {
            title: TITLE.to_string(),
        })
        .unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(worker(), 1, ActionType::ProjectCreate, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn non_owner_sponsor_cannot_create_task() {
        let (stf, mut state, project, _) = setup_task_ready();
        // sponsor2 did not create the project
        let payload = encode_payload(&TaskCreatePayload {
            project,
            title: "hostile".to_string(),
            award: 1,
        })
        .unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(sponsor2(), 0, ActionType::TaskCreate, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn claim_requires_capability() {
        let mut state = State::new();
        let stf = mvp_stf();
        stf.execute_tx(&mut state, &register(sponsor(), ActorRole::Sponsor))
            .unwrap();
        stf.execute_tx(&mut state, &register(worker2(), ActorRole::Worker))
            .unwrap();

        let project = create_project(&stf, &mut state, sponsor());
        let task = create_task(&stf, &mut state, sponsor(), project);

        // worker2 has NO granted abilities
        let payload = encode_payload(&TaskIdPayload { task }).unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(worker2(), 0, ActionType::TaskClaim, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        // task still Created
        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.status, TaskStatus::Created);
    }

    #[test]
    fn claim_nonexistent_task_fails() {
        let (stf, mut state, _, _) = setup_task_ready();
        let ghost = H256::from_bytes([9u8; 32]);
        let payload = encode_payload(&TaskIdPayload { task: ghost }).unwrap();
        let err = stf
            .execute_tx(&mut state, &tx(worker(), 9, ActionType::TaskClaim, payload))
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn claim_twice_single_assignee() {
        let (stf, mut state, _, task) = setup_task_ready();
        stf.execute_tx(&mut state, &claim_tx(task)).unwrap();

        // second worker with the capability, but the task is now claimed
        let payload = encode_payload(&TaskIdPayload { task }).unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(worker2(), 5, ActionType::TaskClaim, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));
        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.assignee, Some(worker()));
    }

    #[test]
    fn start_requires_assignee() {
        let (stf, mut state, _, task) = setup_task_ready();
        stf.execute_tx(&mut state, &claim_tx(task)).unwrap();

        // worker2 starts => not the assignee
        let payload = encode_payload(&TaskIdPayload { task }).unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(worker2(), 6, ActionType::TaskStart, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn submit_requires_started_task_and_right_worker() {
        let (stf, mut state, _, task) = setup_task_ready();
        stf.execute_tx(&mut state, &claim_tx(task)).unwrap();

        // not started yet
        let err = stf
            .execute_tx(&mut state, &submit_tx(task, content_hash(1)))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));

        // started, but submitted by a worker that is not the assignee
        stf.execute_tx(&mut state, &start_tx(task)).unwrap();
        let payload = encode_payload(&SubmissionCreatePayload {
            task,
            content_hash: content_hash(1),
        })
        .unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(worker2(), 7, ActionType::SubmissionCreate, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn accept_requires_sponsor_and_pending_submission() {
        let (stf, mut state, _, task) = setup_task_ready();
        stf.execute_tx(&mut state, &claim_tx(task)).unwrap();
        stf.execute_tx(&mut state, &start_tx(task)).unwrap();
        stf.execute_tx(&mut state, &submit_tx(task, content_hash(1)))
            .unwrap();
        let submission = submission_id(task, content_hash(1));

        // a different sponsor cannot accept (not the task sponsor)
        let payload = encode_payload(&SubmissionIdPayload { submission }).unwrap();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(sponsor2(), 0, ActionType::AcceptFinal, payload),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // the sponsor accepts; a second accept is invalid
        stf.execute_tx(&mut state, &accept_tx(submission)).unwrap();
        let err = stf
            .execute_tx(&mut state, &accept_tx(submission))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));

        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.status, TaskStatus::Completed);
        assert_eq!(state.mmr.size(), 1);
    }

    #[test]
    fn malformed_payload_aborts_without_state_change() {
        let mut state = State::new();
        let stf = mvp_stf();
        let root_before = state.root();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(sponsor(), 0, ActionType::ActorRegister, vec![0xff]),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Serialization(_)));
        assert_eq!(state.root(), root_before, "no state mutation before decode");
        assert!(stf
            .execute_tx(
                &mut state,
                &tx(sponsor(), 0, ActionType::ActorRegister, vec![0xff])
            )
            .is_err());
    }

    #[test]
    fn unsupported_action_rejected() {
        let (stf, mut state, ..) = setup_task_ready();
        let err = stf
            .execute_tx(
                &mut state,
                &tx(sponsor(), 0, ActionType::ReviewDecide, vec![]),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Transaction(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("not enabled in the MVP era"), "got {msg}");
    }
}

#[cfg(test)]
mod fork_gating_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use workstream_core::fork::GuestHash;
    use workstream_core::hash::{Hash, H256};
    use workstream_tx::TxBuilder;

    fn guest(seed: u8) -> GuestHash {
        Hash::sha256(&[seed; 32])
    }

    fn schedule_with_task_fork() -> ForkSchedule {
        ForkSchedule::new(
            1,
            vec![
                ForkConfig {
                    fork_id: 1,
                    name: "genesis".to_string(),
                    activation_height: 0,
                    guest_hash: guest(1),
                    min_proof_system: 1,
                    features: vec![],
                },
                ForkConfig {
                    fork_id: 2,
                    name: "tasks".to_string(),
                    activation_height: 10,
                    guest_hash: guest(2),
                    min_proof_system: 2,
                    features: vec![features::TASK_LIFECYCLE.to_string()],
                },
            ],
        )
        .unwrap()
    }

    fn make_block(number: u64, fork_id: u64, guest_hash: H256, proof_version: u32) -> Block {
        Block {
            header: BlockHeader {
                number,
                parent_hash: H256::default(),
                timestamp: number,
                tx_root: H256::default(),
                state_root: StateRoot::new(H256::default(), H256::default()),
                da_ref: H256::default(),
                fork_id,
                guest_hash,
                proof_system_version: proof_version,
                proof: None,
            },
            transactions: vec![],
        }
    }

    fn task_tx() -> Transaction {
        let account = H256::from_bytes([7u8; 32]);
        TxBuilder::new()
            .chain_id(1)
            .account(account)
            .nonce(0, 1)
            .add_action(ActionType::TaskCreate, vec![])
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_execute_block_valid_header() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        let block = make_block(5, 1, guest(1), 1);
        assert!(stf.execute_block(&mut state, &block).is_ok());
    }

    #[test]
    fn test_execute_block_rejects_wrong_fork_id() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        // Height 5 is fork 1, but header claims fork 2
        let block = make_block(5, 2, guest(1), 1);
        assert!(stf.execute_block(&mut state, &block).is_err());
    }

    #[test]
    fn test_execute_block_rejects_unapproved_guest() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        let block = make_block(5, 1, guest(9), 1);
        assert!(stf.execute_block(&mut state, &block).is_err());
    }

    #[test]
    fn test_execute_block_rejects_low_proof_system() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        // Fork 2 requires proof_system_version >= 2
        let block = make_block(10, 2, guest(2), 1);
        assert!(stf.execute_block(&mut state, &block).is_err());
    }

    #[test]
    fn test_task_action_gated_before_fork() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();

        // Under fork 1 (genesis), task lifecycle is NOT enabled
        let fork1 = stf.active_fork_at(5).unwrap();
        let tx = task_tx();
        let result = stf.execute_tx_with_fork(&mut state, &tx, fork1);
        assert!(result.is_err());
        match result {
            Err(Error::Fork(msg)) => assert!(msg.contains("task-lifecycle")),
            other => panic!("expected fork error, got {other:?}"),
        }
    }

    #[test]
    fn test_task_action_allowed_after_fork() {
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        let mut state = State::new();
        let sponsor = H256::from_bytes([7u8; 32]);
        let title = "bootstrap";

        // Register the sponsor and create a project under fork 1
        // (identity + projects are genesis-era, ungated).
        let reg_tx = TxBuilder::new()
            .chain_id(1)
            .account(sponsor)
            .nonce(0, 0)
            .add_action(
                ActionType::ActorRegister,
                encode_payload(&ActorRegisterPayload {
                    role: ActorRole::Sponsor,
                })
                .unwrap(),
            )
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();
        stf.execute_tx_with_fork(&mut state, &reg_tx, stf.active_fork_at(5).unwrap())
            .unwrap();

        let project_tx = TxBuilder::new()
            .chain_id(1)
            .account(sponsor)
            .nonce(0, 1)
            .add_action(
                ActionType::ProjectCreate,
                encode_payload(&ProjectCreatePayload {
                    title: title.to_string(),
                })
                .unwrap(),
            )
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();
        let events = stf
            .execute_tx_with_fork(&mut state, &project_tx, stf.active_fork_at(5).unwrap())
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "project.created");

        // Task creation requires the (later) task-lifecycle fork — allowed,
        // and the handler runs for real.
        let project_id = handlers::derive_project(&sponsor, title);
        let task_tx = TxBuilder::new()
            .chain_id(1)
            .account(sponsor)
            .nonce(0, 2)
            .add_action(
                ActionType::TaskCreate,
                encode_payload(&TaskCreatePayload {
                    project: project_id,
                    title: "fix-bug".to_string(),
                    award: 100,
                })
                .unwrap(),
            )
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();

        let fork2 = stf.active_fork_at(10).unwrap();
        assert!(stf
            .execute_tx_with_fork(&mut state, &task_tx, fork2)
            .is_ok());
        let task = handlers::get_task(&state, &handlers::derive_task(&project_id, "fix-bug"))
            .unwrap()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Created);
        assert_eq!(task.award, 100);
    }

    #[test]
    fn test_genesis_actions_not_gated() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        let fork1 = stf.active_fork_at(5).unwrap();

        let account = H256::from_bytes([7u8; 32]);
        let payload = encode_payload(&ActorRegisterPayload {
            role: ActorRole::Worker,
        })
        .unwrap();
        let tx = TxBuilder::new()
            .chain_id(1)
            .account(account)
            .nonce(0, 2)
            .add_action(ActionType::ActorRegister, payload)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();

        assert!(stf.execute_tx_with_fork(&mut state, &tx, fork1).is_ok());
        // The handler executed: the actor record now exists in state.
        assert!(handlers::get_actor(&state, &account).unwrap().is_some());
    }

    struct CountingHook {
        calls: AtomicU32,
    }

    impl ForkActivationHook for CountingHook {
        fn on_activation(&self, _fork: &ForkConfig, _height: u64) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_activation_hook_fires_at_boundary() {
        let hook = Arc::new(CountingHook {
            calls: AtomicU32::new(0),
        });
        let stf = StateTransitionFunction::with_schedule_and_hook(
            schedule_with_task_fork(),
            hook.clone(),
        )
        .unwrap();
        let mut state = State::new();

        // Blocks before activation: no hook call
        stf.execute_block(&mut state, &make_block(9, 1, guest(1), 1))
            .unwrap();
        assert_eq!(hook.calls.load(Ordering::SeqCst), 0);

        // Exact activation height: hook fires once
        stf.execute_block(&mut state, &make_block(10, 2, guest(2), 2))
            .unwrap();
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);

        // After activation: no additional calls
        stf.execute_block(&mut state, &make_block(11, 2, guest(2), 2))
            .unwrap();
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_default_stf_uses_genesis_schedule() {
        let stf = StateTransitionFunction::new();
        assert_eq!(stf.fork_schedule().genesis_fork().fork_id, 1);
        // All heights resolve to the genesis fork
        assert_eq!(stf.active_fork_at(1_000).unwrap().fork_id, 1);
    }

    #[test]
    fn test_fork_resolution_deterministic() {
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        for _ in 0..50 {
            assert_eq!(stf.active_fork_at(5).unwrap().fork_id, 1);
            assert_eq!(stf.active_fork_at(10).unwrap().fork_id, 2);
            assert_eq!(stf.active_fork_at(500).unwrap().fork_id, 2);
        }
    }
}
