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

pub(crate) mod authz;
pub mod handlers;

pub use handlers::{
    derive_bundle, derive_guide, derive_lease, derive_project, derive_submission, derive_task,
    get_active_guide, get_actor, get_bundle, get_guide, get_lease, get_nonce, get_nullifier,
    get_project, get_submission, get_task, AcceptanceRecord, ActorGrantPayload, ActorRecord,
    ActorRegisterPayload, ActorRole, BundleAdmitPayload, BundleRecord, BundleStatus, Capability,
    Grant, GuideActivatePayload, GuideIngestPayload, GuideRecord, LeaseRecord, LeaseStatus,
    NullifierRecord, ProjectCreatePayload, ProjectRecord, ReviewDecidePayload, ReviewDecision,
    ReviewLeasePayload, ReviewRecord, SubmissionCreatePayload, SubmissionIdPayload,
    SubmissionRecord, SubmissionStatus, TaskCreatePayload, TaskIdPayload, TaskRecord,
    TaskReleasePayload, TaskScreenPayload, TaskStatus, NULLIFIER_ACCEPT, NULLIFIER_CLAIM,
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
    /// transactions that are valid for the current state. Execution is atomic:
    /// actions run against an isolated draft of the state, and the shared
    /// state is replaced only when every action succeeds — a mid-transaction
    /// failure discards the draft, so no partial changes leak into live state
    /// while the transaction's nonce stays reusable for a retry. Payload
    /// well-formedness is pre-checked here so malformed payloads abort before
    /// any state mutation.
    pub fn execute_tx(&self, state: &mut State, tx: &Transaction) -> Result<Vec<Event>> {
        debug!("Executing transaction for account {:?}", tx.account);

        // Validate transaction (structural checks: non-empty actions, fee).
        self.tx_validator.validate(tx)?;

        // Replay protection: the nonce sequence must be exactly the next one
        // expected for this (account, key_id). A lower value is a replay of an
        // already-executed transaction; a higher value leaves a gap that would
        // permit out-of-order execution. Both are rejected before any mutation.
        let expected = handlers::get_nonce(state, &tx.account, tx.nonce.key_id)?;
        if tx.nonce.seq != expected {
            return Err(Error::Transaction(format!(
                "nonce mismatch for account {:?} key {}: got seq {}, expected {}",
                tx.account, tx.nonce.key_id, tx.nonce.seq, expected
            )));
        }

        // Pre-check: every action payload must decode for its action type
        for action in &tx.actions {
            self.decode_action_payload(action)?;
        }

        // Execute all actions atomically against an isolated draft. If any
        // action fails, the draft is dropped and the shared state — including
        // the nonce — is left exactly as it was: no partial changes are
        // committed and the transaction's nonce remains reusable.
        let mut draft = state.clone();
        let mut events = Vec::new();
        for (idx, action) in tx.actions.iter().enumerate() {
            debug!("Executing action {}: {:?}", idx, action.action_type);
            let action_events = self.execute_action(&mut draft, tx, action)?;
            events.extend(action_events);
        }

        // All actions succeeded: advance the nonce so this exact transaction can
        // never be replayed. Done last (and only on success) so a failed
        // transaction does not burn its nonce — no DoS via nonce exhaustion.
        let next = expected.checked_add(1).ok_or_else(|| {
            Error::Transaction(format!(
                "nonce exhausted for account {:?} key {}",
                tx.account, tx.nonce.key_id
            ))
        })?;
        handlers::set_nonce(&mut draft, &tx.account, tx.nonce.key_id, next)?;

        // Commit: replace the shared state only after full success.
        *state = draft;
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
            ActionType::GuideIngest => decode::<h::GuideIngestPayload>(action),
            ActionType::GuideActivate => decode::<h::GuideActivatePayload>(action),
            ActionType::TaskCreate => decode::<h::TaskCreatePayload>(action),
            ActionType::TaskScreen => decode::<h::TaskScreenPayload>(action),
            ActionType::TaskRelease => decode::<h::TaskReleasePayload>(action),
            ActionType::TaskClaim | ActionType::TaskStart => decode::<h::TaskIdPayload>(action),
            ActionType::SubmissionCreate => decode::<h::SubmissionCreatePayload>(action),
            ActionType::BundleAdmit => decode::<h::BundleAdmitPayload>(action),
            ActionType::ReviewLease => decode::<h::ReviewLeasePayload>(action),
            ActionType::ReviewDecide => decode::<h::ReviewDecidePayload>(action),
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
            ActionType::GuideIngest => handlers::handle_guide_ingest(state, account, payload)?,
            ActionType::GuideActivate => handlers::handle_guide_activate(state, account, payload)?,
            ActionType::TaskCreate => handlers::handle_task_create(state, account, payload)?,
            ActionType::TaskScreen => handlers::handle_task_screen(state, account, payload)?,
            ActionType::TaskRelease => handlers::handle_task_release(state, account, payload)?,
            ActionType::TaskClaim => handlers::handle_task_claim(state, account, payload)?,
            ActionType::TaskStart => handlers::handle_task_start(state, account, payload)?,
            ActionType::SubmissionCreate => {
                handlers::handle_submission_create(state, account, payload)?
            }
            ActionType::BundleAdmit => handlers::handle_bundle_admit(state, account, payload)?,
            ActionType::ReviewLease => handlers::handle_review_lease(state, account, payload)?,
            ActionType::ReviewDecide => handlers::handle_review_decide(state, account, payload)?,
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

    /// Hands out strictly-increasing nonces per account so tests build valid,
    /// replay-free transactions without manual bookkeeping. A fresh book models
    /// a fresh chain (every account starts at seq 0).
    #[derive(Default)]
    struct NonceBook {
        map: std::collections::HashMap<AccountId, u64>,
    }

    impl NonceBook {
        fn next(&mut self, acct: AccountId) -> u64 {
            let seq = *self.map.get(&acct).unwrap_or(&0);
            self.map.insert(acct, seq + 1);
            seq
        }
    }

    /// Build a transaction with an explicit (key_id, seq) nonce. Used by the
    /// nonce-specific tests that need precise control over the sequence value.
    fn raw_tx(
        acct: AccountId,
        key_id: u16,
        seq: u64,
        t: ActionType,
        payload: Vec<u8>,
    ) -> Transaction {
        TxBuilder::new()
            .chain_id(1)
            .account(acct)
            .nonce(key_id, seq)
            .add_action(t, payload)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap()
    }

    /// Build a transaction with the next valid nonce for `acct` (key_id 0).
    fn tx(book: &mut NonceBook, acct: AccountId, t: ActionType, payload: Vec<u8>) -> Transaction {
        raw_tx(acct, 0, book.next(acct), t, payload)
    }

    /// Execute a transaction with the next valid nonce for `acct`.
    ///
    /// The STF does not consume a nonce when execution fails (no DoS via nonce
    /// exhaustion), so on error we roll the book back to stay in sync — a retry
    /// can reuse the same sequence value. Returns the events or the error.
    fn attempt(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        acct: AccountId,
        t: ActionType,
        payload: Vec<u8>,
    ) -> Result<Vec<Event>> {
        let seq = book.next(acct);
        let tx = raw_tx(acct, 0, seq, t, payload);
        match stf.execute_tx(state, &tx) {
            Ok(events) => Ok(events),
            Err(e) => {
                *book.map.get_mut(&acct).unwrap() = seq; // nonce not consumed on failure
                Err(e)
            }
        }
    }

    /// Execute a transaction and return its events (panics on error).
    fn run(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        acct: AccountId,
        t: ActionType,
        payload: Vec<u8>,
    ) -> Vec<Event> {
        attempt(stf, state, book, acct, t, payload).unwrap()
    }

    fn register_payload(role: ActorRole) -> Vec<u8> {
        encode_payload(&ActorRegisterPayload { role }).unwrap()
    }

    fn grant_payload(grantee: AccountId, capability: Capability) -> Vec<u8> {
        encode_payload(&ActorGrantPayload {
            grantee,
            capability,
        })
        .unwrap()
    }

    fn project_payload(title: &str) -> Vec<u8> {
        encode_payload(&ProjectCreatePayload {
            title: title.to_string(),
        })
        .unwrap()
    }

    fn task_payload(project: ProjectId, title: &str, award: u128) -> Vec<u8> {
        encode_payload(&TaskCreatePayload {
            project,
            title: title.to_string(),
            award,
        })
        .unwrap()
    }

    fn id_payload(task: TaskId) -> Vec<u8> {
        encode_payload(&TaskIdPayload { task }).unwrap()
    }

    fn submit_payload(task: TaskId, content: H256) -> Vec<u8> {
        encode_payload(&SubmissionCreatePayload {
            task,
            content_hash: content,
        })
        .unwrap()
    }

    fn submission_payload(submission: SubmissionId) -> Vec<u8> {
        encode_payload(&SubmissionIdPayload { submission }).unwrap()
    }

    fn register(book: &mut NonceBook, acct: AccountId, role: ActorRole) -> Transaction {
        tx(
            book,
            acct,
            ActionType::ActorRegister,
            register_payload(role),
        )
    }

    fn grant(book: &mut NonceBook, to: AccountId, cap: Capability) -> Transaction {
        tx(
            book,
            sponsor(),
            ActionType::ActorGrant,
            grant_payload(to, cap),
        )
    }

    fn create_project(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        acct: AccountId,
    ) -> ProjectId {
        run(
            stf,
            state,
            book,
            acct,
            ActionType::ProjectCreate,
            project_payload(TITLE),
        );
        handlers::derive_project(&acct, TITLE)
    }

    fn create_task(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        acct: AccountId,
        project: ProjectId,
    ) -> TaskId {
        run(
            stf,
            state,
            book,
            acct,
            ActionType::TaskCreate,
            task_payload(project, "task-one", 100),
        );
        handlers::derive_task(&project, "task-one")
    }

    /// Ingest and activate guide v1 for a project from its owner.
    fn setup_active_guide(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        owner: AccountId,
        project: ProjectId,
    ) -> GuideId {
        run(
            stf,
            state,
            book,
            owner,
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        );
        let guide = handlers::derive_guide(&project, 1, &content_hash(1));
        run(
            stf,
            state,
            book,
            owner,
            ActionType::GuideActivate,
            guide_activate_payload(project, guide),
        );
        guide
    }

    /// Screen and release a task from its owner (requires an active guide).
    fn screen_and_release(
        stf: &StateTransitionFunction,
        state: &mut State,
        book: &mut NonceBook,
        owner: AccountId,
        task: TaskId,
    ) {
        run(
            stf,
            state,
            book,
            owner,
            ActionType::TaskScreen,
            screen_payload(task),
        );
        run(
            stf,
            state,
            book,
            owner,
            ActionType::TaskRelease,
            release_payload(task, "ready for pickup"),
        );
    }

    /// Drive the standard setup to the claimable point: both actors
    /// registered, both capabilities granted (sponsor-scoped), project and
    /// guide created, guide activated, task screened and released. The
    /// returned task is `Released` and ready for `TaskClaim`.
    fn setup_task_ready(
        book: &mut NonceBook,
    ) -> (StateTransitionFunction, State, ProjectId, TaskId) {
        let stf = mvp_stf();
        let mut state = State::new();

        // Sponsors + workers
        run(
            &stf,
            &mut state,
            book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        run(
            &stf,
            &mut state,
            book,
            sponsor2(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        run(
            &stf,
            &mut state,
            book,
            worker(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Worker),
        );
        run(
            &stf,
            &mut state,
            book,
            worker2(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Worker),
        );

        // Grant both workers their capabilities (the sponsor issues all grants)
        for grantee in [worker(), worker2()] {
            run(
                &stf,
                &mut state,
                book,
                sponsor(),
                ActionType::ActorGrant,
                grant_payload(grantee, Capability::ClaimWork),
            );
            run(
                &stf,
                &mut state,
                book,
                sponsor(),
                ActionType::ActorGrant,
                grant_payload(grantee, Capability::SubmitWork),
            );
        }

        // Project, guide (ingested + activated), task, screen, release
        let project = create_project(&stf, &mut state, book, sponsor());
        setup_active_guide(&stf, &mut state, book, sponsor(), project);
        let task = create_task(&stf, &mut state, book, sponsor(), project);
        screen_and_release(&stf, &mut state, book, sponsor(), task);
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

    fn claim_tx(book: &mut NonceBook, task: TaskId) -> Transaction {
        tx(book, worker(), ActionType::TaskClaim, id_payload(task))
    }

    fn start_tx(book: &mut NonceBook, task: TaskId) -> Transaction {
        tx(book, worker(), ActionType::TaskStart, id_payload(task))
    }

    fn screen_payload(task: TaskId) -> Vec<u8> {
        encode_payload(&TaskScreenPayload { task }).unwrap()
    }

    fn release_payload(task: TaskId, reason: &str) -> Vec<u8> {
        encode_payload(&TaskReleasePayload {
            task,
            reason: reason.to_string(),
        })
        .unwrap()
    }

    fn submit_tx(book: &mut NonceBook, task: TaskId, content: H256) -> Transaction {
        tx(
            book,
            worker(),
            ActionType::SubmissionCreate,
            submit_payload(task, content),
        )
    }

    fn accept_tx(book: &mut NonceBook, submission: SubmissionId) -> Transaction {
        tx(
            book,
            sponsor(),
            ActionType::AcceptFinal,
            submission_payload(submission),
        )
    }

    /// The reviewer of choice in these tests: a registered worker that is
    /// neither the author (worker) nor the sponsor (who pays).
    fn reviewer() -> AccountId {
        worker2()
    }

    fn bundle_admit_payload(task: TaskId, content: H256) -> Vec<u8> {
        encode_payload(&BundleAdmitPayload {
            task,
            content_hash: content,
        })
        .unwrap()
    }

    fn review_lease_payload(submission: SubmissionId) -> Vec<u8> {
        encode_payload(&ReviewLeasePayload { submission }).unwrap()
    }

    fn review_decide_payload(submission: SubmissionId, decision: ReviewDecision) -> Vec<u8> {
        encode_payload(&ReviewDecidePayload {
            submission,
            decision,
        })
        .unwrap()
    }

    /// Drive the Started task to a review-gated submission: the assignee
    /// admits its bundle, the submission consumes it, and the reviewer
    /// leases + records an `Accept`. Leaves the submission `Pending` with
    /// `accept_reviews == 1` — ready for `accept.final` by the sponsor.
    fn admit_submit_and_review(
        book: &mut NonceBook,
        stf: &StateTransitionFunction,
        state: &mut State,
        task: TaskId,
        content: H256,
    ) -> SubmissionId {
        // The task's assignee (single-worker flows) admits and submits.
        run(
            stf,
            state,
            book,
            worker(),
            ActionType::BundleAdmit,
            bundle_admit_payload(task, content),
        );
        run(
            stf,
            state,
            book,
            worker(),
            ActionType::SubmissionCreate,
            submit_payload(task, content),
        );
        let submission = submission_id(task, content);
        run(
            stf,
            state,
            book,
            reviewer(),
            ActionType::ReviewLease,
            review_lease_payload(submission),
        );
        run(
            stf,
            state,
            book,
            reviewer(),
            ActionType::ReviewDecide,
            review_decide_payload(submission, ReviewDecision::Accept),
        );
        submission
    }

    fn submission_id(task: TaskId, content: H256) -> SubmissionId {
        handlers::derive_submission(&task, &content)
    }

    #[test]
    fn full_happy_path_via_blocks() {
        let stf = mvp_stf();
        let mut state = State::new();
        let initial_root = state.root().hash();
        let mut book = NonceBook::default();

        // Block 0: identity (the reviewer is a third registered actor)
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(&mut book, sponsor(), ActorRole::Sponsor),
                        register(&mut book, worker(), ActorRole::Worker),
                        register(&mut book, reviewer(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 3);
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
                        grant(&mut book, worker(), Capability::ClaimWork),
                        grant(&mut book, worker(), Capability::SubmitWork),
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
                        &mut book,
                        sponsor(),
                        ActionType::ProjectCreate,
                        project_payload(TITLE),
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
                        &mut book,
                        sponsor(),
                        ActionType::TaskCreate,
                        task_payload(project, "task-one", 100),
                    )],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "task.created");
        let task: TaskId = postcard::from_bytes(&events[0].data).unwrap();

        // Block 4: guide ingest + activation (owner preparing screening)
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    4,
                    parent_root,
                    vec![
                        tx(
                            &mut book,
                            sponsor(),
                            ActionType::GuideIngest,
                            guide_ingest_payload(project, 1, content_hash(1)),
                        ),
                        tx(
                            &mut book,
                            sponsor(),
                            ActionType::GuideActivate,
                            guide_activate_payload(project, {
                                handlers::derive_guide(&project, 1, &content_hash(1))
                            }),
                        ),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "guide.ingested");
        assert_eq!(events[1].event_type, "guide.activated");

        // Block 5: screen + release (task becomes claimable)
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    5,
                    parent_root,
                    vec![
                        tx(
                            &mut book,
                            sponsor(),
                            ActionType::TaskScreen,
                            screen_payload(task),
                        ),
                        tx(
                            &mut book,
                            sponsor(),
                            ActionType::TaskRelease,
                            release_payload(task, "ready for pickup"),
                        ),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "task.screened");
        assert_eq!(events[1].event_type, "task.released");
        let screened = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(
            screened.screened_under,
            Some(handlers::derive_guide(&project, 1, &content_hash(1)))
        );

        // Block 6: claim + start
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    6,
                    parent_root,
                    vec![claim_tx(&mut book, task), start_tx(&mut book, task)],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "task.claimed");
        assert_eq!(events[1].event_type, "task.started");
        let task_record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(task_record.status, TaskStatus::Started);
        assert_eq!(task_record.assignee, Some(worker()));

        // Block 7: bundle admission + submission (submission consumes the
        // bundle atomically)
        let submission = submission_id(task, content_hash(9));
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    7,
                    parent_root,
                    vec![
                        tx(
                            &mut book,
                            worker(),
                            ActionType::BundleAdmit,
                            bundle_admit_payload(task, content_hash(9)),
                        ),
                        submit_tx(&mut book, task, content_hash(9)),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "bundle.admitted");
        assert_eq!(events[1].event_type, "submission.created");
        let (sub_id, sub_task, bundle_id): (SubmissionId, TaskId, H256) =
            postcard::from_bytes(&events[1].data).unwrap();
        assert_eq!(sub_id, submission);
        assert_eq!(sub_task, task);
        assert_eq!(
            handlers::derive_bundle(&task, &worker(), &content_hash(9)),
            bundle_id
        );
        let sub_record = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        assert_eq!(sub_record.status, SubmissionStatus::Pending);
        assert_eq!(sub_record.task, task);
        assert_eq!(sub_record.accept_reviews, 0);
        // The bundle is consumed: a second submission cannot reuse it.
        let bundle_record = handlers::get_bundle(&state, &bundle_id).unwrap().unwrap();
        assert_eq!(bundle_record.status, BundleStatus::Consumed);

        // Block 8: review lease + decision (Accept gates the payout)
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    8,
                    parent_root,
                    vec![
                        tx(
                            &mut book,
                            reviewer(),
                            ActionType::ReviewLease,
                            review_lease_payload(submission),
                        ),
                        tx(
                            &mut book,
                            reviewer(),
                            ActionType::ReviewDecide,
                            review_decide_payload(submission, ReviewDecision::Accept),
                        ),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "review.leased");
        assert_eq!(events[1].event_type, "review.decided");
        let sub_record = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        assert_eq!(sub_record.accept_reviews, 1);

        // Block 9: accept final => MMR record + completed state
        let parent_root = state.root().hash();
        let events = stf
            .execute_block(
                &mut state,
                &mvp_block(9, parent_root, vec![accept_tx(&mut book, submission)]),
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "accept.finalized");
        let (_, _, record_index): (SubmissionId, TaskId, u64) =
            postcard::from_bytes(&events[0].data).unwrap();
        assert_eq!(record_index, 1); // the review records live in the MMR too

        let task_record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(task_record.status, TaskStatus::Completed);
        let sub_record = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        assert_eq!(sub_record.status, SubmissionStatus::Accepted);
        assert_eq!(state.mmr.size(), 2); // 1 review + 1 acceptance record

        // Final root differs from start and is deterministic
        assert_ne!(state.root().hash(), initial_root);
    }

    #[test]
    fn deterministic_replay() {
        // Two independent executions of the identical op sequence against the
        // same schedule must yield identical roots and events (no drift).
        let stf = mvp_stf();
        let mut state = State::new();
        let mut book = NonceBook::default();
        let _ = stf
            .execute_block(
                &mut state,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(&mut book, sponsor(), ActorRole::Sponsor),
                        register(&mut book, worker(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        let events_a = stf
            .execute_tx(
                &mut state,
                &grant(&mut book, worker(), Capability::ClaimWork),
            )
            .unwrap();
        let root_a = state.root().hash();

        let stf2 = mvp_stf();
        let mut state2 = State::new();
        let mut book2 = NonceBook::default();
        let _ = stf2
            .execute_block(
                &mut state2,
                &mvp_block(
                    0,
                    H256::ZERO,
                    vec![
                        register(&mut book2, sponsor(), ActorRole::Sponsor),
                        register(&mut book2, worker(), ActorRole::Worker),
                    ],
                ),
            )
            .unwrap();
        let events_b = stf2
            .execute_tx(
                &mut state2,
                &grant(&mut book2, worker(), Capability::ClaimWork),
            )
            .unwrap();
        let root_b = state2.root().hash();

        assert_eq!(root_a, root_b);
        assert_eq!(events_a.len(), events_b.len());
    }

    #[test]
    fn register_twice_rejected() {
        let mut book = NonceBook::default();
        let (stf, mut state, ..) = setup_task_ready(&mut book);
        let result = stf.execute_tx(
            &mut state,
            &register(&mut book, sponsor(), ActorRole::Sponsor),
        );
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)), "got {err:?}");
    }

    #[test]
    fn worker_cannot_create_project() {
        let mut state = State::new();
        let stf = mvp_stf();
        let mut book = NonceBook::default();
        stf.execute_tx(
            &mut state,
            &register(&mut book, worker(), ActorRole::Worker),
        )
        .unwrap();
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::ProjectCreate,
            project_payload(TITLE),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn non_owner_sponsor_cannot_create_task() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, _) = setup_task_ready(&mut book);
        // sponsor2 did not create the project
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::TaskCreate,
            task_payload(project, "hostile", 1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn claim_requires_capability() {
        let mut state = State::new();
        let stf = mvp_stf();
        let mut book = NonceBook::default();
        stf.execute_tx(
            &mut state,
            &register(&mut book, sponsor(), ActorRole::Sponsor),
        )
        .unwrap();
        stf.execute_tx(
            &mut state,
            &register(&mut book, worker2(), ActorRole::Worker),
        )
        .unwrap();

        let project = create_project(&stf, &mut state, &mut book, sponsor());
        setup_active_guide(&stf, &mut state, &mut book, sponsor(), project);
        let task = create_task(&stf, &mut state, &mut book, sponsor(), project);
        screen_and_release(&stf, &mut state, &mut book, sponsor(), task);

        // worker2 has NO granted abilities
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker2(),
            ActionType::TaskClaim,
            id_payload(task),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        // task still Released (untouched by the rejected claim)
        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.status, TaskStatus::Released);
    }

    #[test]
    fn claim_nonexistent_task_fails() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, _) = setup_task_ready(&mut book);
        let ghost = H256::from_bytes([9u8; 32]);
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::TaskClaim,
            id_payload(ghost),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn claim_twice_single_assignee() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();

        // second worker with the capability, but the task is now claimed
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker2(),
            ActionType::TaskClaim,
            id_payload(task),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));
        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.assignee, Some(worker()));
    }

    #[test]
    fn start_requires_assignee() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();

        // worker2 starts => not the assignee
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker2(),
            ActionType::TaskStart,
            id_payload(task),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn submit_requires_started_task_and_right_worker() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();

        // not started yet — fails at the handler stage, so worker's nonce is NOT consumed
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::SubmissionCreate,
            submit_payload(task, content_hash(1)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));

        // started, but submitted by a worker that is not the assignee
        stf.execute_tx(&mut state, &start_tx(&mut book, task))
            .unwrap();
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker2(),
            ActionType::SubmissionCreate,
            submit_payload(task, content_hash(1)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn accept_requires_sponsor_and_pending_submission() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();
        stf.execute_tx(&mut state, &start_tx(&mut book, task))
            .unwrap();
        let submission =
            admit_submit_and_review(&mut book, &stf, &mut state, task, content_hash(1));

        // a different sponsor cannot accept (not the task sponsor)
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::AcceptFinal,
            submission_payload(submission),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // the sponsor accepts; a second accept is invalid
        stf.execute_tx(&mut state, &accept_tx(&mut book, submission))
            .unwrap();
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::AcceptFinal,
            submission_payload(submission),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));

        let record = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(record.status, TaskStatus::Completed);
        assert_eq!(state.mmr.size(), 2); // 1 review + 1 acceptance record
    }

    #[test]
    fn malformed_payload_aborts_without_state_change() {
        let mut state = State::new();
        let stf = mvp_stf();
        let root_before = state.root();
        // Same nonce (seq 0) both times: a failed transaction must not consume
        // its nonce, so the retry still reaches the decode stage.
        let bad = raw_tx(sponsor(), 0, 0, ActionType::ActorRegister, vec![0xff]);
        let err = stf.execute_tx(&mut state, &bad).unwrap_err();
        assert!(matches!(err, Error::Serialization(_)));
        assert_eq!(state.root(), root_before, "no state mutation before decode");
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 0);
        assert!(stf.execute_tx(&mut state, &bad).is_err());
    }

    #[test]
    fn failed_multi_action_tx_leaves_no_partial_changes() {
        let stf = mvp_stf();
        let mut state = State::new();
        let root_before = state.root();

        // A two-action transaction whose first action succeeds and second
        // fails: registering the same account twice. Atomic execution must
        // discard the draft on failure — no actor record may leak into live
        // state while the nonce stays reusable for a retry.
        let bad = TxBuilder::new()
            .chain_id(1)
            .account(sponsor())
            .nonce(0, 0)
            .add_action(
                ActionType::ActorRegister,
                register_payload(ActorRole::Sponsor),
            )
            .add_action(
                ActionType::ActorRegister,
                register_payload(ActorRole::Sponsor),
            )
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();

        let err = stf.execute_tx(&mut state, &bad).unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)), "got {err:?}");
        assert_eq!(
            state.root(),
            root_before,
            "failed tx must not commit partial changes"
        );
        assert!(handlers::get_actor(&state, &sponsor()).unwrap().is_none());
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 0);

        // The nonce was never burned: a clean single-action retry succeeds.
        let retry = raw_tx(
            sponsor(),
            0,
            0,
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        stf.execute_tx(&mut state, &retry).unwrap();
        assert!(handlers::get_actor(&state, &sponsor()).unwrap().is_some());
    }

    #[test]
    fn unsupported_action_rejected() {
        let mut book = NonceBook::default();
        let (stf, mut state, ..) = setup_task_ready(&mut book);
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::AwardFulfill,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, Error::Transaction(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("not enabled in the MVP era"), "got {msg}");
    }

    // -----------------------------------------------------------------------
    // Nonce enforcement (issue #20): replay protection, gap rejection, and
    // per-(account, key_id) independence. These use explicit nonces so they
    // exercise exact sequence values rather than the auto-incrementing book.
    // -----------------------------------------------------------------------

    #[test]
    fn replay_same_nonce_rejected() {
        let stf = mvp_stf();
        let mut state = State::new();

        // First use of seq 0 succeeds and advances the stored nonce to 1.
        let first = raw_tx(
            sponsor(),
            0,
            0,
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        stf.execute_tx(&mut state, &first).unwrap();
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 1);
        let root_after = state.root().hash();

        // Replaying the identical transaction (same seq) is rejected before any
        // mutation — this is the replay-protection guarantee.
        let err = stf.execute_tx(&mut state, &first).unwrap_err();
        assert!(matches!(err, Error::Transaction(_)), "got {err:?}");
        assert!(
            format!("{err}").contains("nonce"),
            "expected a nonce error, got {err}"
        );
        assert_eq!(
            state.root().hash(),
            root_after,
            "rejected replay must not mutate state"
        );
    }

    #[test]
    fn future_nonce_gap_rejected() {
        let stf = mvp_stf();
        let mut state = State::new();

        // Skipping ahead (seq 3 when seq 0 is expected) leaves a gap that would
        // allow out-of-order execution — reject it.
        let err = stf
            .execute_tx(
                &mut state,
                &raw_tx(
                    sponsor(),
                    0,
                    3,
                    ActionType::ActorRegister,
                    register_payload(ActorRole::Sponsor),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Transaction(_)), "got {err:?}");
        assert!(
            format!("{err}").contains("nonce"),
            "expected a nonce error, got {err}"
        );
        // No actor was created and the nonce was not advanced.
        assert!(handlers::get_actor(&state, &sponsor()).unwrap().is_none());
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 0);
    }

    #[test]
    fn nonce_increments_after_success() {
        let stf = mvp_stf();
        let mut state = State::new();

        // seq 0 → stored becomes 1
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                0,
                0,
                ActionType::ActorRegister,
                register_payload(ActorRole::Sponsor),
            ),
        )
        .unwrap();
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 1);

        // seq 1 → stored becomes 2 (the next expected value is always last-used + 1)
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                0,
                1,
                ActionType::ProjectCreate,
                project_payload(TITLE),
            ),
        )
        .unwrap();
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 2);

        // The exact next value is accepted; anything else is not.
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                0,
                2,
                ActionType::TaskCreate,
                task_payload(handlers::derive_project(&sponsor(), TITLE), "t", 1),
            ),
        )
        .unwrap();
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 3);
    }

    #[test]
    fn independent_accounts_share_seq() {
        let stf = mvp_stf();
        let mut state = State::new();

        // Two distinct accounts each start at seq 0 — they do not interfere.
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                0,
                0,
                ActionType::ActorRegister,
                register_payload(ActorRole::Sponsor),
            ),
        )
        .unwrap();
        stf.execute_tx(
            &mut state,
            &raw_tx(
                worker(),
                0,
                0,
                ActionType::ActorRegister,
                register_payload(ActorRole::Worker),
            ),
        )
        .unwrap();

        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 1);
        assert_eq!(handlers::get_nonce(&state, &worker(), 0).unwrap(), 1);
    }

    #[test]
    fn independent_key_ids() {
        let stf = mvp_stf();
        let mut state = State::new();

        // key_id 0 and key_id 1 are tracked independently for the same account.
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                0,
                0,
                ActionType::ActorRegister,
                register_payload(ActorRole::Sponsor),
            ),
        )
        .unwrap();
        // A different key starts its own sequence at seq 0.
        stf.execute_tx(
            &mut state,
            &raw_tx(
                sponsor(),
                1,
                0,
                ActionType::ProjectCreate,
                project_payload(TITLE),
            ),
        )
        .unwrap();

        assert_eq!(handlers::get_nonce(&state, &sponsor(), 0).unwrap(), 1);
        assert_eq!(handlers::get_nonce(&state, &sponsor(), 1).unwrap(), 1);
    }

    // -----------------------------------------------------------------------
    // Nullifiers (issue #21): one-time actions are committed to a permanent
    // set independent of the mutable status machines.
    // -----------------------------------------------------------------------

    #[test]
    fn claim_nullifier_is_bound_once_with_audit_details() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, task) = setup_task_ready(&mut book);

        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();

        // The audit record names the family, the target id, and the claimant.
        let record = handlers::get_nullifier(&state, handlers::NULLIFIER_CLAIM, &task)
            .unwrap()
            .expect("claim must bind its nullifier");
        assert_eq!(record.family, handlers::NULLIFIER_CLAIM.to_vec());
        assert_eq!(record.target, task);
        assert_eq!(record.by, worker());

        // Domain separation: other families and other targets were not
        // consumed by this action.
        assert!(
            handlers::get_nullifier(&state, handlers::NULLIFIER_ACCEPT, &task)
                .unwrap()
                .is_none()
        );
        assert!(
            handlers::get_nullifier(&state, handlers::NULLIFIER_CLAIM, &project)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn second_claim_rejected_without_state_change() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();
        let root_after_claim = state.root();

        // worker2 holds the same ClaimWork capability. The status machine
        // rejects here, with the nullifier backing it up (see the
        // regression tests below for the nullifier-only paths).
        let second = tx(
            &mut book,
            worker2(),
            ActionType::TaskClaim,
            id_payload(task),
        );
        let err = stf.execute_tx(&mut state, &second).unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));
        assert_eq!(
            state.root(),
            root_after_claim,
            "rejected claim must not mutate state"
        );
        assert_eq!(
            handlers::get_task(&state, &task).unwrap().unwrap().assignee,
            Some(worker())
        );
    }

    /// Out-of-band rewrite of a task record, simulating a (hypothetical)
    /// future bug or migration that reverts status fields.
    fn regress_task(
        state: &mut State,
        task: TaskId,
        status: TaskStatus,
        assignee: Option<AccountId>,
    ) {
        let mut record = handlers::get_task(state, &task).unwrap().unwrap();
        record.status = status;
        record.assignee = assignee;
        handlers::store_task(state, task, &record).unwrap();
    }

    #[test]
    fn claim_nullifier_survives_status_regression() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();

        // Revert the task to its pre-claim shape, bypassing the handlers:
        // the status machine alone would now accept a claim.
        regress_task(&mut state, task, TaskStatus::Released, None);

        // The nullifier set — not the status field — is the last line of
        // defense: the second claim still fails.
        let retry = tx(
            &mut book,
            worker2(),
            ActionType::TaskClaim,
            id_payload(task),
        );
        let err = stf.execute_tx(&mut state, &retry).unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref msg) if msg.contains("nullifier")),
            "expected the nullifier check, got {err:?}"
        );
        assert!(
            handlers::get_task(&state, &task)
                .unwrap()
                .unwrap()
                .assignee
                .is_none(),
            "the nullifier rejection must not mutate the task"
        );
    }

    #[test]
    fn accept_nullifier_survives_status_regression() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);
        stf.execute_tx(&mut state, &claim_tx(&mut book, task))
            .unwrap();
        stf.execute_tx(&mut state, &start_tx(&mut book, task))
            .unwrap();
        let submission =
            admit_submit_and_review(&mut book, &stf, &mut state, task, content_hash(1));
        stf.execute_tx(&mut state, &accept_tx(&mut book, submission))
            .unwrap();
        let mmr_size = state.mmr.size();

        // Out-of-band revert of both the submission and the task, making
        // the status machine accept again. The acceptance nullifier must
        // refuse the payout's re-execution regardless.
        let mut regressed = handlers::get_submission(&state, &submission)
            .unwrap()
            .unwrap();
        regressed.status = SubmissionStatus::Pending;
        handlers::store_submission(&mut state, submission, &regressed).unwrap();
        regress_task(&mut state, task, TaskStatus::Started, Some(worker()));

        // Baseline for the no-mutation check: after the out-of-band
        // reverts, before the rejected re-acceptance.
        let root_before_retry = state.root();

        let re_accept = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::AcceptFinal,
            submission_payload(submission),
        )
        .unwrap_err();
        assert!(
            matches!(re_accept, Error::InvalidTransition(ref msg) if msg.contains("nullifier")),
            "expected the nullifier check, got {re_accept:?}"
        );
        assert_eq!(
            state.root(),
            root_before_retry,
            "rejected re-acceptance must not mutate state"
        );
        assert_eq!(
            state.mmr.size(),
            mmr_size,
            "the immutable acceptance trail grows only on real acceptance"
        );

        // The audit record exists exactly once, attributed to the sponsor.
        let record = handlers::get_nullifier(&state, handlers::NULLIFIER_ACCEPT, &submission)
            .unwrap()
            .expect("acceptance must bind its nullifier");
        assert_eq!(record.family, handlers::NULLIFIER_ACCEPT.to_vec());
        assert_eq!(record.target, submission);
        assert_eq!(record.by, sponsor());
    }

    // -----------------------------------------------------------------------
    // Authorization (issue #22): role gating, sponsor-scoped grants, and
    // the actor-record invariants behind them.
    // -----------------------------------------------------------------------

    /// An account with no actor record may execute nothing: every handler
    /// begins by resolving the actor through the policy gate.
    #[test]
    fn unregistered_account_denied_every_action() {
        let mut book = NonceBook::default();
        let mut state = State::new();
        let stf = mvp_stf();

        // A real worker record is needed so grant payloads resolve past the
        // payload stage; the *caller* stays unregistered.
        run(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Worker),
        );

        let stranger = || H256::from_bytes([0xE1; 32]);
        // Note: ActorRegister is intentionally NOT on this list — it is
        // the open entry point into the identity layer.
        let cases: Vec<(ActionType, Vec<u8>)> = vec![
            (
                ActionType::ActorGrant,
                grant_payload(worker(), Capability::ClaimWork),
            ),
            (ActionType::ProjectCreate, project_payload("stranger-p")),
            (
                ActionType::TaskCreate,
                task_payload(H256::from_bytes([1; 32]), "t", 1),
            ),
            (ActionType::TaskClaim, id_payload(H256::from_bytes([2; 32]))),
            (ActionType::TaskStart, id_payload(H256::from_bytes([2; 32]))),
            (
                ActionType::SubmissionCreate,
                submit_payload(H256::from_bytes([2; 32]), content_hash(9)),
            ),
            (
                ActionType::AcceptFinal,
                submission_payload(H256::from_bytes([3; 32])),
            ),
        ];
        for (i, (action, payload)) in cases.into_iter().enumerate() {
            // Modeled as sequential attempts from one unknown account: the
            // first failure exposes its nonce (the STF does not burn
            // nonces on failure), so each attempt reuses seq 0.
            let tx = raw_tx(stranger(), 0, 0, action, payload);
            let err = stf.execute_tx(&mut state, &tx).unwrap_err();
            assert!(
                matches!(err, Error::NotFound(_) | Error::Unauthorized(_)),
                "case {i} ({action:?}) denied: expected NotFound/Unauthorized, got {err:?}"
            );
        }

        // Nothing was created for the stranger: no actor, no nonce burn.
        assert!(handlers::get_actor(&state, &stranger()).unwrap().is_none());
        assert_eq!(handlers::get_nonce(&state, &stranger(), 0).unwrap(), 0);
    }

    #[test]
    fn sponsor_denies_worker_actions_and_holds_no_grants() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, task) = setup_task_ready(&mut book);

        // A sponsor cannot perform worker actions.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskClaim,
            id_payload(task),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(ref m) if m.contains("Worker")));
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskStart,
            id_payload(task),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::SubmissionCreate,
            submit_payload(task, content_hash(3)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // Invariant: an actor record can only carry grants from the
        // worker-only grant path — the sponsor's record stays empty.
        assert!(handlers::get_actor(&state, &sponsor())
            .unwrap()
            .unwrap()
            .grants
            .is_empty());
        let _ = project;
    }

    #[test]
    fn worker_denies_sponsor_actions() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, task) = setup_task_ready(&mut book);

        // Grants flow only from sponsors.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::ActorGrant,
            grant_payload(worker2(), Capability::ClaimWork),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // Projects and tasks are sponsor territory.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::ProjectCreate,
            project_payload("worker-p"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::TaskCreate,
            task_payload(H256::from_bytes([1; 32]), "t", 1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
        let _ = task;
    }

    #[test]
    fn grant_is_sponsor_scoped() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, task) = setup_task_ready(&mut book);

        // A third worker, granted ClaimWork by sponsor2 ONLY — it holds no
        // grant from the task's sponsor at all.
        let worker3 = H256::from_bytes([0xE2; 32]);
        run(
            &stf,
            &mut state,
            &mut book,
            worker3,
            ActionType::ActorRegister,
            register_payload(ActorRole::Worker),
        );
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::ActorGrant,
            grant_payload(worker3, Capability::ClaimWork),
        );

        // Claiming the sponsor()-owned task must be refused even though
        // worker3 generally holds the ClaimWork capability.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker3,
            ActionType::TaskClaim,
            id_payload(task),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Unauthorized(ref m) if m.contains("granted by")),
            "expected sponsor-scoping denial, got {err:?}"
        );

        // The same worker CAN claim a task owned by its own grantor.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::ProjectCreate,
            project_payload("sponsor-two"),
        );
        let project2 = handlers::derive_project(&sponsor2(), "sponsor-two");
        setup_active_guide(&stf, &mut state, &mut book, sponsor2(), project2);
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::TaskCreate,
            task_payload(project2, "beta-task", 77),
        );
        let task2 = handlers::derive_task(&project2, "beta-task");
        screen_and_release(&stf, &mut state, &mut book, sponsor2(), task2);
        run(
            &stf,
            &mut state,
            &mut book,
            worker3,
            ActionType::TaskClaim,
            id_payload(task2),
        );
        assert_eq!(
            handlers::get_task(&state, &task2)
                .unwrap()
                .unwrap()
                .assignee,
            Some(worker3)
        );

        // The existing sponsor/worker flow is unaffected.
        run(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::TaskClaim,
            id_payload(task),
        );
        assert_eq!(
            handlers::get_task(&state, &task).unwrap().unwrap().assignee,
            Some(worker())
        );
        let _ = project;
    }

    #[test]
    fn grant_invariants_sponsor_grantee_and_duplicates() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, _) = setup_task_ready(&mut book);

        // Grantee must be a worker: granting to another sponsor is denied.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorGrant,
            grant_payload(sponsor2(), Capability::ClaimWork),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Unauthorized(ref m) if m.contains("Worker")),
            "expected grantee-role denial, got {err:?}"
        );
        // And the sponsor record remains grant-free (invariant preserved).
        assert!(handlers::get_actor(&state, &sponsor2())
            .unwrap()
            .unwrap()
            .grants
            .is_empty());

        // Duplicate grant from the same sponsor is rejected (setup_task_ready
        // already issued ClaimWork from sponsor()): the capability set does
        // not grow.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorGrant,
            grant_payload(worker(), Capability::ClaimWork),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(_)));
        // ClaimWork (from the setup) + SubmitWork (from the setup): the
        // duplicate attempt added nothing.
        assert_eq!(
            handlers::get_actor(&state, &worker())
                .unwrap()
                .unwrap()
                .grants
                .len(),
            2
        );
    }

    #[test]
    fn grants_record_their_grantor_and_coexist_per_sponsor() {
        let mut book = NonceBook::default();
        let (stf, mut state, _, _) = setup_task_ready(&mut book);

        // A second sponsor may grant the same capability: both grants
        // coexist, each carrying its issuer. (The worker already holds
        // ClaimWork + SubmitWork from sponsor() via the setup, hence 3.)
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::ActorGrant,
            grant_payload(worker(), Capability::ClaimWork),
        );
        let grants = handlers::get_actor(&state, &worker())
            .unwrap()
            .unwrap()
            .grants;
        assert_eq!(grants.len(), 3);
        assert!(grants.contains(&handlers::Grant {
            capability: Capability::ClaimWork,
            grantor: sponsor(),
        }));
        assert!(grants.contains(&handlers::Grant {
            capability: Capability::ClaimWork,
            grantor: sponsor2(),
        }));
        assert!(grants.contains(&handlers::Grant {
            capability: Capability::SubmitWork,
            grantor: sponsor(),
        }));
    }

    // -----------------------------------------------------------------------
    // Guides (issue #23): content-addressed, strictly lineage-ordered
    // project guides with an exactly-one active-version pointer.
    // -----------------------------------------------------------------------

    fn guide_ingest_payload(project: ProjectId, version: u32, content: H256) -> Vec<u8> {
        encode_payload(&GuideIngestPayload {
            project,
            version,
            content_hash: content,
        })
        .unwrap()
    }

    fn guide_activate_payload(project: ProjectId, guide: GuideId) -> Vec<u8> {
        encode_payload(&GuideActivatePayload { project, guide }).unwrap()
    }

    #[test]
    fn guide_lineage_is_strictly_ordered() {
        let mut book = NonceBook::default();
        let stf = mvp_stf();
        let mut state = State::new();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        let project = create_project(&stf, &mut state, &mut book, sponsor());

        // Version 1 first.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        );
        // Version 2 next; version 4 (a skip) is refused.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 2, content_hash(2)),
        );
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 4, content_hash(3)),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref m) if m.contains("must be")),
            "expected version-ordering refusal, got {err:?}"
        );

        // Continuing the chain works: v3 follows v2.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 3, content_hash(4)),
        );
        assert_eq!(
            handlers::latest_guide_version(&state, &project).unwrap(),
            Some(3)
        );

        // A (project, version) pair can never be re-ingested — even with
        // different content.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 2, content_hash(9)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(ref m) if m.contains("must be")));
    }

    #[test]
    fn guide_ingest_requires_project_owner() {
        let mut book = NonceBook::default();
        let stf = mvp_stf();
        let mut state = State::new();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        let project = create_project(&stf, &mut state, &mut book, sponsor());

        // A different sponsor cannot ingest into the project.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(ref m) if m.contains("owner")));

        // A worker can never ingest.
        run(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Worker),
        );
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // The owner can.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        );
    }

    #[test]
    fn guide_activation_flow() {
        let mut book = NonceBook::default();
        let stf = mvp_stf();
        let mut state = State::new();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        let project = create_project(&stf, &mut state, &mut book, sponsor());

        // No active guide exists before the first activation.
        assert_eq!(handlers::get_active_guide(&state, &project).unwrap(), None);

        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 1, content_hash(1)),
        );
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 2, content_hash(2)),
        );
        let v1 = handlers::derive_guide(&project, 1, &content_hash(1));
        let v2 = handlers::derive_guide(&project, 2, &content_hash(2));

        // Activate v1.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideActivate,
            guide_activate_payload(project, v1),
        );
        assert_eq!(
            handlers::get_active_guide(&state, &project).unwrap(),
            Some(v1)
        );

        // A project's guide cannot activate another project's version.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ProjectCreate,
            project_payload("other-project"),
        );
        let other = handlers::derive_project(&sponsor(), "other-project");
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideActivate,
            guide_activate_payload(other, v2),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidTransition(ref m) if m.contains("does not belong")));

        // Re-activation replaces the pointer (still exactly one active).
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideActivate,
            guide_activate_payload(project, v2),
        );
        assert_eq!(
            handlers::get_active_guide(&state, &project).unwrap(),
            Some(v2)
        );

        // An unknown guide id is a NotFound, not a state change.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideActivate,
            guide_activate_payload(project, content_hash(0xEE)),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
        assert_eq!(
            handlers::get_active_guide(&state, &project).unwrap(),
            Some(v2)
        );
    }

    // -----------------------------------------------------------------------
    // Task lifecycle (issue #24): Draft → Screened → Released → Claimed.
    // -----------------------------------------------------------------------

    #[test]
    fn screen_requires_active_guide_and_owner() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, _) = setup_task_ready(&mut book);
        // setup_task_ready ends past screening; create a fresh Draft task
        // on the same project to exercise screening directly.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskCreate,
            task_payload(project, "second-task", 5),
        );
        let draft = handlers::derive_task(&project, "second-task");

        // A non-owner sponsor cannot screen someone else's task.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor2(),
            ActionType::TaskScreen,
            screen_payload(draft),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Unauthorized(ref m) if m.contains("screens")),
            "expected owner refusal, got {err:?}"
        );

        // A worker can never screen (role gate).
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker(),
            ActionType::TaskScreen,
            screen_payload(draft),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));

        // The owner can screen: the draft picks up the active guide stamp.
        let active = handlers::get_active_guide(&state, &project)
            .unwrap()
            .unwrap();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskScreen,
            screen_payload(draft),
        );
        let screened = handlers::get_task(&state, &draft).unwrap().unwrap();
        assert_eq!(screened.status, TaskStatus::Screened);
        assert_eq!(screened.screened_under, Some(active));
    }

    #[test]
    fn screen_requires_project_active_guide() {
        let mut book = NonceBook::default();
        let stf = mvp_stf();
        let mut state = State::new();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        let project = create_project(&stf, &mut state, &mut book, sponsor());
        let task = create_task(&stf, &mut state, &mut book, sponsor(), project);

        // No guide ingested, none active: screening must refuse.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskScreen,
            screen_payload(task),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref m) if m.contains("no active guide")),
            "expected missing-guide refusal, got {err:?}"
        );

        // With the guide active, screening succeeds.
        setup_active_guide(&stf, &mut state, &mut book, sponsor(), project);
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskScreen,
            screen_payload(task),
        );
    }

    #[test]
    fn screening_stamp_is_lineage_pinned() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, task) = setup_task_ready(&mut book);
        let v1 = handlers::derive_guide(&project, 1, &content_hash(1));
        assert_eq!(
            handlers::get_task(&state, &task)
                .unwrap()
                .unwrap()
                .screened_under,
            Some(v1)
        );

        // The owner ships a new guide version and activates it: tasks
        // already past screening keep their original stamp.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideIngest,
            guide_ingest_payload(project, 2, content_hash(2)),
        );
        let v2 = handlers::derive_guide(&project, 2, &content_hash(2));
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::GuideActivate,
            guide_activate_payload(project, v2),
        );
        assert_eq!(
            handlers::get_active_guide(&state, &project).unwrap(),
            Some(v2)
        );
        assert_eq!(
            handlers::get_task(&state, &task)
                .unwrap()
                .unwrap()
                .screened_under,
            Some(v1),
            "an existing task's stamp must not follow re-activations"
        );
    }

    #[test]
    fn release_requires_screened_state_and_reason() {
        let mut book = NonceBook::default();
        let stf = mvp_stf();
        let mut state = State::new();
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::ActorRegister,
            register_payload(ActorRole::Sponsor),
        );
        let project = create_project(&stf, &mut state, &mut book, sponsor());
        setup_active_guide(&stf, &mut state, &mut book, sponsor(), project);
        let task = create_task(&stf, &mut state, &mut book, sponsor(), project);

        // Releasing a Draft (not screened) task is refused.
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskRelease,
            release_payload(task, "ship it"),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref m) if m.contains("not releasable")),
            "expected wrong-state refusal, got {err:?}"
        );

        // Screening then releasing with an empty reason is refused.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskScreen,
            screen_payload(task),
        );
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskRelease,
            release_payload(task, "   "),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref m) if m.contains("non-empty reason")),
            "expected reason validation, got {err:?}"
        );

        // A real reason releases the task.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskRelease,
            release_payload(task, "scope frozen"),
        );
        assert_eq!(
            handlers::get_task(&state, &task).unwrap().unwrap().status,
            TaskStatus::Released
        );
    }

    #[test]
    fn claim_requires_released_status() {
        let mut book = NonceBook::default();
        let (stf, mut state, project, task) = setup_task_ready(&mut book);
        let claimed = handlers::get_task(&state, &task).unwrap().unwrap();
        assert_eq!(claimed.status, TaskStatus::Released);

        // A brand-new draft cannot be claimed even by a fully-empowered
        // worker: the lifecycle gate (not just grants) blocks it.
        run(
            &stf,
            &mut state,
            &mut book,
            sponsor(),
            ActionType::TaskCreate,
            task_payload(project, "draft-only", 5),
        );
        let draft = handlers::derive_task(&project, "draft-only");
        let err = attempt(
            &stf,
            &mut state,
            &mut book,
            worker2(),
            ActionType::TaskClaim,
            id_payload(draft),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidTransition(ref m) if m.contains("not claimable")),
            "expected lifecycle gate, got {err:?}"
        );
        // Draft status preserved.
        assert_eq!(
            handlers::get_task(&state, &draft).unwrap().unwrap().status,
            TaskStatus::Draft
        );
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
        assert_eq!(task.status, TaskStatus::Draft);
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
            .nonce(0, 0)
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
