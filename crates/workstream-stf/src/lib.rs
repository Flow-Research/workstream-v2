//! State Transition Function (STF) for WorkStream
//!
//! Deterministic state transition: stf(state, block) -> (new_state, events)
//! All logic must be deterministic - no wall clocks, no network calls, no randomness

use tracing::{debug, info};
use workstream_core::fork::{
    features, validate_header_fork, ForkActivationHook, ForkConfig, ForkSchedule, NoopForkHook,
};
use workstream_core::{types::*, Error, Result};
use workstream_state::State;
use workstream_tx::TxValidator;

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
    pub fn execute_tx(&self, state: &mut State, tx: &Transaction) -> Result<Vec<Event>> {
        debug!("Executing transaction for account {:?}", tx.account);

        // Validate transaction
        self.tx_validator.validate(tx)?;

        // Check nonce (simplified)
        // TODO: Implement nonce tracking

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

    /// Execute a single action
    fn execute_action(
        &self,
        state: &mut State,
        tx: &Transaction,
        action: &Action,
    ) -> Result<Vec<Event>> {
        match action.action_type {
            ActionType::ActorRegister => self.handle_actor_register(state, tx, action),
            ActionType::ProjectCreate => self.handle_project_create(state, tx, action),
            ActionType::TaskCreate => self.handle_task_create(state, tx, action),
            ActionType::SubmissionCreate => self.handle_submission_create(state, tx, action),
            ActionType::AcceptFinal => self.handle_accept_final(state, tx, action),
            ActionType::ReviewDecide => self.handle_review_decide(state, tx, action),
            _ => {
                // For unimplemented actions in starter template
                debug!("Action {:?} not yet fully implemented", action.action_type);
                Ok(vec![])
            }
        }
    }

    fn handle_actor_register(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        Ok(vec![])
    }

    fn handle_project_create(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        Ok(vec![])
    }

    fn handle_task_create(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        Ok(vec![])
    }

    fn handle_submission_create(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        Ok(vec![])
    }

    fn handle_accept_final(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        // FinalAcceptance: atomic record + award
        Ok(vec![])
    }

    fn handle_review_decide(
        &self,
        _state: &mut State,
        _tx: &Transaction,
        _action: &Action,
    ) -> Result<Vec<Event>> {
        Ok(vec![])
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

        // 4. Execute transactions under this fork's rules
        let mut all_events = Vec::new();
        for tx in &block.transactions {
            let events = self.execute_tx_with_fork(state, tx, fork)?;
            all_events.extend(events);
        }

        // Update state root would happen here
        Ok(all_events)
    }
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
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();

        // Under fork 2, task lifecycle is enabled
        let fork2 = stf.active_fork_at(10).unwrap();
        let tx = task_tx();
        assert!(stf.execute_tx_with_fork(&mut state, &tx, fork2).is_ok());
    }

    #[test]
    fn test_genesis_actions_not_gated() {
        let mut state = State::new();
        let stf = StateTransitionFunction::with_schedule(schedule_with_task_fork()).unwrap();
        let fork1 = stf.active_fork_at(5).unwrap();

        let account = H256::from_bytes([7u8; 32]);
        let tx = TxBuilder::new()
            .chain_id(1)
            .account(account)
            .nonce(0, 2)
            .add_action(ActionType::ActorRegister, vec![])
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1000,
            })
            .build()
            .unwrap();

        assert!(stf.execute_tx_with_fork(&mut state, &tx, fork1).is_ok());
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
