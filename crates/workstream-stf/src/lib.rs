//! State Transition Function (STF) for WorkStream
//!
//! Deterministic state transition: stf(state, block) -> (new_state, events)
//! All logic must be deterministic - no wall clocks, no network calls, no randomness

use tracing::{debug, info};
use workstream_core::{types::*, Error, Result};
use workstream_state::State;
use workstream_tx::TxValidator;

#[derive(Clone)]
pub struct StateTransitionFunction {
    tx_validator: TxValidator,
}

impl StateTransitionFunction {
    pub fn new() -> Self {
        StateTransitionFunction {
            tx_validator: TxValidator::new(),
        }
    }

    /// Execute a single transaction
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

    /// Execute a full block
    pub fn execute_block(&self, state: &mut State, block: &Block) -> Result<Vec<Event>> {
        info!("Executing block #{}", block.header.number);
        let mut all_events = Vec::new();

        for tx in &block.transactions {
            let events = self.execute_tx(state, tx)?;
            all_events.extend(events);
        }

        // Update state root would happen here
        Ok(all_events)
    }
}

impl Default for StateTransitionFunction {
    fn default() -> Self {
        Self::new()
    }
}
