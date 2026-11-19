//! Deterministic guest statement for an authenticated STF transition.
//!
//! The private witness contains leaf state data and the fork schedule, not
//! trusted cached tree nodes. The verifier supplies its own claim; no value
//! from the receipt's journal is treated as a trust root.
use crate::{mvp_genesis_schedule, StateTransitionFunction};
use serde::{Deserialize, Serialize};
use workstream_core::fork::ForkSchedule;
use workstream_core::proof::transactions_commitment;
use workstream_core::{Error, Hash, Result, Transaction, H256};
use workstream_state::{State, StateSnapshot};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub before: StateSnapshot,
    pub height: u64,
    pub block_hash: H256,
    pub pre: H256,
    pub post: H256,
    pub transactions: Vec<Transaction>,
    /// Fork rules the guest executes under. Bound by the host before proving;
    /// the guest rebuilds its STF from this schedule.
    pub schedule: ForkSchedule,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub version: u32,
    pub height: u64,
    pub block_hash: H256,
    pub pre: H256,
    pub post: H256,
    pub transactions_hash: H256,
}

/// Ordered, public batch statement. Both the composing guest and its consumer
/// bind the approved leaf image, heights, block identifiers and all roots.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub leaf_image: H256,
    pub blocks: [Claim; 2],
}

impl Pair {
    pub fn validate(&self) -> Result<()> {
        let [a, b] = &self.blocks;
        if a.version != 1
            || b.version != 1
            || a.height == 0
            || a.height.checked_add(1) != Some(b.height)
            || a.post != b.pre
        {
            return Err(Error::InvalidProof(
                "nonconsecutive batch transitions".into(),
            ));
        }
        Ok(())
    }
}

impl Claim {
    pub fn new(
        height: u64,
        block_hash: H256,
        pre: H256,
        post: H256,
        transactions: &[Transaction],
    ) -> Result<Self> {
        Ok(Self {
            version: 1,
            height,
            block_hash,
            pre,
            post,
            transactions_hash: transactions_commitment(transactions)?,
        })
    }
}

pub fn execute(w: Witness) -> Result<Claim> {
    let mut state = State::from_snapshot(w.before)?;
    if w.height == 0 || state.root().hash() != w.pre {
        return Err(Error::InvalidProof(
            "incorrect starting state or height".into(),
        ));
    }
    let stf = StateTransitionFunction::with_schedule(w.schedule)?;
    crate::governance::check_activation(&state, stf.fork_schedule(), w.height)?;
    let fork = stf
        .active_fork_at(w.height)
        .ok_or_else(|| Error::Fork("unknown height".into()))?;
    for tx in &w.transactions {
        if tx.chain_id != stf.fork_schedule().chain_id {
            return Err(Error::Transaction("incorrect chain ID".into()));
        }
        stf.execute_tx_with_fork(&mut state, tx, fork)?;
    }
    if state.root().hash() != w.post {
        return Err(Error::InvalidProof("incorrect resulting state".into()));
    }
    Claim::new(w.height, w.block_hash, w.pre, w.post, &w.transactions)
}

/// Default helper for tests and tooling that do not carry an explicit schedule.
pub fn mvp_witness(
    before: StateSnapshot,
    height: u64,
    transactions: Vec<Transaction>,
) -> Result<Witness> {
    let schedule = mvp_genesis_schedule()?;
    let state = State::from_snapshot(before.clone())?;
    let pre = state.root().hash();
    Ok(Witness {
        before,
        height,
        block_hash: Hash::sha256(b"workstream/default-witness"),
        pre,
        post: pre,
        transactions,
        schedule,
    })
}
