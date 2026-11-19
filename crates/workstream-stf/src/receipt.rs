//! Deterministic MVP guest statement. The private witness contains leaf
//! data, not trusted cached tree nodes. The verifier supplies its own claim.
use crate::{mvp_genesis_schedule, StateTransitionFunction};
use serde::{Deserialize, Serialize};
use workstream_core::{Error, Hash, Result, Transaction, H256};
use workstream_state::{State, StateSnapshot};

#[derive(Serialize, Deserialize)]
pub struct Witness {
    pub before: StateSnapshot,
    pub height: u64,
    pub block_hash: H256,
    pub pre: H256,
    pub post: H256,
    pub transactions: Vec<Transaction>,
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

impl Claim {
    pub fn new(
        height: u64,
        block_hash: H256,
        pre: H256,
        post: H256,
        transactions: &[Transaction],
    ) -> Result<Self> {
        let bytes =
            postcard::to_allocvec(transactions).map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(Self {
            version: 1,
            height,
            block_hash,
            pre,
            post,
            transactions_hash: Hash::sha256_concat(&[b"WS:v1:zk-transactions:", &bytes]),
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
    let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule()?)?;
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
