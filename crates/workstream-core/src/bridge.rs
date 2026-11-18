//! Bridge: value in/out transfers and escrow / compensation payouts (issue #89).
//!
//! The bridge wraps bridged (external) value into shielded notes escrowed for
//! task workers, and releases those notes when value leaves the rollup (bridge
//! withdrawal) or when a task compensation is paid out (`award.fulfill` mapped
//! onto the escrow pool).
//!
//! Release tracking here is local to this adapter. Canonical note spends
//! are recorded separately by the rollup state transition function.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::hash::{Hash, H256};
use crate::privacy::{Asset, ShieldedNote};
use crate::types::{AccountId, Event, TaskId};
use crate::{Error, Result};

/// Domain tag for task compensation payout escrow derivations.
const PAYOUT_TAG: &[u8] = b"WS:v1:bridge:payout:";

/// An escrowed shielded note awaiting release.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeEscrow {
    pub escrow_id: H256,
    pub asset: Asset,
    pub amount: u128,
    pub recipient: AccountId,
    pub note: ShieldedNote,
    /// Whether the escrowed note has already been spent (released).
    pub spent: bool,
    task: Option<TaskId>,
}

/// Bridge escrow pool: deposits lock value into shielded notes; releases spend
/// them out (bridge withdrawal or task compensation payout).
#[derive(Debug, Default)]
pub struct BridgePool {
    escrows: HashMap<H256, BridgeEscrow>,
    funded_notes: HashSet<H256>,
}

impl BridgePool {
    /// Create a new, empty escrow pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deposit (value in): lock `amount` of `asset` as a shielded note escrow
    /// for `recipient`. Returns the escrow id (the note commitment).
    pub fn deposit(
        &mut self,
        asset: Asset,
        amount: u128,
        recipient: AccountId,
        note: ShieldedNote,
    ) -> Result<H256> {
        if amount == 0 {
            return Err(Error::Validation(
                "bridge deposit must be non-zero".to_string(),
            ));
        }
        let escrow_id = note.commitment();
        self.insert_escrow(BridgeEscrow {
            escrow_id,
            asset,
            amount,
            recipient,
            note,
            spent: false,
            task: None,
        })?;
        Ok(escrow_id)
    }

    /// Deposit (value in) earmarked for a task compensation payout: escrow is
    /// keyed by the deterministic (task, worker, award) payout context. Returns
    /// the escrow id.
    pub fn deposit_task(
        &mut self,
        task: TaskId,
        worker: AccountId,
        award: u128,
        asset: Asset,
        amount: u128,
        note: ShieldedNote,
    ) -> Result<H256> {
        if award != amount || amount == 0 {
            return Err(Error::Validation(
                "task payout deposit must exactly fund a non-zero award".to_string(),
            ));
        }
        let escrow_id = Self::payout_escrow_id(task, worker, award);
        self.insert_escrow(BridgeEscrow {
            escrow_id,
            asset,
            amount,
            recipient: worker,
            note,
            spent: false,
            task: Some(task),
        })?;
        Ok(escrow_id)
    }

    /// Release a withdrawal escrow to `recipient`. Fails closed on unknown escrows,
    /// double releases, and zero-value notes.
    pub fn release(&mut self, escrow_id: H256, recipient: AccountId) -> Result<BridgeEscrow> {
        if self.get(&escrow_id).is_some_and(|e| e.task.is_some()) {
            return Err(Error::Unauthorized(
                "task escrow requires an award payout".into(),
            ));
        }
        self.release_to(escrow_id, recipient)
    }

    fn release_to(&mut self, escrow_id: H256, recipient: AccountId) -> Result<BridgeEscrow> {
        let escrow = self.escrows.get_mut(&escrow_id).ok_or_else(|| {
            Error::NotFound(format!("bridge escrow not found: {}", escrow_id.to_hex()))
        })?;
        if escrow.spent {
            return Err(Error::Validation(format!(
                "bridge escrow already released: {}",
                escrow_id.to_hex()
            )));
        }
        if escrow.recipient != recipient {
            return Err(Error::Unauthorized("escrow recipient mismatch".into()));
        }
        escrow.spent = true;
        Ok(escrow.clone())
    }

    /// Release the escrow backing a task compensation payout to the task's
    /// worker. Corresponds to the `award.fulfilled(task, worker, award)` event
    /// emitted by the STF award fulfillment handler.
    /// The caller must supply an event from a verified, finalized block.
    /// Raw RPC events are not evidence of finality.
    pub fn apply_finalized_award(&mut self, event: &Event) -> Result<BridgeEscrow> {
        if event.event_type != "award.fulfilled" {
            return Err(Error::Validation("expected award.fulfilled".into()));
        }
        let ((task, worker, award), rest) =
            postcard::take_from_bytes::<(TaskId, AccountId, u128)>(&event.data)
                .map_err(|e| Error::Serialization(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::Validation("trailing award event data".into()));
        }
        let escrow_id = Self::payout_escrow_id(task, worker, award);
        self.release_to(escrow_id, worker)
    }

    /// Look up an escrow by id.
    pub fn get(&self, escrow_id: &H256) -> Option<&BridgeEscrow> {
        self.escrows.get(escrow_id)
    }

    /// Number of live escrows.
    pub fn len(&self) -> usize {
        self.escrows.len()
    }

    /// Whether the pool holds no escrows.
    pub fn is_empty(&self) -> bool {
        self.escrows.is_empty()
    }

    fn insert_escrow(&mut self, escrow: BridgeEscrow) -> Result<()> {
        if escrow.asset.id != escrow.note.asset || escrow.amount != escrow.note.amount {
            return Err(Error::Validation("deposit does not match note".into()));
        }
        if self.escrows.contains_key(&escrow.escrow_id) {
            return Err(Error::Validation(format!(
                "bridge escrow already exists: {}",
                escrow.escrow_id.to_hex()
            )));
        }
        if !self.funded_notes.insert(escrow.note.commitment()) {
            return Err(Error::Validation("note already escrowed".into()));
        }
        self.escrows.insert(escrow.escrow_id, escrow);
        Ok(())
    }

    /// Deterministic escrow id for a task compensation payout context
    /// (task, worker, award).
    fn payout_escrow_id(task: TaskId, worker: AccountId, award: u128) -> H256 {
        Hash::sha256_concat(&[
            PAYOUT_TAG,
            task.as_bytes(),
            worker.as_bytes(),
            &award.to_be_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::AssetKind;

    fn asset(kind: AssetKind) -> Asset {
        Asset {
            id: H256::from_bytes([1u8; 32]),
            kind,
        }
    }

    fn worker() -> AccountId {
        AccountId::from_bytes([4u8; 32])
    }

    #[test]
    fn escrow_preserves_value_and_beneficiary_across_deposit_paths() {
        let mut pool = BridgePool::new();
        let token = asset(AssetKind::BridgedStablecoin);
        let note = ShieldedNote::new(token.id, 10, H256::from_bytes([8; 32]));
        let task = H256::from_bytes([5; 32]);
        assert!(pool
            .deposit(token.clone(), 11, worker(), note.clone())
            .is_err());
        assert!(pool
            .deposit_task(task, worker(), 11, token.clone(), 10, note.clone())
            .is_err());
        let id = pool
            .deposit(token.clone(), 10, worker(), note.clone())
            .unwrap();
        assert!(pool.release(id, H256::ZERO).is_err());
        assert!(!pool.get(&id).unwrap().spent);
        pool.release(id, worker()).unwrap();
        assert!(pool
            .deposit_task(task, worker(), 10, token, 10, note)
            .is_err());
    }

    #[test]
    fn bridge_deposit_escrows_shielded_note() {
        let mut pool = BridgePool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);

        let asset = asset(AssetKind::BridgedStablecoin);
        let escrow = ShieldedNote::new(asset.id, 100, H256::from_bytes([7u8; 32]));
        let escrow_id = pool.deposit(asset, 100, worker(), escrow.clone()).unwrap();
        assert_eq!(escrow_id, escrow.commitment());
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&escrow_id).is_some());
        assert!(!pool.get(&escrow_id).unwrap().spent);
    }

    #[test]
    fn bridge_rejects_zero_value_escrow_deposits() {
        let mut pool = BridgePool::new();
        let asset = asset(AssetKind::NativeGas);
        let note = ShieldedNote::new(asset.id, 0, H256::ZERO);
        assert!(pool.deposit(asset, 0, worker(), note).is_err());
    }

    #[test]
    fn bridge_release_spends_escrowed_note_once() {
        let mut pool = BridgePool::new();
        let asset = asset(AssetKind::BridgedStablecoin);
        let note = ShieldedNote::new(asset.id, 100, H256::from_bytes([7u8; 32]));
        let escrow_id = pool.deposit(asset, 100, worker(), note).unwrap();

        let released = pool.release(escrow_id, worker()).unwrap();
        assert!(released.spent);
        assert_eq!(released.recipient, worker());
        assert!(pool.release(escrow_id, worker()).is_err());
    }

    #[test]
    fn bridge_release_fails_closed_on_unknown_escrow() {
        let mut pool = BridgePool::new();
        assert!(pool.release(H256::ZERO, worker()).is_err());
    }

    #[test]
    fn task_compensation_payout_releases_escrow_to_worker() {
        let mut pool = BridgePool::new();
        let task = TaskId::from_bytes([3u8; 32]);
        let worker = AccountId::from_bytes([4u8; 32]);
        let asset = asset(AssetKind::NativeGas);
        let note = ShieldedNote::new(asset.id, 50, H256::from_bytes([8u8; 32]));
        let escrow_id = pool
            .deposit_task(task, worker, 50, asset, 50, note)
            .unwrap();
        assert_eq!(escrow_id, BridgePool::payout_escrow_id(task, worker, 50));

        assert!(pool.release(escrow_id, worker).is_err());
        let event = Event {
            event_type: "award.fulfilled".into(),
            data: postcard::to_allocvec(&(task, worker, 50u128)).unwrap(),
            block_number: 1,
            tx_index: 0,
        };
        let released = pool.apply_finalized_award(&event).unwrap();
        assert!(released.spent);
        assert_eq!(released.recipient, worker);

        assert!(pool.apply_finalized_award(&event).is_err());
    }
}
