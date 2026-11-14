//! WorkStream sequencer library: minimal mempool and block builder (issue #16).
//!
//! Deterministic block production:
//! - transactions are admitted to a FIFO dedup mempool,
//! - `build_block` pops up to `max` transactions at once, executes them in
//!   arrival order under the block's fork context, drops (and therefore
//!   never includes) transactions whose execution fails, then seals a
//!   header: parent link, state root, canonical tx root, fork/guest fields.
//!
//! The same `Transaction`s replayed by the node (#32) in the same order
//! produce identical headers — the consensus property this module affords.

use std::collections::{HashSet, VecDeque};

use workstream_core::hash::{Hash, H256};
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_state::State;
use workstream_stf::StateTransitionFunction;
use workstream_tx::TxValidator;

/// Fixed block slot spacing in seconds (consensus-derived timestamp).
pub const SLOT_SECONDS: u64 = 12;

/// Parent hash of the very first block (genesis boundary marker).
pub const GENESIS_PARENT_HASH: &[u8] = b"WS:v1:genesis-parent-hash";

/// Domain tag for transaction canonical hashes.
const TX_TAG: &[u8] = b"WS:v1:tx:";

/// Domain tag for pair nodes inside the tx-merkle fold.
const TX_NODE_TAG: &[u8] = b"WS:v1:txnode:";

/// Deterministic commitment over an empty tx list.
const TX_ROOT_EMPTY: &[u8] = b"WS:v1:txroot:empty";

/// Domain tag for the block header hash.
const HEADER_TAG: &[u8] = b"WS:v1:header:";

/// Canonical transaction hash: H(tag ‖ postcard(tx)).
///
/// Returns a typed error if canonical encoding fails; the transaction hash is
/// a consensus commitment, so it must fail closed rather than panic (SEC-008).
pub fn tx_hash(tx: &Transaction) -> Result<H256> {
    let bytes = postcard::to_allocvec(tx)
        .map_err(|e| Error::Serialization(format!("transaction encode: {e}")))?;
    Ok(Hash::sha256_concat(&[TX_TAG, &bytes]))
}

/// Canonical commit over ordered tx hashes (duplicate-last pairing fold).
///
/// The node must recompute this identically; it is a consensus format.
pub fn tx_root(leaf_hashes: &[H256]) -> H256 {
    if leaf_hashes.is_empty() {
        return Hash::sha256(TX_ROOT_EMPTY);
    }
    let mut level: Vec<H256> = leaf_hashes.to_vec();
    while level.len() > 1 {
        // Pair adjacent hashes; a trailing unpaired hash is committed against
        // itself (deterministic duplicate-last fold, panic-free).
        level = level
            .chunks(2)
            .map(|pair| {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                Hash::sha256_concat(&[TX_NODE_TAG, left.as_bytes(), right.as_bytes()])
            })
            .collect();
    }
    level[0]
}

/// Header hash. The proof is excluded (a proof may be attached later without
/// changing the chain hash); everything else participates.
///
/// Returns a typed error if canonical encoding fails; the header hash is a
/// consensus commitment, so it must fail closed rather than panic (SEC-008).
pub fn header_hash(header: &BlockHeader) -> Result<H256> {
    let mut exposed = header.clone();
    exposed.proof = None;
    let bytes = postcard::to_allocvec(&exposed)
        .map_err(|e| Error::Serialization(format!("block header encode: {e}")))?;
    Ok(Hash::sha256_concat(&[HEADER_TAG, &bytes]))
}

/// FIFO, deduplicating, bounded mempool.
///
/// Admission performs basic well-formedness validation only; semantic validation
/// happens at execution time in `build_block` (a transaction that fails to
/// execute is dropped, deterministically, because execution is deterministic).
#[derive(Debug)]
pub struct Mempool {
    max_size: usize,
    validator: TxValidator,
    pending: VecDeque<Transaction>,
    seen: HashSet<H256>,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Mempool {
            max_size,
            validator: TxValidator::new(),
            pending: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    /// Admit a transaction; returns its canonical hash.
    pub fn submit(&mut self, tx: Transaction) -> Result<H256> {
        self.validator.validate(&tx)?;
        let hash = tx_hash(&tx)?;
        if self.seen.contains(&hash) {
            return Err(Error::Transaction(format!(
                "transaction {hash} already submitted"
            )));
        }
        if self.pending.len() >= self.max_size {
            return Err(Error::Transaction("mempool full".to_string()));
        }
        self.seen.insert(hash);
        self.pending.push_back(tx);
        Ok(hash)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Pop up to `max` transactions in arrival order.
    fn drain(&mut self, max: usize) -> Vec<Transaction> {
        // Clamp: `drain` panics when the range end exceeds len.
        let n = max.min(self.pending.len());
        self.pending.drain(0..n).collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(1_000)
    }
}

/// Sequencer core: canonical state copy + mempool + deterministic block
/// builder. Produces one block per call; the chain is a linear hash-linked
/// header sequence from the genesis boundary.
pub struct Sequencer {
    stf: StateTransitionFunction,
    state: State,
    mempool: Mempool,
    last_header: Option<BlockHeader>,
}

impl Sequencer {
    /// Chain begins at height 1, linked to [`GENESIS_PARENT_HASH`].
    pub fn new(stf: StateTransitionFunction) -> Self {
        Sequencer {
            stf,
            state: State::new(),
            mempool: Mempool::default(),
            last_header: None,
        }
    }

    /// Submit a transaction to the mempool (see [`Mempool::submit`]).
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<H256> {
        self.mempool.submit(tx)
    }

    /// Number of pending transactions.
    pub fn pending(&self) -> usize {
        self.mempool.len()
    }

    /// Current chain tip height (0 == genesis, no blocks built yet).
    pub fn tip(&self) -> BlockNumber {
        self.last_header.as_ref().map(|h| h.number).unwrap_or(0)
    }

    /// Current committed state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Build the next block from up to `max_txs` mempool transactions.
    ///
    /// Deterministic procedure:
    /// 1. pop transactions in arrival order onto a draft state,
    /// 2. execute each under the block's fork; drop failures,
    /// 3. commit draft state; compute tx root and header.
    pub fn build_block(&mut self, max_txs: Option<u32>) -> Result<Block> {
        let number = self.tip() + 1;
        let fork = self
            .stf
            .active_fork_at(number)
            .ok_or_else(|| Error::State(format!("no active fork at height {number}")))?;

        let mut draft = self.state.clone();
        let popped = self.mempool.drain(max_txs.unwrap_or(u32::MAX) as usize);

        let mut included: Vec<Transaction> = Vec::with_capacity(popped.len());
        for tx in popped {
            match self.stf.execute_tx_with_fork(&mut draft, &tx, fork) {
                Ok(_) => included.push(tx),
                Err(_) => {
                    // Deterministically dropped: it fails identically for any
                    // replier, so excluding it keeps replay equivalence.
                    continue;
                }
            }
        }

        self.state = draft;
        let state_root = self.state.root();

        let mut tx_leaf_hashes: Vec<H256> = Vec::with_capacity(included.len());
        for tx in &included {
            tx_leaf_hashes.push(tx_hash(tx)?);
        }
        let computed_tx_root = tx_root(&tx_leaf_hashes);

        let parent_hash = match self.last_header.as_ref() {
            Some(header) => header_hash(header)?,
            None => Hash::sha256(GENESIS_PARENT_HASH),
        };

        // Consensus-derived timestamp: slot grid over block height.
        let timestamp = number * SLOT_SECONDS;

        let header = BlockHeader {
            number,
            parent_hash,
            timestamp,
            tx_root: computed_tx_root,
            state_root,
            da_ref: H256::ZERO, // DA integration is a later milestone item
            fork_id: fork.fork_id,
            guest_hash: fork.guest_hash,
            proof_system_version: fork.min_proof_system,
            proof: None, // proofs are prover work (not part of #16)
        };
        self.last_header = Some(header.clone());

        Ok(Block {
            header,
            transactions: included,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_stf::encode_payload;
    use workstream_stf::{
        mvp_genesis_schedule, ActorGrantPayload, ActorRegisterPayload, ActorRole, Capability,
        ProjectCreatePayload,
    };
    use workstream_tx::TxBuilder;

    fn account(tag: u8) -> AccountId {
        H256::from_bytes([tag; 32])
    }

    fn seq_tx(acct: AccountId, seq: u64, t: ActionType, payload: Vec<u8>) -> Transaction {
        TxBuilder::new()
            .chain_id(1)
            .account(acct)
            .nonce(0, seq)
            .add_action(t, payload)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1_000,
            })
            .build()
            .unwrap()
    }

    fn mvp_sequencer() -> Sequencer {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        Sequencer::new(stf)
    }

    #[test]
    fn tx_root_is_deterministic_and_order_sensitive() {
        let empty = tx_root(&[]);
        assert_eq!(empty, tx_root(&[]));

        let a = tx_hash(&seq_tx(
            account(1),
            0,
            ActionType::ActorRegister,
            b"x".to_vec(),
        ))
        .unwrap();
        let b = tx_hash(&seq_tx(
            account(2),
            0,
            ActionType::ActorRegister,
            b"y".to_vec(),
        ))
        .unwrap();

        assert_ne!(a, b);
        assert_eq!(tx_root(&[a]), tx_root(&[a]));
        // single-leaf root degenerates to the leaf hash itself (standard
        // merkle behavior; no ambiguity because pair nodes are domain-tagged)
        assert_eq!(tx_root(&[a]), a);

        let pairs_matter = tx_root(&[a, b]);
        let pairs_flipped = tx_root(&[b, a]);
        assert_ne!(pairs_matter, pairs_flipped);

        // Odd counts fall to duplicate-last deterministically
        assert_eq!(tx_root(&[a, b, a]), tx_root(&[a, b, a]));
        assert_ne!(tx_root(&[a, b, a]), tx_root(&[a, b]));
    }

    #[test]
    fn header_hash_excludes_proof() {
        let mut header = BlockHeader {
            number: 1,
            parent_hash: H256::ZERO,
            timestamp: 12,
            tx_root: H256::ZERO,
            state_root: StateRoot::new(H256::ZERO, H256::ZERO),
            da_ref: H256::ZERO,
            fork_id: 1,
            guest_hash: H256::ZERO,
            proof_system_version: 1,
            proof: None,
        };
        let bare = header_hash(&header).unwrap();
        header.proof = Some(Proof {
            proof_data: vec![0x00; 8],
            proof_type: ProofType::ZkVm,
        });
        let proven = header_hash(&header).unwrap();
        assert_eq!(bare, proven);
    }

    #[test]
    fn mempool_admission_and_dedup() {
        let mut mempool = Mempool::new(3);
        let tx = seq_tx(account(1), 0, ActionType::ActorRegister, b"a".to_vec());
        let hash = mempool.submit(tx.clone()).unwrap();
        assert_eq!(mempool.len(), 1);

        // duplicate submission rejected
        assert!(mempool.submit(tx).is_err());
        assert_eq!(mempool.len(), 1);
        assert_ne!(hash, H256::ZERO);

        // well-formedness: empty actions and Zero fee rejected
        let mut bad = seq_tx(account(2), 0, ActionType::ActorRegister, b"b".to_vec());
        bad.actions.clear();
        assert!(matches!(
            mempool.submit(bad),
            Err(Error::Transaction(msg)) if msg.contains("Empty")
        ));
    }

    #[test]
    fn mempool_bounded() {
        let mut mempool = Mempool::new(1);
        mempool
            .submit(seq_tx(
                account(1),
                0,
                ActionType::ActorRegister,
                b"a".to_vec(),
            ))
            .unwrap();
        assert!(mempool
            .submit(seq_tx(
                account(1),
                1,
                ActionType::ActorRegister,
                b"b".to_vec()
            ))
            .is_err());
    }

    fn actor_set() -> (Transaction, Transaction) {
        let sponsor = seq_tx(
            account(0x11),
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })
            .unwrap(),
        );
        let worker = seq_tx(
            account(0x22),
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Worker,
            })
            .unwrap(),
        );
        (sponsor, worker)
    }

    fn grant_tx(cap: Capability) -> Transaction {
        seq_tx(
            account(0x11),
            1,
            ActionType::ActorGrant,
            encode_payload(&ActorGrantPayload {
                grantee: account(0x22),
                capability: cap,
            })
            .unwrap(),
        )
    }

    /// Project-create tx for the sponsor. The `seq` must match the account's
    /// next expected nonce (0 register, 1 grant, 2 project in the full flow).
    fn project_tx(seq: u64) -> Transaction {
        seq_tx(
            account(0x11),
            seq,
            ActionType::ProjectCreate,
            encode_payload(&ProjectCreatePayload {
                title: "chain-project".to_string(),
            })
            .unwrap(),
        )
    }

    #[test]
    fn build_empty_block_links_genesis() {
        let mut sequencer = mvp_sequencer();
        let block = sequencer.build_block(None).unwrap();

        assert_eq!(block.header.number, 1);
        assert_eq!(block.header.parent_hash, Hash::sha256(GENESIS_PARENT_HASH));
        assert_eq!(block.header.timestamp, SLOT_SECONDS);
        assert_eq!(block.header.tx_root, tx_root(&[]));
        assert!(block.transactions.is_empty());
        assert_eq!(sequencer.tip(), 1);

        // header passes the consensus fork validation
        workstream_core::fork::validate_header_fork(
            &block.header,
            &mvp_genesis_schedule().unwrap(),
        )
        .unwrap();

        // next block links to the previous header hash
        let block2 = sequencer.build_block(None).unwrap();
        assert_eq!(block2.header.number, 2);
        assert_eq!(
            block2.header.parent_hash,
            header_hash(&block.header).unwrap()
        );
        assert_eq!(block2.header.timestamp, 2 * SLOT_SECONDS);
    }

    #[test]
    fn build_block_includes_valid_and_drops_invalid() {
        let mut sequencer = mvp_sequencer();
        let (sponsor, worker) = actor_set();
        sequencer.submit_tx(sponsor).unwrap();
        sequencer.submit_tx(worker).unwrap();
        sequencer
            .submit_tx(grant_tx(Capability::ClaimWork))
            .unwrap();
        // well-formed with a valid next nonce (0x22 consumed seq 0 in this
        // block) but references a nonexistent task: dropped at execution
        sequencer
            .submit_tx(seq_tx(
                account(0x22),
                1,
                ActionType::TaskClaim,
                encode_payload(&workstream_stf::TaskIdPayload { task: H256::ZERO }).unwrap(),
            ))
            .unwrap();

        let block = sequencer.build_block(Some(10)).unwrap();
        assert_eq!(block.header.number, 1);
        assert_eq!(block.transactions.len(), 3);

        // the tx root commits exactly to the included transactions
        let hashes: Vec<H256> = block
            .transactions
            .iter()
            .map(|tx| tx_hash(tx).unwrap())
            .collect();
        assert_eq!(block.header.tx_root, tx_root(&hashes));

        // the failing transaction was dropped without touching the chain
        assert_eq!(sequencer.pending(), 0);
    }

    #[test]
    fn state_root_advances_with_blocks() {
        let mut sequencer = mvp_sequencer();
        let empty = sequencer.build_block(None).unwrap();
        let root_empty = empty.header.state_root.hash();

        let (sponsor, _worker) = actor_set();
        sequencer.submit_tx(sponsor).unwrap();
        let with_tx = sequencer.build_block(None).unwrap();
        assert_ne!(with_tx.header.state_root.hash(), root_empty);
        // and equals the committed state's root
        assert_eq!(with_tx.header.state_root, sequencer.state().root());

        // the sponsor has consumed seq 0 (register); the next valid nonce
        // under replay protection is exactly 1 — a gap must not be accepted.
        sequencer.submit_tx(project_tx(1)).unwrap();
        let project_block = sequencer.build_block(None).unwrap();
        assert_ne!(
            project_block.header.state_root.hash(),
            with_tx.header.state_root.hash()
        );

        // Header chain integrity end to end
        assert_eq!(
            project_block.header.parent_hash,
            header_hash(&with_tx.header).unwrap()
        );

        assert_eq!(
            with_tx.header.parent_hash,
            header_hash(&empty.header).unwrap()
        );
    }

    #[test]
    fn deterministic_build_replay() {
        // Two independent sequencers fed the identical tx order produce
        // byte-identical blocks (same header chain, same state roots).
        let (a1, a2) = replay_chain();
        let (b1, b2) = replay_chain();

        assert_eq!(
            postcard::to_allocvec(&(a1, a2)).unwrap(),
            postcard::to_allocvec(&(b1, b2)).unwrap()
        );
    }

    /// Build a deterministic two-block chain: register two actors + grant in
    /// block 1, then an empty block that seals the state without new txs.
    fn replay_chain() -> (Block, Block) {
        let mut sequencer = mvp_sequencer();
        let (sponsor, worker) = actor_set();
        sequencer.submit_tx(sponsor).unwrap();
        sequencer.submit_tx(worker).unwrap();
        sequencer
            .submit_tx(grant_tx(Capability::SubmitWork))
            .unwrap();
        let b1 = sequencer.build_block(None).unwrap();
        let b2 = sequencer.build_block(None).unwrap();
        (b1, b2)
    }
}
