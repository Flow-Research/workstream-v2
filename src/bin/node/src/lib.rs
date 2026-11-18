//! WorkStream node library: block verification and state sync (issue #32).
//!
//! The node verifies blocks produced by the sequencer and maintains the
//! canonical state. Verification is deterministic: the same block applied
//! to the same state must yield identical results on every node.
//!
//! Verification steps for each block:
//! 1. Parent hash: `header_hash(prev_header) == block.header.parent_hash`
//! 2. Fork rules: header passes `validate_header_fork`
//! 3. Tx root: recomputed `tx_root` over the block's transactions matches
//! 4. Execution: STF executes all transactions under the block's fork
//! 5. State root: computed `state.root()` matches `header.state_root`
//!
//! If any check fails, the block is rejected; the node state is unchanged.

use std::path::Path;
use std::sync::Arc;
use workstream_core::fork::{validate_header_fork, ForkSchedule};
use workstream_core::hash::{Hash, H256};
use workstream_core::traits::prover::{ProveBlockTransition, ZkProof, ZkvmBackend};
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_prover::{InMemoryZkBackend, DEFAULT_GUEST_ID};
use workstream_sequencer::{header_hash, tx_hash, tx_root, GENESIS_PARENT_HASH};
use workstream_state::State;
use workstream_stf::StateTransitionFunction;

/// Trait for sourcing blocks. Implementations may be in-memory queues,
/// file readers, or (later) P2P network fetchers.
pub trait BlockSource {
    /// Fetch the next block to process, if available.
    fn next_block(&mut self) -> Option<Block>;

    /// Fetch a specific block by height, if available.
    fn block_at(&self, height: BlockNumber) -> Option<Block>;
}

/// Simple in-memory block source for testing and local sync.
#[derive(Debug, Default)]
pub struct MemoryBlockSource {
    blocks: Vec<Block>,
    cursor: usize,
}

impl MemoryBlockSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl BlockSource for MemoryBlockSource {
    fn next_block(&mut self) -> Option<Block> {
        if self.cursor < self.blocks.len() {
            let block = self.blocks[self.cursor].clone();
            self.cursor += 1;
            Some(block)
        } else {
            None
        }
    }

    fn block_at(&self, height: BlockNumber) -> Option<Block> {
        self.blocks
            .iter()
            .find(|b| b.header.number == height)
            .cloned()
    }
}

/// Result of applying a block.
#[derive(Debug)]
pub struct ApplyResult {
    pub height: BlockNumber,
    pub state_root: StateRoot,
    pub events: Vec<Event>,
}

/// Verifying node: applies blocks from a source, maintains canonical state.
pub struct Node<S: BlockSource> {
    stf: StateTransitionFunction,
    schedule: ForkSchedule,
    state: State,
    source: S,
    /// zkVM proof verification backend (SEC-002); blocks whose attached
    /// proof fails verification are rejected before commit.
    backend: Arc<dyn ZkvmBackend>,
    last_header: Option<BlockHeader>,
}

impl<S: BlockSource> Node<S> {
    /// Create a node starting from genesis (empty state, no blocks applied).
    pub fn new(stf: StateTransitionFunction, schedule: ForkSchedule, source: S) -> Self {
        Self::with_backend(stf, schedule, source, Arc::new(InMemoryZkBackend::new()))
    }

    /// Create a node with a custom proof-verification backend.
    pub fn with_backend(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        backend: Arc<dyn ZkvmBackend>,
    ) -> Self {
        Node {
            stf,
            schedule,
            state: State::new(),
            source,
            backend,
            last_header: None,
        }
    }

    /// Current chain tip height (0 == genesis, no blocks applied yet).
    pub fn tip(&self) -> BlockNumber {
        self.last_header.as_ref().map(|h| h.number).unwrap_or(0)
    }

    /// Current committed state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Current state root.
    pub fn state_root(&self) -> StateRoot {
        self.state.root()
    }

    /// Last applied block header.
    pub fn last_header(&self) -> Option<&BlockHeader> {
        self.last_header.as_ref()
    }

    /// Apply the next block from the source.
    ///
    /// Returns `Ok(Some(result))` if a block was applied successfully,
    /// `Ok(None)` if no block is available, or `Err` if verification failed.
    pub fn apply_next(&mut self) -> Result<Option<ApplyResult>> {
        match self.source.next_block() {
            Some(block) => self.apply_block(block).map(Some),
            None => Ok(None),
        }
    }

    /// Apply all available blocks from the source.
    ///
    /// Stops at the first error or when no more blocks are available.
    pub fn sync(&mut self) -> Result<Vec<ApplyResult>> {
        let mut results = Vec::new();
        while let Some(result) = self.apply_next()? {
            results.push(result);
        }
        Ok(results)
    }

    /// Verify and apply a single block.
    pub fn apply_block(&mut self, block: Block) -> Result<ApplyResult> {
        let height = block.header.number;

        // 1. Height continuity
        let expected_height = self.tip() + 1;
        if height != expected_height {
            return Err(Error::Consensus(format!(
                "block height {} does not follow tip {}",
                height,
                self.tip()
            )));
        }

        // 2. Parent hash
        let expected_parent = match self.last_header.as_ref() {
            Some(header) => header_hash(header)?,
            None => Hash::sha256(GENESIS_PARENT_HASH),
        };
        if block.header.parent_hash != expected_parent {
            return Err(Error::Consensus(format!(
                "parent hash mismatch at height {}: expected {}, got {}",
                height, expected_parent, block.header.parent_hash
            )));
        }

        // 3. Fork rules (fork_id, guest_hash, proof_system_version)
        validate_header_fork(&block.header, &self.schedule)?;

        // 4. Tx root
        let leaf_hashes: Vec<H256> = block
            .transactions
            .iter()
            .map(|tx| tx_hash(tx).unwrap())
            .collect();
        let computed_tx_root = tx_root(&leaf_hashes);
        if block.header.tx_root != computed_tx_root {
            return Err(Error::Consensus(format!(
                "tx root mismatch at height {}: expected {}, got {}",
                height, computed_tx_root, block.header.tx_root
            )));
        }

        // 5. Execute on a draft state (rollback on failure)
        let mut draft = self.state.clone();
        let events = self.stf.execute_block(&mut draft, &block)?;

        // 6. State root
        let computed_state_root = draft.root();
        if block.header.state_root != computed_state_root {
            return Err(Error::Consensus(format!(
                "state root mismatch at height {}: expected {}, got {}",
                height,
                computed_state_root.hash(),
                block.header.state_root.hash()
            )));
        }

        // 7. zkVM proof verification (SEC-002): reject blocks whose attached
        //    proof fails verification before any state is committed. Blocks
        //    without a proof are not yet attributable to a prover and are
        //    deferred to the prover/header integration (issue #83).
        if let Some(proof) = block.header.proof.clone() {
            let stateroot_pre = self.state.root().smt_root;
            let transition = ProveBlockTransition {
                version: 1,
                block_hash: *header_hash(&block.header)?.as_bytes(),
                stateroot_pre,
                transactions: block.transactions.clone(),
            };
            let zk_proof = ZkProof {
                version: 1,
                proof_bytes: proof.proof_data.clone(),
                public_inputs: computed_state_root.smt_root.as_bytes().to_vec(),
                guest_id: DEFAULT_GUEST_ID.to_string(),
                guest_hash: Hash::sha256(DEFAULT_GUEST_ID.as_bytes()),
                stateroot_pre,
            };
            let valid = self
                .backend
                .verify_block_transition(&transition, &zk_proof)?;
            if !valid {
                return Err(Error::Consensus(format!(
                    "zk proof verification failed at height {height}"
                )));
            }
        }

        // Commit
        self.state = draft;
        self.state.last_header = Some(block.header.clone());
        self.last_header = Some(block.header);

        Ok(ApplyResult {
            height,
            state_root: computed_state_root,
            events,
        })
    }

    /// Persist the node state (SMT/MMR snapshot + last applied header) to
    /// `<dir>/state.json` so a restart resumes at the same tip.
    pub fn save_state(&self, dir: &Path) -> Result<()> {
        self.state.save_to_dir(dir)
    }

    /// Rebuild a verifying node from a previously persisted state directory.
    pub fn load_state(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        dir: &Path,
    ) -> Result<Self> {
        let state = State::load_from_dir(dir)?;
        let last_header = state.last_header.clone();
        let mut node = Self::new(stf, schedule, source);
        node.state = state;
        node.last_header = last_header;
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_crypto::signature;
    use workstream_sequencer::Sequencer;
    use workstream_stf::{
        encode_payload, mvp_genesis_schedule, ActorRegisterPayload, ActorRole, ProjectCreatePayload,
    };
    use workstream_tx::TxBuilder;

    fn account(tag: u8) -> AccountId {
        H256::from_bytes([tag; 32])
    }

    /// Deterministic Ed25519 signer for admission fixtures.
    fn ed25519_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn test_tx(acct: AccountId, seq: u64, t: ActionType, payload: Vec<u8>) -> Transaction {
        let mut tx = TxBuilder::new()
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
            .unwrap();
        signature::sign_tx_ed25519(&mut tx, &ed25519_signing_key()).unwrap();
        tx
    }

    fn register_tx(tag: u8, role: ActorRole) -> Transaction {
        test_tx(
            account(tag),
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload { role }).unwrap(),
        )
    }

    fn project_tx(tag: u8, title: &str) -> Transaction {
        test_tx(
            account(tag),
            1,
            ActionType::ProjectCreate,
            encode_payload(&ProjectCreatePayload {
                title: title.to_string(),
            })
            .unwrap(),
        )
    }

    fn mvp_stf() -> StateTransitionFunction {
        StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap()
    }

    fn mvp_schedule() -> ForkSchedule {
        mvp_genesis_schedule().unwrap()
    }

    fn build_chain(txs_per_block: Vec<Vec<Transaction>>) -> (Vec<Block>, State) {
        let mut sequencer = Sequencer::new(mvp_stf());
        let mut blocks = Vec::new();

        for txs in txs_per_block {
            for tx in txs {
                sequencer.submit_tx(tx).unwrap();
            }
            blocks.push(sequencer.build_block(None).unwrap());
        }

        (blocks, sequencer.state().clone())
    }

    #[test]
    fn node_state_round_trips_through_disk() {
        let node = Node::new(mvp_stf(), mvp_schedule(), MemoryBlockSource::new());
        let dir =
            std::env::temp_dir().join(format!("workstream-node-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        node.save_state(&dir).unwrap();
        let restored =
            Node::load_state(mvp_stf(), mvp_schedule(), MemoryBlockSource::new(), &dir).unwrap();
        assert_eq!(restored.tip(), node.tip());
        assert_eq!(restored.state_root(), node.state_root());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_syncs_empty_blocks() {
        let (blocks, _) = build_chain(vec![vec![], vec![], vec![]]);
        let mut source = MemoryBlockSource::new();
        for b in blocks {
            source.push(b);
        }

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        assert_eq!(node.tip(), 0);

        let results = node.sync().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(node.tip(), 3);
        assert_eq!(results[0].height, 1);
        assert_eq!(results[1].height, 2);
        assert_eq!(results[2].height, 3);
    }

    #[test]
    fn node_syncs_with_transactions() {
        let (blocks, sequencer_state) = build_chain(vec![
            vec![register_tx(0x11, ActorRole::Sponsor)],
            vec![project_tx(0x11, "test-project")],
        ]);

        let mut source = MemoryBlockSource::new();
        for b in blocks.clone() {
            source.push(b);
        }

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let results = node.sync().unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(node.tip(), 2);

        // State roots must match sequencer
        assert_eq!(node.state_root(), sequencer_state.root());

        // Events were captured
        assert_eq!(results[0].events.len(), 1);
        assert_eq!(results[0].events[0].event_type, "actor.registered");
        assert_eq!(results[1].events.len(), 1);
        assert_eq!(results[1].events[0].event_type, "project.created");
    }

    #[test]
    fn node_rejects_bad_parent_hash() {
        let (mut blocks, _) = build_chain(vec![vec![], vec![]]);
        blocks[1].header.parent_hash = H256::ZERO; // corrupt

        let mut source = MemoryBlockSource::new();
        for b in blocks {
            source.push(b);
        }

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        node.apply_next().unwrap(); // block 1 OK

        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("parent hash mismatch"));
        assert_eq!(node.tip(), 1); // unchanged
    }

    #[test]
    fn node_rejects_bad_tx_root() {
        let (mut blocks, _) = build_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]);
        blocks[0].header.tx_root = H256::ZERO; // corrupt

        let mut source = MemoryBlockSource::new();
        source.push(blocks.into_iter().next().unwrap());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("tx root mismatch"));
    }

    #[test]
    fn node_rejects_bad_state_root() {
        let (mut blocks, _) = build_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]);
        blocks[0].header.state_root = StateRoot::new(H256::ZERO, H256::ZERO); // corrupt

        let mut source = MemoryBlockSource::new();
        source.push(blocks.into_iter().next().unwrap());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("state root mismatch"));
    }

    #[test]
    fn node_accepts_valid_proof() {
        let (mut blocks, _) = build_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]);
        let block = blocks.pop().unwrap();
        let backend = InMemoryZkBackend::new();
        let transition = ProveBlockTransition {
            version: 1,
            block_hash: [7u8; 32],
            stateroot_pre: State::new().root().smt_root,
            transactions: block.transactions.clone(),
        };
        let proof = backend.compute_proof(&transition).unwrap();
        let mut block = block;
        block.header.proof = Some(Proof {
            proof_data: proof.proof_bytes.clone(),
            proof_type: ProofType::ZkVm,
        });

        let mut source = MemoryBlockSource::new();
        source.push(block);
        let mut node = Node::with_backend(
            mvp_stf(),
            mvp_schedule(),
            source,
            Arc::new(InMemoryZkBackend::new()),
        );
        let result = node.apply_next().unwrap();
        let result = result.unwrap();
        assert_eq!(result.height, 1);
        assert_eq!(node.tip(), 1);
    }

    #[test]
    fn node_rejects_invalid_proof() {
        let (mut blocks, _) = build_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]);
        let mut block = blocks.pop().unwrap();
        block.header.proof = Some(Proof {
            proof_data: vec![0u8; 32],
            proof_type: ProofType::ZkVm,
        });

        let mut source = MemoryBlockSource::new();
        source.push(block);
        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("zk proof verification failed"));
        assert_eq!(node.tip(), 0); // unchanged after rejection
    }

    #[test]
    fn node_rejects_height_gap() {
        let (blocks, _) = build_chain(vec![vec![], vec![], vec![]]);
        let mut source = MemoryBlockSource::new();
        // Skip block 1
        source.push(blocks[1].clone());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("does not follow tip"));
    }

    #[test]
    fn node_rejects_bad_fork_id() {
        let (mut blocks, _) = build_chain(vec![vec![]]);
        blocks[0].header.fork_id = 999; // invalid fork

        let mut source = MemoryBlockSource::new();
        source.push(blocks.into_iter().next().unwrap());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Fork(_)));
    }

    #[test]
    fn deterministic_verification() {
        // Two independent nodes fed identical blocks produce identical state
        let (blocks, _) = build_chain(vec![
            vec![register_tx(0x11, ActorRole::Sponsor)],
            vec![register_tx(0x22, ActorRole::Worker)],
            vec![project_tx(0x11, "determinism-test")],
        ]);

        let mut source1 = MemoryBlockSource::new();
        let mut source2 = MemoryBlockSource::new();
        for b in &blocks {
            source1.push(b.clone());
            source2.push(b.clone());
        }

        let mut node1 = Node::new(mvp_stf(), mvp_schedule(), source1);
        let mut node2 = Node::new(mvp_stf(), mvp_schedule(), source2);

        node1.sync().unwrap();
        node2.sync().unwrap();

        assert_eq!(node1.state_root(), node2.state_root());
        assert_eq!(node1.tip(), node2.tip());
    }

    #[test]
    fn node_and_sequencer_state_converge() {
        // The core consensus property: node replaying sequencer blocks
        // ends up with identical state
        let txs = vec![
            register_tx(0x11, ActorRole::Sponsor),
            register_tx(0x22, ActorRole::Worker),
            project_tx(0x11, "convergence"),
        ];

        let mut sequencer = Sequencer::new(mvp_stf());
        for tx in txs {
            sequencer.submit_tx(tx).unwrap();
        }
        let block = sequencer.build_block(None).unwrap();
        let sequencer_header = block.header.clone();

        let mut source = MemoryBlockSource::new();
        source.push(block);

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        node.sync().unwrap();

        // State roots converge
        assert_eq!(node.state_root(), sequencer.state().root());

        // The node's last header equals the sequencer's produced header
        assert_eq!(
            header_hash(node.last_header().unwrap()).unwrap(),
            header_hash(&sequencer_header).unwrap()
        );
    }
}
