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
use workstream_core::proof::ProofCommitment;
use workstream_core::traits::p2p::{GetBlockRequest, P2pNetwork};
use workstream_core::traits::prover::{ProveBlockTransition, ZkvmBackend};
use workstream_core::traits::verifier::BlockProofVerifier;
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_prover::{decode_header_proof, InMemoryVerifier};
use workstream_sequencer::{
    header_hash, tx_hash, tx_root, InMemoryP2pNetwork, GENESIS_PARENT_HASH,
};
use workstream_state::State;
use workstream_stf::StateTransitionFunction;

pub mod indexer;
pub mod rpc;

pub use indexer::EventIndexer;
pub use rpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcServer};

/// Trait for sourcing blocks. Implementations may be in-memory queues,
/// file readers, or (later) P2P network fetchers.
pub trait BlockSource {
    /// Fetch the block at `next_height`, if available. Passing the height
    /// lets a rejected block be retried without consuming the source cursor.
    fn next_block(&mut self, next_height: BlockNumber) -> Option<Block>;

    /// Fetch a specific block by height, if available.
    fn block_at(&self, height: BlockNumber) -> Option<Block>;
}

/// Simple in-memory block source for testing and local sync.
#[derive(Debug, Default)]
pub struct MemoryBlockSource {
    blocks: Vec<Block>,
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
    fn next_block(&mut self, next_height: BlockNumber) -> Option<Block> {
        self.block_at(next_height)
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
    /// P2P gossip network for block propagation (issue #84).
    network: Arc<dyn P2pNetwork>,
    /// Indexed event/state views over applied blocks (issue #86).
    indexer: EventIndexer,
    /// zkVM proof verifier (SEC-002/#83); attached proofs are checked before
    /// any state is committed.
    verifier: Arc<dyn BlockProofVerifier>,
    /// Whether an attached proof is mandatory for every block.
    require_proof: bool,
    last_header: Option<BlockHeader>,
}

impl<S: BlockSource> Node<S> {
    /// Create a node starting from genesis (empty state, no blocks applied).
    pub fn new(stf: StateTransitionFunction, schedule: ForkSchedule, source: S) -> Self {
        // Default to the portable in-memory verifier bound to this node's own
        // STF/fork schedule. Real receipt verification is injected explicitly
        // with [`Node::with_verifier`].
        Self::with_verifier(
            stf.clone(),
            schedule,
            source,
            Arc::new(InMemoryVerifier::new(stf)),
        )
    }

    /// Create a node that syncs from the supplied P2P network.
    pub fn with_network(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        network: Arc<dyn P2pNetwork>,
    ) -> Self {
        Self {
            network,
            ..Self::new(stf, schedule, source)
        }
    }

    /// Create a node with a custom proof-verification backend.
    ///
    /// Kept for callers that previously injected a [`ZkvmBackend`]; the backend
    /// is wrapped in an [`InMemoryVerifier`] for the block-apply path.
    pub fn with_backend(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        backend: Arc<dyn ZkvmBackend>,
    ) -> Self {
        Self::with_verifier(
            stf,
            schedule,
            source,
            Arc::new(InMemoryVerifier::with_backend(backend)),
        )
    }

    /// Create a node with a custom synchronous block-proof verifier.
    pub fn with_verifier(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        verifier: Arc<dyn BlockProofVerifier>,
    ) -> Self {
        Node {
            stf,
            schedule,
            state: State::new(),
            source,
            indexer: EventIndexer::new(),
            network: Arc::new(InMemoryP2pNetwork::new()),
            verifier,
            require_proof: false,
            last_header: None,
        }
    }

    /// Require every applied block to carry a valid zkVM proof.
    pub fn require_proof(mut self) -> Self {
        self.require_proof = true;
        self
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

    /// Indexed event/state views over applied blocks (issue #86).
    pub fn indexer(&self) -> &EventIndexer {
        &self.indexer
    }

    /// Events emitted by an applied block, in emission order.
    pub fn events_for_block(&self, block_number: BlockNumber) -> Vec<&Event> {
        self.indexer.events(block_number)
    }

    /// State root observed after applying a block, if indexed.
    pub fn state_root_at(&self, block_number: BlockNumber) -> Option<StateRoot> {
        self.indexer.state_root_at(block_number)
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
        let next_height = self.tip() + 1;
        match self.source.next_block(next_height) {
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

    /// Apply blocks served by the P2P gossip network, starting at the next
    /// expected height, until the network has no block at that height.
    ///
    /// Blocks served here are subject to the same full verification pipeline
    /// (parent, fork, tx root, execution, state root, zkVM proof) as source
    /// blocks; a failing block stops the sync without committing state.
    pub async fn sync_via_network(&mut self) -> Result<Vec<ApplyResult>> {
        let mut results = Vec::new();
        let mut height = self.tip() + 1;
        loop {
            let response = self
                .network
                .get_block(GetBlockRequest {
                    version: 1,
                    api_version: 1,
                    height,
                })
                .await?;
            let Some(block) = response.block else {
                break;
            };
            results.push(self.apply_block(block)?);
            height = self.tip() + 1;
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

        // 7. zkVM proof verification (SEC-002/#83): decode the self-describing
        //    header envelope, bind it to the canonical transition commitment
        //    and verify through the injected verifier before committing state.
        let attached_proof = match block.header.proof.clone() {
            Some(proof) => Some(proof),
            None if self.require_proof => {
                return Err(Error::Consensus(format!(
                    "block at height {height} has no attached zk proof"
                )));
            }
            None => None,
        };
        let fork = self
            .schedule
            .active_fork_at(height)
            .ok_or_else(|| Error::Fork(format!("no active fork at height {height}")))?;
        if attached_proof.is_none() && fork.has_feature("risc0-receipts") {
            return Err(Error::Consensus(format!(
                "block at height {height} is missing required zkVM receipt"
            )));
        }

        if let Some(proof) = attached_proof {
            let zk_proof = decode_header_proof(&proof).map_err(|e| {
                Error::Consensus(format!(
                    "zk proof verification failed at height {height}: invalid proof envelope: {e}"
                ))
            })?;
            let stateroot_pre = self.state.root().hash();
            let stateroot_post = computed_state_root.hash();
            let proof_commitment =
                ProofCommitment::new(&block.header, stateroot_pre, &block.transactions)?;
            let commitment = proof_commitment.hash()?;

            if zk_proof.stateroot_pre != stateroot_pre
                || zk_proof.public_inputs != stateroot_post.as_bytes().to_vec()
                || zk_proof.guest_hash != block.header.guest_hash
                || zk_proof.commitment != commitment
            {
                return Err(Error::Consensus(format!(
                    "zk proof verification failed at height {height}: commitment or public input mismatch"
                )));
            }

            let backend_witness = postcard::to_allocvec(&self.state.snapshot())
                .map_err(|e| Error::Serialization(format!("backend witness encode: {e}")))?;
            let transition = ProveBlockTransition {
                version: 1,
                height,
                block_hash: *commitment.as_bytes(),
                stateroot_pre,
                stateroot_post,
                guest_hash: block.header.guest_hash,
                commitment: proof_commitment,
                transactions: block.transactions.clone(),
                backend_witness,
            };
            transition.validate()?;
            if !self
                .verifier
                .verify_block_transition(&transition, &zk_proof)?
            {
                return Err(Error::Consensus(format!(
                    "zk proof verification failed at height {height}"
                )));
            }
        }

        // Commit
        self.state = draft;
        self.state.last_header = Some(block.header.clone());
        self.last_header = Some(block.header);

        // Index the applied block's events and state root for API-facing
        // views (issue #86).
        self.indexer
            .record(height, computed_state_root.clone(), events.clone());

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
        Self::load_state_with_verifier(
            stf.clone(),
            schedule,
            source,
            Arc::new(InMemoryVerifier::new(stf)),
            dir,
        )
    }

    /// Rebuild a verifying node with a custom block-proof verifier.
    pub fn load_state_with_verifier(
        stf: StateTransitionFunction,
        schedule: ForkSchedule,
        source: S,
        verifier: Arc<dyn BlockProofVerifier>,
        dir: &Path,
    ) -> Result<Self> {
        let state = State::load_from_dir(dir)?;
        let last_header = state.last_header.clone();
        let mut node = Self::with_verifier(stf, schedule, source, verifier);
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

    /// Deterministic Ed25519 signer for admission fixtures.
    fn signing_key(tag: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[tag; 32])
    }

    /// Account IDs are derived from the signing key so the fixture satisfies
    /// transaction admission's signer/account ownership check.
    fn account(tag: u8) -> AccountId {
        workstream_core::Hash::sha256(signing_key(tag).verifying_key().as_bytes())
    }

    fn test_tx(tag: u8, seq: u64, t: ActionType, payload: Vec<u8>) -> Transaction {
        let mut tx = TxBuilder::new()
            .chain_id(1)
            .account(account(tag))
            .nonce(0, seq)
            .add_action(t, payload)
            .fee(FeeSpec {
                payer: FeePayer::Self_,
                asset_id: 0,
                max_fee: 1_000,
            })
            .build()
            .unwrap();
        signature::sign_tx_ed25519(&mut tx, &signing_key(tag)).unwrap();
        tx
    }

    fn register_tx(tag: u8, role: ActorRole) -> Transaction {
        test_tx(
            tag,
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload { role }).unwrap(),
        )
    }

    fn project_tx(tag: u8, title: &str) -> Transaction {
        test_tx(
            tag,
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

    async fn build_proved_chain(txs_per_block: Vec<Vec<Transaction>>) -> Vec<Block> {
        let mut sequencer = Sequencer::new(mvp_stf());
        let mut blocks = Vec::new();
        for txs in txs_per_block {
            for tx in txs {
                sequencer.submit_tx(tx).unwrap();
            }
            blocks.push(sequencer.build_and_submit_block(None).await.unwrap());
        }
        blocks
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
    fn node_indexes_events_and_state_roots_for_applied_blocks() {
        let (blocks, _) = build_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]);
        let mut source = MemoryBlockSource::new();
        source.push(blocks.into_iter().next().unwrap());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        let results = node.sync().unwrap();
        assert_eq!(results.len(), 1);

        assert!(!node.events_for_block(1).is_empty());
        assert!(node.state_root_at(1).is_some());
    }

    #[tokio::test]
    async fn node_accepts_valid_proof() {
        let blocks = build_proved_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]).await;
        let block = blocks.into_iter().next().unwrap();
        assert!(block.header.proof.is_some());

        let mut source = MemoryBlockSource::new();
        source.push(block);
        let mut node = Node::new(mvp_stf(), mvp_schedule(), source).require_proof();
        let result = node.apply_next().unwrap().unwrap();
        assert_eq!(result.height, 1);
        assert_eq!(node.tip(), 1);
    }

    #[tokio::test]
    async fn node_rejects_invalid_proof() {
        let blocks = build_proved_chain(vec![vec![register_tx(0x11, ActorRole::Sponsor)]]).await;
        let mut block = blocks.into_iter().next().unwrap();
        block.header.proof.as_mut().unwrap().proof_data[0] ^= 0xff;

        let mut source = MemoryBlockSource::new();
        source.push(block);
        let mut node = Node::new(mvp_stf(), mvp_schedule(), source).require_proof();
        let err = node.apply_next().unwrap_err();
        assert!(matches!(err, Error::Consensus(_)));
        assert!(err.to_string().contains("zk proof verification failed"));
        assert_eq!(node.tip(), 0); // unchanged after rejection
    }

    #[tokio::test]
    async fn p2p_network_publishes_and_gets_block() {
        let (blocks, _) = build_chain(vec![vec![], vec![]]);
        let network = InMemoryP2pNetwork::new();
        for block in &blocks {
            network
                .publish_block(workstream_core::traits::p2p::PublishBlockRequest {
                    version: 1,
                    api_version: 1,
                    block: block.clone(),
                })
                .await
                .unwrap();
        }
        let response = network
            .get_block(workstream_core::traits::p2p::GetBlockRequest {
                version: 1,
                api_version: 1,
                height: 1,
            })
            .await
            .unwrap();
        assert!(response.block.is_some());
        let missing = network
            .get_block(workstream_core::traits::p2p::GetBlockRequest {
                version: 1,
                api_version: 1,
                height: 99,
            })
            .await
            .unwrap();
        assert!(missing.block.is_none());
    }

    #[tokio::test]
    async fn node_syncs_blocks_via_network() {
        let (blocks, _) = build_chain(vec![vec![], vec![]]);
        let network = InMemoryP2pNetwork::new();
        for block in &blocks {
            network
                .publish_block(workstream_core::traits::p2p::PublishBlockRequest {
                    version: 1,
                    api_version: 1,
                    block: block.clone(),
                })
                .await
                .unwrap();
        }

        let mut node = Node::with_network(
            mvp_stf(),
            mvp_schedule(),
            MemoryBlockSource::new(),
            Arc::new(network),
        );
        let results = node.sync_via_network().await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(node.tip(), 2);
    }

    #[test]
    fn node_rejects_height_gap() {
        let (blocks, _) = build_chain(vec![vec![], vec![], vec![]]);
        let mut source = MemoryBlockSource::new();
        // Skip block 1; the block source does not serve it, but applying a
        // future block directly must still fail the continuity check.
        source.push(blocks[1].clone());

        let mut node = Node::new(mvp_stf(), mvp_schedule(), source);
        assert!(node.apply_next().unwrap().is_none());
        let err = node.apply_block(blocks[1].clone()).unwrap_err();
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
