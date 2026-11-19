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
use std::path::Path;
use std::sync::Arc;

use workstream_core::hash::{Hash, H256};
use workstream_core::proof::ProofCommitment;
use workstream_core::traits::da::{DaClient, PostBlockRequest};
use workstream_core::traits::p2p::{P2pNetwork, PublishBlockRequest};
use workstream_core::traits::prover::{
    ProofBundleResponse, ProveBlockRequest, ProveBlockTransition, ProverApi, ZkProof, ZkvmBackend,
};
use workstream_core::types::*;
use workstream_core::{Error, Result};
use workstream_prover::{encode_header_proof, InMemoryZkBackend, Prover};
use workstream_state::State;
use workstream_stf::StateTransitionFunction;
use workstream_tx::TxValidator;

pub mod da;
pub mod p2p;
pub use da::InMemoryDaClient;
pub use p2p::InMemoryP2pNetwork;

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
#[derive(Clone, Debug)]
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
#[derive(Clone)]
pub struct Sequencer {
    stf: StateTransitionFunction,
    state: State,
    mempool: Mempool,
    last_header: Option<BlockHeader>,
    /// Data availability client used to publish produced blocks (issue #82).
    da: Arc<dyn DaClient>,
    /// zkVM prover used to generate block transition proofs (issue #83).
    /// P2P gossip network used to propagate produced blocks (issue #84).
    p2p: Arc<dyn P2pNetwork>,
    prover: Arc<dyn ProverApi>,
    /// Optional backend used by the sequencer to verify the produced proof
    /// before DA publication. Constructors that only receive a `ProverApi`
    /// leave this unset and rely on the prover's own fail-closed behavior.
    backend: Option<Arc<dyn ZkvmBackend>>,
}

impl Sequencer {
    /// Chain begins at height 1, linked to [`GENESIS_PARENT_HASH`].
    pub fn new(stf: StateTransitionFunction) -> Self {
        Self::with_da(stf, Arc::new(crate::da::InMemoryDaClient::new()))
    }

    /// Create a sequencer wired to a data availability client (default
    /// in-memory prover/backend).
    pub fn with_da(stf: StateTransitionFunction, da: Arc<dyn DaClient>) -> Self {
        let backend: Arc<dyn ZkvmBackend> = Arc::new(InMemoryZkBackend::new(stf.clone()));
        Self::with_da_and_backend(stf, da, backend)
    }

    /// Create a sequencer whose proving backend is selected from the
    /// environment (see [`workstream_prover::PROVER_BACKEND_ENV`]).
    pub fn with_da_from_env(stf: StateTransitionFunction, da: Arc<dyn DaClient>) -> Result<Self> {
        let prover = Prover::from_env(stf.clone())?;
        let backend = prover.backend();
        Ok(Sequencer {
            stf,
            state: State::new(),
            mempool: Mempool::default(),
            last_header: None,
            da,
            prover: Arc::new(prover),
            p2p: Arc::new(crate::p2p::InMemoryP2pNetwork::new()),
            backend: Some(backend),
        })
    }

    /// Create a sequencer with a custom zkVM proving backend.
    pub fn with_backend(stf: StateTransitionFunction, backend: Arc<dyn ZkvmBackend>) -> Self {
        Self::with_da_and_backend(stf, Arc::new(crate::da::InMemoryDaClient::new()), backend)
    }

    /// Create a sequencer with custom DA and proving backends.
    pub fn with_da_and_backend(
        stf: StateTransitionFunction,
        da: Arc<dyn DaClient>,
        backend: Arc<dyn ZkvmBackend>,
    ) -> Self {
        let prover = Arc::new(Prover::with_backend(backend.clone()));
        Sequencer {
            stf,
            state: State::new(),
            mempool: Mempool::default(),
            last_header: None,
            da,
            prover,
            p2p: Arc::new(crate::p2p::InMemoryP2pNetwork::new()),
            backend: Some(backend),
        }
    }

    /// Create a sequencer wired to a data availability client and a `ProverApi`
    /// adapter. Use [`Sequencer::with_da_and_backend`] when the sequencer
    /// should also verify the produced proof before publication.
    pub fn with_da_and_prover(
        stf: StateTransitionFunction,
        da: Arc<dyn DaClient>,
        prover: Arc<dyn ProverApi>,
    ) -> Self {
        Self::with_da_and_prover_and_p2p(
            stf,
            da,
            prover,
            Arc::new(crate::p2p::InMemoryP2pNetwork::new()),
        )
    }

    /// Create a sequencer wired to a data availability client, a zkVM prover,
    /// and a P2P gossip network.
    pub fn with_da_and_prover_and_p2p(
        stf: StateTransitionFunction,
        da: Arc<dyn DaClient>,
        prover: Arc<dyn ProverApi>,
        p2p: Arc<dyn P2pNetwork>,
    ) -> Self {
        Sequencer {
            stf,
            state: State::new(),
            mempool: Mempool::default(),
            last_header: None,
            da,
            p2p,
            prover,
            backend: None,
        }
    }

    /// Submit a transaction to the mempool (see [`Mempool::submit`]).
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<H256> {
        self.mempool.submit(tx)
    }

    /// P2P gossip network the sequencer publishes proved blocks to.
    pub fn p2p(&self) -> &Arc<dyn P2pNetwork> {
        &self.p2p
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

    fn validate_bundle(
        bundle: &ProofBundleResponse,
        transition: &ProveBlockTransition,
        commitment: H256,
        stateroot_pre: H256,
        stateroot_post: H256,
    ) -> Result<()> {
        if bundle.version != 1
            || bundle.api_version != 1
            || bundle.guest_hash != transition.guest_hash
            || bundle.commitment != commitment
            || bundle.stateroot_pre != stateroot_pre
            || bundle.stateroot_post != stateroot_post
            || bundle.public_inputs != stateroot_post.as_bytes().to_vec()
            || bundle.proof_bytes.is_empty()
        {
            return Err(Error::InvalidProof(
                "prover bundle does not match the candidate transition".into(),
            ));
        }
        Ok(())
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
            da_ref: H256::ZERO, // populated by build_and_submit_block once DA is configured
            fork_id: fork.fork_id,
            guest_hash: fork.guest_hash,
            proof_system_version: fork.min_proof_system,
            proof: None, // proofs are prover work (not part of #16)
        };
        self.last_header = Some(header.clone());
        self.state.last_header = Some(header.clone());

        Ok(Block {
            header,
            transactions: included,
        })
    }

    /// Persist the sequencer state (SMT/MMR snapshot + last applied header)
    /// to `<dir>/state.json` so a restart resumes at the same tip.
    pub fn save_state(&self, dir: &Path) -> Result<()> {
        self.state.save_to_dir(dir)
    }

    /// Rebuild a sequencer from a previously persisted state directory.
    pub fn load_state(
        stf: StateTransitionFunction,
        da: Arc<dyn DaClient>,
        dir: &Path,
    ) -> Result<Self> {
        let backend: Arc<dyn ZkvmBackend> = Arc::new(InMemoryZkBackend::new(stf.clone()));
        Self::load_state_with_backend(stf, da, backend, dir)
    }

    /// Rebuild a sequencer from disk with a custom proving backend.
    pub fn load_state_with_backend(
        stf: StateTransitionFunction,
        da: Arc<dyn DaClient>,
        backend: Arc<dyn ZkvmBackend>,
        dir: &Path,
    ) -> Result<Self> {
        let state = State::load_from_dir(dir)?;
        let last_header = state.last_header.clone();
        let prover = Arc::new(Prover::with_backend(backend.clone()));
        Ok(Sequencer {
            stf,
            state,
            mempool: Mempool::default(),
            last_header,
            da,
            prover,
            p2p: Arc::new(crate::p2p::InMemoryP2pNetwork::new()),
            backend: Some(backend),
        })
    }

    /// Build the next block, generate its zkVM proof, publish the finalized
    /// block to DA, and commit the staged sequencer only on success.
    ///
    /// Every fallible step (execution, proving, proof verification and DA)
    /// operates on a clone. State, tip, mempool and seen hashes are installed
    /// as one atomic commit, so an unavailable DA layer or failed proof leaves
    /// the sequencer exactly as it was.
    pub async fn build_and_submit_block(&mut self, max_txs: Option<u32>) -> Result<Block> {
        let pre_state = self.state.clone();
        let stateroot_pre = pre_state.root().hash();
        let backend_witness = postcard::to_allocvec(&pre_state.snapshot())
            .map_err(|e| Error::Serialization(format!("backend witness encode: {e}")))?;

        let mut staged = self.clone();
        let mut block = staged.build_block(max_txs)?;

        // The fork is resolved from the candidate height, not the committed
        // tip. Reject before proving if the header advertises another guest.
        let fork = staged
            .stf
            .active_fork_at(block.header.number)
            .ok_or_else(|| {
                Error::Fork(format!("no active fork at height {}", block.header.number))
            })?;
        if fork.guest_hash != block.header.guest_hash {
            return Err(Error::Fork(format!(
                "block {} guest hash is not approved for fork {}",
                block.header.number, fork.fork_id
            )));
        }

        let stateroot_post = block.header.state_root.hash();
        let proof_commitment =
            ProofCommitment::new(&block.header, stateroot_pre, &block.transactions)?;
        let commitment = proof_commitment.hash()?;
        let block_hash = *commitment.as_bytes();
        let transition = ProveBlockTransition {
            version: 1,
            height: block.header.number,
            block_hash,
            stateroot_pre,
            stateroot_post,
            guest_hash: block.header.guest_hash,
            commitment: proof_commitment,
            transactions: block.transactions.clone(),
            backend_witness,
        };
        transition.validate()?;

        let bundle: ProofBundleResponse = staged
            .prover
            .prove_block(ProveBlockRequest {
                version: 1,
                api_version: 1,
                height: transition.height,
                block_hash: transition.block_hash,
                stateroot_pre: transition.stateroot_pre,
                stateroot_post: transition.stateroot_post,
                guest_hash: transition.guest_hash,
                commitment: transition.commitment.clone(),
                transactions: transition.transactions.clone(),
                backend_witness: transition.backend_witness.clone(),
            })
            .await?;
        Self::validate_bundle(
            &bundle,
            &transition,
            commitment,
            stateroot_pre,
            stateroot_post,
        )?;

        let proof = ZkProof {
            version: 1,
            proof_bytes: bundle.proof_bytes,
            public_inputs: bundle.public_inputs,
            guest_id: bundle.guest_id,
            guest_hash: bundle.guest_hash,
            stateroot_pre: bundle.stateroot_pre,
            commitment: bundle.commitment,
        };
        if let Some(backend) = staged.backend.as_ref() {
            if !backend.verify_block_transition(&transition, &proof)? {
                return Err(Error::InvalidProof(
                    "produced proof failed backend verification".into(),
                ));
            }
        }

        // Attach the self-describing envelope and stable DA key before
        // publication. `header_hash` excludes `proof` and `da_ref` does not
        // participate in the proof commitment, so the binding stays stable.
        block.header.proof = Some(encode_header_proof(&proof)?);
        block.header.da_ref = commitment;
        let block_bytes = serde_json::to_vec(&block)
            .map_err(|e| Error::Serialization(format!("block encode: {e}")))?;
        let post = staged
            .da
            .post_block(PostBlockRequest {
                version: 1,
                api_version: 1,
                block_bytes: block_bytes.clone(),
                commitment: Some(commitment),
            })
            .await?;
        if !post.available {
            return Err(Error::Consensus(
                "data availability submission unavailable".to_string(),
            ));
        }
        self.p2p
            .publish_block(PublishBlockRequest {
                version: 1,
                api_version: 1,
                block: block.clone(),
            })
            .await?;

        // Single commit point: all of state, header, mempool and seen hashes
        // come from `staged` together.
        staged.last_header = Some(block.header.clone());
        staged.state.last_header = staged.last_header.clone();
        *self = staged;
        Ok(block)
    }

    /// Escape hatch: submit a transaction directly to the data availability
    /// layer, bypassing sequencer mempool admission, and return the DA
    /// reference assigned to the submission.
    ///
    /// The transaction still passes fail-closed structural and signature
    /// validation before it is published.
    pub async fn submit_tx_direct(&mut self, tx: Transaction) -> Result<H256> {
        self.mempool.validator.validate(&tx)?;
        let tx_bytes = serde_json::to_vec(&tx)
            .map_err(|e| Error::Serialization(format!("transaction encode: {e}")))?;
        let post = self
            .da
            .post_tx(workstream_core::traits::da::PostTxRequest {
                version: 1,
                api_version: 1,
                tx_bytes: tx_bytes.clone(),
            })
            .await?;
        if !post.available {
            return Err(Error::Consensus(
                "data availability submission unavailable".to_string(),
            ));
        }
        Ok(Hash::sha256(&tx_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workstream_crypto::signature;
    use workstream_stf::encode_payload;
    use workstream_stf::{
        mvp_genesis_schedule, ActorGrantPayload, ActorRegisterPayload, ActorRole, Capability,
        ProjectCreatePayload,
    };
    use workstream_tx::TxBuilder;

    /// Deterministic Ed25519 signer for admission fixtures: signatures must
    /// be reproducible so identical transactions hash identically (dedup) and
    /// replay enforcement stays deterministic.
    fn signing_key(tag: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[tag; 32])
    }

    /// Account IDs are derived from the signing key so the fixture satisfies
    /// transaction admission's signer/account ownership check.
    fn account(tag: u8) -> AccountId {
        workstream_core::Hash::sha256(signing_key(tag).verifying_key().as_bytes())
    }

    fn seq_tx(tag: u8, seq: u64, t: ActionType, payload: Vec<u8>) -> Transaction {
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

    fn mvp_sequencer() -> Sequencer {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        Sequencer::new(stf)
    }

    #[test]
    fn sequencer_state_round_trips_through_disk() {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        let sequencer = Sequencer::new(stf.clone());
        let dir =
            std::env::temp_dir().join(format!("workstream-sequencer-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        sequencer.save_state(&dir).unwrap();
        let restored =
            Sequencer::load_state(stf, Arc::new(crate::da::InMemoryDaClient::new()), &dir).unwrap();
        assert_eq!(restored.tip(), sequencer.tip());
        assert_eq!(restored.state().root(), sequencer.state().root());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sequencer_build_and_submit_block_publishes_to_da() {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        let da = Arc::new(crate::da::InMemoryDaClient::new());
        let mut sequencer = Sequencer::with_da(stf, da);

        let block = sequencer.build_and_submit_block(None).await.unwrap();
        assert_eq!(block.header.number, 1);
        assert_ne!(block.header.da_ref, H256::ZERO);
    }

    #[tokio::test]
    async fn sequencer_escape_hatch_submits_tx_directly_to_da() {
        let stf = StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap();
        let da = Arc::new(crate::da::InMemoryDaClient::new());
        let mut sequencer = Sequencer::with_da(stf, da);

        let pending_before = sequencer.pending();
        let da_ref = sequencer
            .submit_tx_direct(seq_tx(0x11, 0, ActionType::ActorRegister, b"x".to_vec()))
            .await
            .unwrap();
        assert_ne!(da_ref, H256::ZERO);
        // Direct submission bypasses mempool admission/queueing.
        assert_eq!(sequencer.pending(), pending_before);

        let mut bad = seq_tx(0x11, 1, ActionType::ActorRegister, b"y".to_vec());
        bad.signature = None;
        let err = sequencer.submit_tx_direct(bad).await.unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got {err:?}");
    }

    #[test]
    fn tx_root_is_deterministic_and_order_sensitive() {
        let empty = tx_root(&[]);
        assert_eq!(empty, tx_root(&[]));

        let a = tx_hash(&seq_tx(1, 0, ActionType::ActorRegister, b"x".to_vec())).unwrap();
        let b = tx_hash(&seq_tx(2, 0, ActionType::ActorRegister, b"y".to_vec())).unwrap();

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
        let tx = seq_tx(1, 0, ActionType::ActorRegister, b"a".to_vec());
        let hash = mempool.submit(tx.clone()).unwrap();
        assert_eq!(mempool.len(), 1);

        // duplicate submission rejected
        assert!(mempool.submit(tx).is_err());
        assert_eq!(mempool.len(), 1);
        assert_ne!(hash, H256::ZERO);

        // well-formedness: empty actions and Zero fee rejected
        let mut bad = seq_tx(2, 0, ActionType::ActorRegister, b"b".to_vec());
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
            .submit(seq_tx(1, 0, ActionType::ActorRegister, b"a".to_vec()))
            .unwrap();
        assert!(mempool
            .submit(seq_tx(1, 1, ActionType::ActorRegister, b"b".to_vec()))
            .is_err());
    }

    fn actor_set() -> (Transaction, Transaction) {
        let sponsor = seq_tx(
            0x11,
            0,
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })
            .unwrap(),
        );
        let worker = seq_tx(
            0x22,
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
            0x11,
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
            0x11,
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
                0x22,
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
