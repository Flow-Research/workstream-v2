//! End-to-end rollup acceptance for issue #83.
//!
//! Exercises the full loop with the default in-memory backend:
//! execute (sequencer/STF) -> prove (guest commitment) -> publish (DA) ->
//! verify (node, before state commit). A real RISC Zero receipt is opt-in
//! behind `WORKSTREAM_GUEST_IMAGE`/`WORKSTREAM_GUEST_ID`; it must not be the
//! only coverage of this acceptance criterion.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use workstream_core::traits::da::{
    AvailabilityInfo, DaClient, GetBlockRequest, GetBlockResponse, PostBlockRequest,
    PostBlockResponse, PostTxRequest, PostTxResponse,
};
use workstream_core::traits::prover::ZkvmBackend;
use workstream_core::types::*;
use workstream_core::{Error, Result, H256};
use workstream_crypto::signature;
use workstream_node::{MemoryBlockSource, Node};
use workstream_prover::{decode_header_proof, encode_header_proof, InMemoryZkBackend};
use workstream_sequencer::{InMemoryDaClient, Sequencer};
use workstream_stf::{
    derive_project, derive_task, encode_payload, get_task, mvp_genesis_schedule,
    ActorRegisterPayload, ActorRole, ProjectCreatePayload, StateTransitionFunction,
    TaskCreatePayload,
};
use workstream_tx::TxBuilder;

#[path = "../../../tests/support/accounts.rs"]
mod accounts;
use accounts::{account, signer};

const SPONSOR_TAG: u8 = 11;

fn stf() -> StateTransitionFunction {
    StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap()
}

fn sponsor() -> AccountId {
    account(SPONSOR_TAG)
}

fn tx(sequence: u64, action_type: ActionType, payload: Vec<u8>) -> Transaction {
    let mut tx = TxBuilder::new()
        .chain_id(1)
        .account(sponsor())
        .nonce(0, sequence)
        .add_action(action_type, payload)
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1_000,
        })
        .build()
        .unwrap();
    signature::sign_tx_ed25519(&mut tx, &signer(sponsor())).unwrap();
    tx
}

fn register_sponsor() -> Transaction {
    tx(
        0,
        ActionType::ActorRegister,
        encode_payload(&ActorRegisterPayload {
            role: ActorRole::Sponsor,
        })
        .unwrap(),
    )
}

fn project_id() -> ProjectId {
    derive_project(&sponsor(), "rollup-project")
}

fn create_project() -> Transaction {
    tx(
        1,
        ActionType::ProjectCreate,
        encode_payload(&ProjectCreatePayload {
            title: "rollup-project".to_string(),
        })
        .unwrap(),
    )
}

fn task_id() -> TaskId {
    derive_task(&project_id(), "prove-the-block")
}

fn create_task() -> Transaction {
    // `task.create` is fork-gated by TASK_LIFECYCLE; the MVP genesis schedule
    // enables it, so its presence in block 2 proves fork context is carried
    // through execution, proving and node replay.
    tx(
        2,
        ActionType::TaskCreate,
        encode_payload(&TaskCreatePayload {
            project: project_id(),
            title: "prove-the-block".to_string(),
            award: 100,
        })
        .unwrap(),
    )
}

fn assert_published(block: &Block) {
    let proof = block.header.proof.as_ref().expect("missing zk proof");
    assert_eq!(proof.proof_type, ProofType::ZkVm);
    assert_ne!(block.header.guest_hash, H256::ZERO);
    assert_ne!(block.header.da_ref, H256::ZERO);
    // The proof binds the canonical commitment, never the DA reference.
    let decoded = decode_header_proof(proof).unwrap();
    assert_eq!(decoded.guest_hash, block.header.guest_hash);
    assert_eq!(
        decoded.public_inputs,
        block.header.state_root.hash().as_bytes().to_vec()
    );
}

fn node_for(block: Block) -> Node<MemoryBlockSource> {
    let mut source = MemoryBlockSource::new();
    source.push(block);
    Node::new(stf(), mvp_genesis_schedule().unwrap(), source).require_proof()
}

#[tokio::test]
async fn rollup_execute_prove_publish_verify() {
    let da = Arc::new(InMemoryDaClient::new());
    let mut sequencer = Sequencer::with_da(stf(), da.clone());

    sequencer.submit_tx(register_sponsor()).unwrap();
    sequencer.submit_tx(create_project()).unwrap();
    let block_one = sequencer.build_and_submit_block(Some(2)).await.unwrap();

    sequencer.submit_tx(create_task()).unwrap();
    let block_two = sequencer.build_and_submit_block(None).await.unwrap();

    assert_eq!(block_one.header.number, 1);
    assert_eq!(block_one.transactions.len(), 2);
    assert_eq!(block_two.header.number, 2);
    assert_eq!(block_two.transactions.len(), 1);
    assert_published(&block_one);
    assert_published(&block_two);

    // The node must be able to retrieve the exact published block using only
    // the reference committed in the header.
    let fetched = da
        .get_block(GetBlockRequest {
            version: 1,
            api_version: 1,
            da_id: format!("da:{}", block_one.header.da_ref.to_hex()),
        })
        .await
        .unwrap();
    let published: Block = serde_json::from_slice(&fetched.block_bytes.unwrap()).unwrap();
    assert_eq!(published.header, block_one.header);
    assert_eq!(
        serde_json::to_vec(&published.transactions).unwrap(),
        serde_json::to_vec(&block_one.transactions).unwrap()
    );

    // Verify both blocks through the node before accepting the chain tip.
    let mut source = MemoryBlockSource::new();
    source.push(block_one);
    source.push(block_two);
    let mut node = Node::new(stf(), mvp_genesis_schedule().unwrap(), source).require_proof();
    let results = node.sync().unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(node.tip(), 2);
    assert_eq!(node.state_root(), sequencer.state().root());
    assert!(get_task(node.state(), &task_id()).unwrap().is_some());
}

/// DA client that reports the first block publication as unavailable.
struct FlakyDaClient {
    inner: InMemoryDaClient,
    fail_first: AtomicBool,
}

impl FlakyDaClient {
    fn new() -> Self {
        Self {
            inner: InMemoryDaClient::new(),
            fail_first: AtomicBool::new(true),
        }
    }
}

#[async_trait]
impl DaClient for FlakyDaClient {
    async fn post_block(&self, req: PostBlockRequest) -> Result<PostBlockResponse> {
        if self.fail_first.swap(false, Ordering::SeqCst) {
            return Ok(PostBlockResponse {
                version: 1,
                api_version: 1,
                da_id: String::new(),
                available: false,
            });
        }
        self.inner.post_block(req).await
    }

    async fn get_block(&self, req: GetBlockRequest) -> Result<GetBlockResponse> {
        self.inner.get_block(req).await
    }

    async fn get_availability(&self) -> Result<AvailabilityInfo> {
        self.inner.get_availability().await
    }

    async fn post_tx(&self, req: PostTxRequest) -> Result<PostTxResponse> {
        self.inner.post_tx(req).await
    }
}

#[tokio::test]
async fn da_failure_rolls_back_then_retry_succeeds() {
    let da = Arc::new(FlakyDaClient::new());
    let backend: Arc<dyn ZkvmBackend> = Arc::new(InMemoryZkBackend::new(stf()));
    let mut sequencer = Sequencer::with_da_and_backend(stf(), da, backend);
    sequencer.submit_tx(register_sponsor()).unwrap();
    let empty_root = sequencer.state().root().hash();

    let err = sequencer.build_and_submit_block(None).await.unwrap_err();
    assert!(matches!(err, Error::Consensus(_)));
    assert_eq!(sequencer.tip(), 0);
    assert_eq!(sequencer.pending(), 1);
    assert_eq!(sequencer.state().root().hash(), empty_root);

    let block = sequencer.build_and_submit_block(None).await.unwrap();
    assert_eq!(block.header.number, 1);
    assert_eq!(sequencer.pending(), 0);
    assert_published(&block);

    let mut node = node_for(block);
    assert_eq!(node.apply_next().unwrap().unwrap().height, 1);
    assert_eq!(node.state_root(), sequencer.state().root());
}

async fn proved_block() -> Block {
    let mut sequencer = Sequencer::with_da(stf(), Arc::new(InMemoryDaClient::new()));
    sequencer.submit_tx(register_sponsor()).unwrap();
    sequencer.build_and_submit_block(None).await.unwrap()
}

#[tokio::test]
async fn node_rejects_tampered_and_missing_proofs() {
    let block = proved_block().await;

    let mut tampered = block.clone();
    let mut envelope = decode_header_proof(tampered.header.proof.as_ref().unwrap()).unwrap();
    envelope.proof_bytes[0] ^= 0xff;
    tampered.header.proof = Some(encode_header_proof(&envelope).unwrap());
    let err = node_for(tampered).apply_next().unwrap_err();
    assert!(err.to_string().contains("zk proof verification failed"));

    let mut missing = block;
    missing.header.proof = None;
    let err = node_for(missing).apply_next().unwrap_err();
    assert!(err.to_string().contains("no attached zk proof"));
}

#[tokio::test]
async fn node_rejects_guest_hash_mismatch_inside_proof() {
    let mut block = proved_block().await;
    let mut envelope = decode_header_proof(block.header.proof.as_ref().unwrap()).unwrap();
    envelope.guest_hash = H256::from_bytes([0xab; 32]);
    block.header.proof = Some(encode_header_proof(&envelope).unwrap());

    let err = node_for(block).apply_next().unwrap_err();
    assert!(err
        .to_string()
        .contains("commitment or public input mismatch"));
}
