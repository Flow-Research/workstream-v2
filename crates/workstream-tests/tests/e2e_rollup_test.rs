//! End-to-end rollup proof integration (issue #83).
//!
//! Exercises the full path: signed transaction -> sequencer execution ->
//! prover output attached to the block header -> DA publication/retrieval ->
//! node sync/apply with proof verification. Tampered and missing proofs are
//! rejected before any state is committed.

use std::sync::Arc;

use workstream_core::hash::{Hash, H256};
use workstream_core::traits::prover::{ProveBlockTransition, ZkvmBackend};
use workstream_core::types::*;
use workstream_crypto::signature;
use workstream_node::{MemoryBlockSource, Node};
use workstream_prover::{
    decode_header_proof, encode_header_proof, InMemoryVerifier, InMemoryZkBackend,
};
use workstream_sequencer::{header_hash, InMemoryDaClient, Sequencer};
use workstream_stf::{
    encode_payload, mvp_genesis_schedule, ActorRegisterPayload, ActorRole, StateTransitionFunction,
};
use workstream_tx::TxBuilder;

fn account() -> AccountId {
    H256::from_bytes([0x11; 32])
}

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

fn register_tx() -> Transaction {
    let mut tx = TxBuilder::new()
        .chain_id(1)
        .account(account())
        .nonce(0, 0)
        .add_action(
            ActionType::ActorRegister,
            encode_payload(&ActorRegisterPayload {
                role: ActorRole::Sponsor,
            })
            .unwrap(),
        )
        .fee(FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1_000,
        })
        .build()
        .unwrap();
    signature::sign_tx_ed25519(&mut tx, &signing_key()).unwrap();
    tx
}

fn stf() -> StateTransitionFunction {
    StateTransitionFunction::with_schedule(mvp_genesis_schedule().unwrap()).unwrap()
}

fn required_proof_node(block: Block, backend: Arc<dyn ZkvmBackend>) -> Node<MemoryBlockSource> {
    let mut source = MemoryBlockSource::new();
    source.push(block);
    Node::with_verifier(
        stf(),
        mvp_genesis_schedule().unwrap(),
        source,
        Arc::new(InMemoryVerifier::with_backend(backend)),
    )
    .require_proof()
}

#[tokio::test]
async fn execute_prove_publish_verify_round_trip() {
    let stf = stf();
    let backend: Arc<dyn ZkvmBackend> = Arc::new(InMemoryZkBackend::with_stf(stf.clone()));
    let da = Arc::new(InMemoryDaClient::new());
    let mut sequencer = Sequencer::with_da_and_backend(stf.clone(), da.clone(), backend.clone());

    sequencer.submit_tx(register_tx()).unwrap();
    let stateroot_pre = sequencer.state().root().smt_root;

    // Execute + prove + publish.
    let block = sequencer.build_and_submit_block(Some(1)).await.unwrap();
    assert_eq!(block.header.number, 1);
    assert_eq!(block.transactions.len(), 1);

    // The header carries the full prover envelope, not just proof bytes.
    let header_proof = block
        .header
        .proof
        .as_ref()
        .expect("proof attached to header");
    let envelope = decode_header_proof(header_proof).unwrap();
    assert_eq!(envelope.stateroot_pre, stateroot_pre);
    assert_eq!(
        envelope.public_inputs,
        block.header.state_root.smt_root.as_bytes().to_vec()
    );
    let transition = ProveBlockTransition {
        version: 1,
        block_hash: *header_hash(&block.header).unwrap().as_bytes(),
        stateroot_pre,
        transactions: block.transactions.clone(),
    };
    assert!(backend
        .verify_block_transition(&transition, &envelope)
        .unwrap());

    // DA returns the final, self-verifying bytes (including the proof).
    let published = serde_json::to_vec(&block).unwrap();
    let da_id = format!("da:{}", Hash::sha256(&published).to_hex());
    let from_da_bytes = da
        .get_block_bytes(&da_id)
        .await
        .unwrap()
        .expect("block published to DA");
    let from_da: Block = serde_json::from_slice(&from_da_bytes).unwrap();
    assert_eq!(from_da.header, block.header);
    assert_eq!(
        serde_json::to_vec(&from_da.transactions).unwrap(),
        serde_json::to_vec(&block.transactions).unwrap()
    );

    // Node sync/apply verifies the DA-retrieved proof before committing state.
    let mut node = required_proof_node(from_da.clone(), backend.clone());
    let results = node.sync().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(node.state_root(), sequencer.state().root());
    assert_eq!(node.last_header().unwrap(), &from_da.header);

    // A tampered proof is rejected even though the header hash is unchanged.
    let mut tampered = from_da.clone();
    let mut bad_envelope = decode_header_proof(tampered.header.proof.as_ref().unwrap()).unwrap();
    bad_envelope.proof_bytes[0] ^= 0xff;
    tampered.header.proof = Some(encode_header_proof(&bad_envelope).unwrap());
    let err = required_proof_node(tampered, backend.clone())
        .apply_next()
        .unwrap_err();
    assert!(err.to_string().contains("zk proof verification failed"));

    // A missing proof is rejected when the node requires proofs.
    let mut missing = from_da.clone();
    missing.header.proof = None;
    let err = required_proof_node(missing, backend)
        .apply_next()
        .unwrap_err();
    assert!(err.to_string().contains("has no attached zk proof"));
}
