use workstream_core::{FeePayer, FeeSpec, Nonce, Transaction, H256};
use workstream_prover::risc0;
use workstream_state::State;
use workstream_stf::receipt::{Claim, Witness};

#[test]
#[ignore = "requires r0vm and WORKSTREAM_GUEST_IMAGE"]
fn real_receipt_binds_image_roots_and_execution() {
    let image = std::fs::read(std::env::var("WORKSTREAM_GUEST_IMAGE").unwrap()).unwrap();
    let approved = risc0::image_id(&image).unwrap();
    let state = State::new();
    let root = state.root().hash();
    let mut w = Witness {
        before: state.snapshot(),
        height: 1,
        block_hash: H256::from_bytes([7; 32]),
        pre: root,
        post: root,
        transactions: vec![],
    };
    let bytes = risc0::prove(&image, approved, &w).unwrap();
    let mut claim = Claim::new(1, w.block_hash, root, root, &[]).unwrap();
    risc0::verify(&bytes, approved, &claim).unwrap();
    assert!(risc0::verify(&bytes, H256::ZERO, &claim).is_err());
    claim.post = H256::ZERO;
    assert!(risc0::verify(&bytes, approved, &claim).is_err());
    w.post = H256::ZERO;
    assert!(risc0::prove(&image, approved, &w).is_err());
    w.post = root;
    w.transactions.push(Transaction {
        chain_id: 1,
        account: H256::ZERO,
        nonce: Nonce { key_id: 0, seq: 0 },
        fee: FeeSpec {
            payer: FeePayer::Self_,
            asset_id: 0,
            max_fee: 1,
        },
        actions: vec![],
        auth: vec![],
        signature: None,
        public_key: None,
    });
    assert!(risc0::prove(&image, approved, &w).is_err());
    println!(
        "verified {}-byte RISC Zero receipt for guest {approved}",
        bytes.len()
    );
}
