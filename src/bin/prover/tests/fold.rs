use workstream_core::H256;
use workstream_prover::{fold, risc0};
use workstream_state::State;
use workstream_stf::mvp_genesis_schedule;
use workstream_stf::receipt::{Claim, Pair, Witness};

#[test]
#[ignore = "requires local r0vm and the two packaged guest images"]
fn recursive_pair_checks_both_receipts_and_intermediate_root() {
    let path = std::env::var("WORKSTREAM_GUEST_IMAGE").unwrap();
    let leaf = std::fs::read(&path).unwrap();
    let fold_image = std::fs::read(format!("{path}.fold")).unwrap();
    let leaf_image = risc0::image_id(&leaf).unwrap();
    let fold_id = risc0::image_id(&fold_image).unwrap();
    let prove = |height, state: &State| {
        let root = state.root().hash();
        let hash = H256::from_bytes([height as u8; 32]);
        let w = Witness {
            before: state.snapshot(),
            height,
            block_hash: hash,
            pre: root,
            post: root,
            transactions: vec![],
            schedule: mvp_genesis_schedule().unwrap(),
        };
        let bytes = risc0::prove(&leaf, leaf_image, &w).unwrap();
        (
            Claim::new(height, hash, root, root, &[]).unwrap(),
            bincode::deserialize::<risc0_zkvm::Receipt>(&bytes).unwrap(),
        )
    };
    let mut state = State::new();
    let (a, ra) = prove(1, &state);
    let (b, rb) = prove(2, &state);
    let mut pair = Pair {
        leaf_image,
        blocks: [a, b],
    };
    let receipt = fold::aggregate(&fold_image, fold_id, &pair, [ra.clone(), rb]).unwrap();
    assert!(matches!(
        receipt.inner,
        risc0_zkvm::InnerReceipt::Succinct(_)
    ));
    fold::verify(&receipt, fold_id, &pair).unwrap();
    // The second receipt is valid by itself but starts on a different state.
    state.set(b"other-state", b"1").unwrap();
    let (other, ro) = prove(2, &state);
    pair.blocks[1] = other;
    assert!(fold::aggregate(&fold_image, fold_id, &pair, [ra, ro]).is_err());
    assert!(fold::verify(&receipt, fold_id, &pair).is_err());
}
