#![no_main]
risc0_zkvm::guest::entry!(main);

fn main() {
    use risc0_zkvm::{guest::env, sha::Digest};
    let mut len = [0; 4];
    env::read_slice(&mut len);
    let len = u32::from_le_bytes(len) as usize;
    assert!(len <= 1024);
    let mut bytes = vec![0; len];
    env::read_slice(&mut bytes);
    let pair: workstream_stf::receipt::Pair = postcard::from_bytes(&bytes).unwrap();
    pair.validate().expect("discontinuous batch");
    let id = Digest::try_from(pair.leaf_image.as_bytes().as_slice()).unwrap();
    for claim in &pair.blocks {
        env::verify(id, &postcard::to_allocvec(claim).unwrap()).unwrap();
    }
    env::commit_slice(&postcard::to_allocvec(&pair).unwrap());
}
