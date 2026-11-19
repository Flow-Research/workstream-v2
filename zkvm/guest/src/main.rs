#![no_main]
risc0_zkvm::guest::entry!(main);

fn main() {
    use risc0_zkvm::guest::env;
    let mut len = [0u8; 4];
    env::read_slice(&mut len);
    let len = u32::from_le_bytes(len) as usize;
    assert!(len <= 16 * 1024 * 1024, "oversized witness");
    let mut input = vec![0u8; len];
    env::read_slice(&mut input);
    let witness = postcard::from_bytes(&input).expect("invalid transition witness");
    let claim = workstream_stf::receipt::execute(witness).expect("invalid state transition");
    env::commit_slice(&postcard::to_allocvec(&claim).expect("encode transition journal"));
}
