use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "package_guest USER_ELF OUTPUT");
    println!(
        "{}",
        workstream_prover::risc0::package_file(Path::new(&args[1]), Path::new(&args[2])).unwrap()
    );
}
