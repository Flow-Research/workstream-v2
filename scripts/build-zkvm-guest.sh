#!/usr/bin/env bash
# Build with rust-src (tested with rustc 1.92, LLVM lower-atomic pass).
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: build-zkvm-guest.sh OUTPUT.r0bf}
RUSTC_BOOTSTRAP=1 \
  CARGO_TARGET_RISCV32IM_RISC0_ZKVM_ELF_RUSTFLAGS='--cfg getrandom_backend="unsupported" -C passes=lower-atomic -C link-arg=-Ttext=0x00200800' \
  cargo build --locked --release --manifest-path zkvm/guest/Cargo.toml \
    --target riscv32im-risc0-zkvm-elf -Zbuild-std=std,panic_abort \
    -Zbuild-std-features=compiler-builtins-mem
cargo run -q -p workstream-prover --example package_guest -- \
    zkvm/guest/target/riscv32im-risc0-zkvm-elf/release/workstream-stf-guest "$out"
