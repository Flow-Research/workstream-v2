#!/usr/bin/env bash
# CI parity checks: run exactly what CI runs.
# Usage: ./scripts/check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt --all -- --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> cargo test"
cargo test --workspace

echo "==> cargo test --doc"
cargo test --doc --workspace

echo
echo "All checks passed."
