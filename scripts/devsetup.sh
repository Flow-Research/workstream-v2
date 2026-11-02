#!/usr/bin/env bash
# Development environment setup: verify required tooling is present.
# Usage: ./scripts/devsetup.sh
set -euo pipefail

cd "$(dirname "$0")/.."

MISSING=0

have() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "OK     $1 ($($1 --version 2>/dev/null | head -n1))"
    else
        echo "MISSING $1 - $2"
        MISSING=1
    fi
}

echo "==> Checking tooling"
have git "Install git: https://git-scm.com"
if command -v rustc >/dev/null 2>&1; then
    echo "OK     rustc ($(rustc --version))"
else
    echo "MISSING rustc - Install rustup: https://rustup.rs"
    MISSING=1
fi
have cargo "Install rustup: https://rustup.rs"
have docker "Optional for localnet: https://docs.docker.com"
have make "Install make: xcode-select --install (macOS) or apt install make (Linux)"

if [ "$MISSING" -ne 0 ]; then
    echo
    echo "Some tools are missing. Install them and re-run."
    exit 1
fi

echo
echo "==> Building workspace (this may take a few minutes on first run)..."
cargo build --workspace

echo
echo "==> Running tests..."
cargo test --workspace

echo
echo "Development environment ready. Try: make help"
