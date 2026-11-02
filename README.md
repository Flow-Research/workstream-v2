# WorkStream

A sovereign zk-Rollup for governed work coordination, built from the design documented in the [Flow Research](../research/) repository. WorkStream implements the Workstream protocol as a verifiable state transition function proven in a zkVM.

## Overview

WorkStream is a sovereign zero-knowledge rollup where:
- **Canonical truth lives on-chain**: Rollup state root is canonical, not a database
- **Verifiable execution**: All state transitions are proven in a zkVM (RISC Zero/SP1)
- **Privacy by default**: Only commitments go on-chain, artifacts are encrypted off-rollup
- **Modular and extensible**: Clean separation of concerns with trait-based adapters
- **High testability**: Deterministic STF, comprehensive testing, property-based tests

## Architecture

Based on the research papers:
- [Workstream as a Sovereign zk-Rollup](../research/workstream-sovereign-zkrollup-paper/) - Operation-by-operation re-implementation
- [Encoding Workstream on a Sovereign zk-Rollup](../research/workstream-zkrollup-design-cases/) - Design rationale and encoding decisions

### Core Design Principles

1. **Deterministic State Transition**: Everything must be deterministic (no wall clocks, no floating point)
2. **Two-Structure State**: Sparse Merkle Tree for mutable objects + Merkle Mountain Range for append-only records
3. **SHA-256 Everywhere**: Content addressing, state commitments, all hashes use SHA-256
4. **Account Abstraction**: Modular validators for humans and agents
5. **Policy as Data**: Rules evaluated by a bounded interpreter, hash-locked
6. **Atomic Transactions**: Multi-action transactions with all-or-nothing semantics
7. **Private by Default**: Shielded notes for value, commitments for sensitive data

## Workspace Structure

```
workstream/
├── crates/
│   ├── workstream-core/      # Core types, traits, errors
│   ├── workstream-crypto/    # Hashing, Merkle trees, signatures
│   ├── workstream-state/     # State trie (SMT + MMR)
│   ├── workstream-tx/        # Transaction types and validation
│   ├── workstream-stf/       # State transition function
│   └── workstream-rlp/       # Serialization (RLP-style)
├── src/
│   ├── bin/                  # Binaries (sequencer, prover, node)
│   └── (shared modules)
├── tests/                    # Integration tests
├── docs/                     # Additional documentation
└── examples/                 # Usage examples
```

## Quick Start

```bash
# Verify tooling + build + test (first time)
./scripts/devsetup.sh

# Build the workspace
cargo build

# Run tests
cargo test

# Run with tracing
RUST_LOG=debug cargo test
```

### Makefile Targets

| Command | Description |
|---------|-------------|
| `make help` | Show all targets |
| `make build` | Build the workspace |
| `make test` | Run all tests |
| `make ci` | Run exactly what CI runs (fmt, clippy, test, doc) |
| `make run-sequencer` / `run-prover` / `run-node` | Run a component with example config |
| `make localnet-up` / `localnet-down` | Start/stop the dockerized localnet |

See `docs/dev/localnet.md` for the full development guide.

## Development

This is a research implementation following the specifications in the design documents. See the research papers for detailed rationale.

### Error Handling

All crates use the unified error type from `workstream-core`:

```rust
use workstream_core::{Error, Result};

fn validate_input(input: &[u8]) -> Result<()> {
    if input.is_empty() {
        return Err(Error::Validation("input cannot be empty".to_string()));
    }
    Ok(())
}
```

Error features:
- **Categories**: `ErrorCategory` classifies errors (State, Crypto, Validation, etc.)
- **Error codes**: Stable numeric codes via `err.code()` for programmatic handling
- **Retryability**: `err.is_retryable()` and `err.is_fatal()` helpers
- **Conversions**: `From<std::io::Error>` and `From<serde_json::Error>` impls

### Configuration

All binaries load configuration from `workstream_core::config` with this precedence (later wins):

1. Built-in defaults
2. TOML file (`--config path/to/file.toml`)
3. Environment overrides (e.g. `WORKSTREAM_SEQUENCER_PORT=9000`)
4. CLI flags (e.g. `--port 9000`)

```toml
# config/sequencer.toml
port = 8545
mempool_size = 10000
block_interval_ms = 2000
log_level = "info"
```

```bash
# Run with a config file
workstream-sequencer --config config/sequencer.toml

# Override via environment
WORKSTREAM_SEQUENCER_PORT=9000 workstream-sequencer
```

Example configs live in `config/*.example.toml`. Every config struct has
`validate()`, `apply_env_overrides()`, and `Default` implementations.

### Fork Gating

Consensus upgrades are hard forks activated by block height via `ForkSchedule`
(see `docs/ARCHITECTURE.md`). Headers are validated against the schedule; the
STF gates actions by fork feature flags. Resolution is a pure function of
height — fully deterministic for the zkVM.
### Logging

All binaries use `workstream_core::logging` for tracing:

```rust
use workstream_core::logging;

fn main() {
    logging::init_tracing();  // respects RUST_LOG, safe to call multiple times
    tracing::info!("component started");
}
```

Log macros are available: `log_error!`, `log_warn!`, `log_info!`, `log_debug!`, `log_trace!`.

### Key Components

- **State**: `State` with SMT for mutable objects and MMR for immutable records
- **Transactions**: 19 transaction types covering the full Workstream lifecycle
- **STF**: Deterministic state transition function
- **Accounts**: Account abstraction with modular validators
- **Policies**: Bounded DSL interpreter
- **Value**: Shielded notes with view keys

## Status

🚧 **Early Development** - This is a starter template based on the research design. Implementation in progress.

## License

Apache-2.0
