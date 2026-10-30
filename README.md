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
# Build the workspace
cargo build

# Run tests
cargo test

# Run with tracing
RUST_LOG=debug cargo test
```

## Development

This is a research implementation following the specifications in the design documents. See the research papers for detailed rationale.

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
