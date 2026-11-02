# Localnet — Local Development Environment

This guide explains how to run the full WorkStream component stack
(sequencer, prover, node) locally for development.

## Prerequisites

- **Rust** (via [rustup](https://rustup.rs)) for building/testing
- **Docker** (optional) for the containerized localnet
- **make** for the Makefile targets

If you are starting fresh, run the setup script and it will verify everything:

```bash
./scripts/devsetup.sh
```

## Option 1: Run components natively

Each binary reads a TOML config file with this precedence
(later wins): built-in defaults → TOML file → `WORKSTREAM_*` env vars → CLI flags.

```bash
# Terminal 1 — sequencer (RPC on :8545)
make run-sequencer

# Terminal 2 — prover
make run-prover

# Terminal 3 — node (P2P on :30303)
make run-node
```

Override ports or log levels without editing the example configs:

```bash
WORKSTREAM_SEQUENCER_PORT=9000 make run-sequencer
WORKSTREAM_NODE_P2P_PORT=30304 make run-node
WORKSTREAM_PROVER_ZKVM=sp1 make run-prover
```

## Option 2: Run the localnet in Docker

```bash
make localnet-up      # build + start all three services
make localnet-status  # show service state
make localnet-logs    # tail logs
make localnet-down    # stop + remove containers
```

Services after startup:

| Service   | Container     | Port  | Purpose                          |
|-----------|---------------|-------|----------------------------------|
| sequencer | `ws-sequencer`| 8545  | Transaction ordering, mempool    |
| prover    | `ws-prover`   | 8080  | zkVM proof generation            |
| node      | `ws-node`     | 30303 | Proof verification, canonical state |

## Development loop

```bash
make help        # overview of all targets
make ci          # run exactly what CI runs
make test-doc    # documentation tests
make clippy-fix  # auto-fix lint suggestions
```

Useful scripts:

```bash
./scripts/check.sh       # CI parity checks
./scripts/devsetup.sh    # tool verification + build + test
./scripts/localnet-up.sh # dockerized localnet
./scripts/localnet-down.sh
```

## Notes

- All binaries use the shared `workstream-core` config system
  (`config/*.example.toml`). Copy examples to `config/*.toml` for
  project-specific overrides that stay untracked.
- The config system is documented in `docs/ARCHITECTURE.md` → *Configuration*.
- Logs respect `RUST_LOG`/`log_level` config; defaults are `info`.
