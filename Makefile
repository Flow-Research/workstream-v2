# WorkStream Makefile
# Development targets and localnet orchestration

.PHONY: help build build-release check test test-verbose fmt fmt-check clippy clippy-fix \
        doc clean run-sequencer run-prover run-node \
        localnet-up localnet-down localnet-logs localnet-status localnet-restart \
        docker-build ci

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Build & test
# ---------------------------------------------------------------------------

build: ## Build the workspace (debug)
	cargo build --workspace

build-release: ## Build the workspace (release, optimized)
	cargo build --release --workspace

check: ## Type-check without full codegen
	cargo check --workspace --all-targets

test: ## Run all tests
	cargo test --workspace

test-verbose: ## Run tests with output captured disabled
	cargo test --workspace -- --nocapture

test-doc: ## Run documentation tests
	cargo test --doc --workspace

# ---------------------------------------------------------------------------
# Lint & format
# ---------------------------------------------------------------------------

fmt: ## Auto-format all Rust code
	cargo fmt --all

fmt-check: ## Verify formatting (CI parity)
	cargo fmt --all -- --check

clippy: ## Run clippy with CI settings
	cargo clippy --workspace --all-targets --all-features -- -D warnings

clippy-fix: ## Auto-apply clippy suggestions where possible
	cargo clippy --fix --workspace --allow-dirty --allow-staged

doc: ## Build documentation (warnings are errors, CI parity)
	cargo doc --workspace --no-deps

clean: ## Remove build artifacts
	cargo clean

# ---------------------------------------------------------------------------
# Run components (single process each)
# ---------------------------------------------------------------------------

run-sequencer: ## Run the sequencer (IP 8545) with example config
	cargo run -q -p workstream-sequencer -- --config config/sequencer.example.toml

run-prover: ## Run the prover with example config
	cargo run -q -p workstream-prover -- --config config/prover.example.toml

run-node: ## Run the node with example config
	cargo run -q -p workstream-node -- --config config/node.example.toml

# ---------------------------------------------------------------------------
# Localnet (docker compose)
# ---------------------------------------------------------------------------

localnet-up: ## Start the localnet (build + start all services)
	docker compose -f docker-compose.yml up -d --build

localnet-down: ## Stop the localnet and remove containers
	docker compose -f docker-compose.yml down --volumes

localnet-logs: ## Tail localnet logs
	docker compose -f docker-compose.yml logs -f --tail=50

localnet-status: ## Show localnet service status
	docker compose -f docker-compose.yml ps

localnet-restart: ## Restart the localnet from scratch (builder image reused)
	docker compose -f docker-compose.yml down --volumes
	docker compose -f docker-compose.yml up -d --build

docker-build: ## Build the workstream docker image only
	docker build -t workstream:dev .

# ---------------------------------------------------------------------------
# CI parity
# ---------------------------------------------------------------------------

ci: ## Run the exact checks CI runs (fmt, clippy, test, doc)
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace
	cargo test --doc --workspace
	@echo "All CI checks passed."
