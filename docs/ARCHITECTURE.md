# WorkStream Architecture

## Design Philosophy

WorkStream implements a sovereign zkRollup for the Workstream governed work protocol. The design follows the research documents in detail:

1. **Canonical truth in the rollup** - State root is canonical, not PostgreSQL
2. **Verifiable computation** - All transitions proven in zkVM
3. **Privacy by default** - Only commitments public
4. **Deterministic execution** - STF is a pure function
5. **Modular extensibility** - Trait-based architecture

## State Model

### Two-Structure Design

```rust
pub struct State {
    pub smt: SparseMerkleTree,      // Mutable lifecycle objects
    pub mmr: MerkleMountainRange,  // Immutable records
    pub version: u64,
}
```

**SMT (Sparse Merkle Tree)** for:
- accounts, grants, projects, guides, policies
- tasks in flight, claims, bundles
- queues, leases, governance state

**MMR (Merkle Mountain Range)** for:
- submissions (finalized)
- reviews, checker runs
- contribution records
- awards
- audit history

### Global State Root

```rust
pub struct StateRoot {
    pub version: u8,
    pub smt_root: H256,
    pub mmr_root: H256,
}
```

## Component Interfaces

All cross-component communication goes through versioned traits in `workstream-core/src/traits/`:
- `SequencerApi` - Transaction submission, mempool status, block building
- `ProverApi` - Proof generation for state transitions
- `VerifierApi` - Block and proof verification
- `DaClient` - Data availability layer interaction

DTOs are versioned (serde-serializable) and separate from internal types. See `docs/design/interfaces-and-boundaries.md` for the full design.

## Error Handling

All crates use the unified error type `workstream_core::Error`:
- `ErrorCategory` classifies errors (State, Crypto, Validation, etc.)
- Stable numeric `ErrorCode`s via `err.code()` for cross-boundary handling
- `is_retryable()` / `is_fatal()` helpers
- `From<std::io::Error>` and `From<serde_json::Error>` conversions

## Logging

Binaries initialize tracing via `workstream_core::logging::init_tracing()` (respects `RUST_LOG`, safe to call multiple times). Log macros `log_error!`, `log_warn!`, `log_info!`, `log_debug!`, `log_trace!` are exported.

## Transaction Flow

1. **Mempool** - Sequencer collects transactions
2. **Ordering** - Deterministic ordering in block
3. **Execution** - STF processes transactions atomically
4. **State Update** - State transitions applied
5. **Proving** - zkVM generates validity proof
6. **DA Publication** - Block data posted to DA layer
7. **Verification** - Full nodes verify proof

## Transaction Types

All 19 operations from the research:

### Identity & Access
- `ActorRegister`, `ActorLink`, `ActorGrant`, `ActorRevoke`, `ActorSuspend`, etc.

### Project & Governance
- `ProjectCreate`, `GuideIngest`, `PolicyCompile`, `PolicyApprove`, `GuideActivate`

### Work Lifecycle
- `TaskCreate`, `TaskScreen`, `TaskRelease`, `TaskClaim`, `TaskStart`
- `BundlePrepare`, `BundleAdmit`, `SubmissionCreate`

### Evaluation
- `CheckRun`, `RouteSubmission`

### Review
- `ReviewLease`, `ReviewDecide`

### Resolution
- `RevisionPrepare`, `AcceptFinal`

### Value & Reputation
- `AwardFulfill`, `ReputationProject`

### Governance
- `GovUpgrade`, `GovSetSequencer`, `GovSetParameters`

## Account Abstraction

Single account primitive with modular validators:

```rust
pub struct Account {
    pub id: AccountId,
    pub kind: AccountKind,      // Human, Agent, Service
    pub status: AccountStatus,
    pub validator: ValidatorRef,
    pub controllers: Vec<KeyRef>,
    pub delegate_of: Option<AccountId>,
    pub scope: Option<Scope>,
    // ...
}
```

Validators handle:
- **Human**: Passkey + device keys + recovery
- **Agent**: Delegated with scope/expiry or self-sovereign
- **Service**: Programmatic

## Policy System

Policies are data, evaluated by bounded interpreter:
- Hash-locked, versioned
- Deterministic evaluation
- Declared oracles for external inputs
- Total and terminating

## Value Model

Shielded notes over canonical asset registry:
- Native rollup asset (gas)
- Bridged stablecoins (USDC)
- Project points (soulbound)

Privacy via commitments and nullifiers, auditable via viewing keys.

## Proof Architecture

- **zkVM**: RISC Zero or SP1 (standard-hash friendly like Magnetar)
- **Batching**: Multiple transactions per proof
- **Folding**: Accumulate proofs across batches
- **Recursion**: Verify checker receipts inline
- **Precompiles**: Signature verification (minimal set)

## Security Considerations

See the research paper for full adversary analysis. Key points:
- Proves state transitions, doesn't make human review trustless
- Sequencer can censor (mitigated by escape hatch)
- Bridge has weaker guarantees than state validity
- Circuit governance is critical trust assumption

## Development Status

This is a starter template. Implementations are simplified for structure. Production would need:
- Full SMT/MMR implementations
- Complete STF logic for all operations
- zkVM integration
- P2P networking
- DA layer integration
- RPC server
- Indexer
- Wallet support
