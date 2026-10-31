# Design: Interfaces and Boundaries

*Issue: #13*  
*Type: Spike*  
*Status: In Progress*  
*Date: Sat Oct 31 2026*

## Problem Statement

FlowStream (WorkStream) needs strict, versioned interfaces between components (sequencer, prover, node, DA client) similar to Ethereum's Engine API. Currently components are coupled through shared types and there are no explicit boundaries. This spike defines the contracts.

## Goals

1. Define trait boundaries for all major components
2. Establish versioning strategy for APIs
3. Separate DTOs (wire format) from internal types
4. Enable independent upgrades of components
5. Support multiple implementations

## Current State

- Binaries exist as stubs (sequencer, prover, node)
- Shared types in `workstream-core`
- No explicit interfaces/traits for component communication
- Components would need to share internal types

## Requirements

- All cross-process/component communication via versioned interfaces
- No internal implementation types leak across boundaries
- APIs must be versionable and backward compatible where possible
- Support for process separation (can run as separate processes later)
- Deterministic serialization for all wire formats

## Design Options

### Option 1: Trait-based in-process only
- Pros: Simple, Rust-native, easy to test
- Cons: Doesn't enforce process separation, easy to leak types
- Verdict: Good for now, can evolve to IPC later

### Option 2: gRPC/Protobuf with strict schemas
- Pros: Language agnostic, strong versioning
- Cons: Overhead, more complex setup
- Verdict: Good for future, maybe overkill now

### Option 3: Trait-based + versioned DTOs (Recommended)
- Pros: Rust-native, enforces separation, easy to serialize later
- Cons: Still in-process by default
- Verdict: Best fit for current needs

## Recommended Design

Use trait-based interfaces in `workstream-core/src/traits/` with versioned DTOs.

### Component Boundaries

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Sequencer   │     │    Prover    │     │     Node     │
│              │     │              │     │   (Verifier) │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │    SequencerApi    │    ProverApi       │
       └──────────┬─────────┴──────────┬─────────┘
                  │                    │
              ┌───▼───┐            ┌───▼───┐
              │   DA  │            │  Core │
              │ Client│            │ Types │
              └───────┘            └───────┘
```

## API Sketch

### 1. Sequencer API
```rust
#[async_trait]
pub trait SequencerApi {
    fn api_version(&self) -> u32 { 1 }
    
    async fn submit_tx(&self, req: SubmitTxRequest) -> Result<SubmitTxResponse>;
    async fn get_mempool_status(&self) -> Result<MempoolStatus>;
    async fn build_block(&self, req: BuildBlockRequest) -> Result<BlockHeaderDraft>;
}
```

### 2. Prover API
```rust
#[async_trait]
pub trait ProverApi {
    fn api_version(&self) -> u32 { 1 }
    
    async fn prove_block(&self, req: ProveBlockRequest) -> Result<ProofBundleResponse>;
    async fn get_supported_guests(&self) -> Result<Vec<GuestInfo>>;
    async fn get_prover_status(&self) -> Result<ProverStatus>;
}
```

### 3. Verifier API
```rust
#[async_trait]
pub trait VerifierApi {
    fn api_version(&self) -> u32 { 1 }
    
    async fn verify_block(&self, req: VerifyBlockRequest) -> Result<VerifyBlockResponse>;
    async fn verify_proof(&self, req: VerifyProofRequest) -> Result<VerifyProofResponse>;
}
```

### 4. DA Client API
```rust
#[async_trait]
pub trait DaClient {
    fn api_version(&self) -> u32 { 1 }
    
    async fn post_block(&self, req: PostBlockRequest) -> Result<PostBlockResponse>;
    async fn get_block(&self, req: GetBlockRequest) -> Result<GetBlockResponse>;
    async fn get_availability(&self) -> Result<AvailabilityInfo>;
}
```

## Versioning Strategy

1. **API Version**: Each trait has `api_version()` method, increment on breaking changes
2. **Request/Response Versioning**: All DTOs include `version: u32` field
3. **Backward Compatibility**: Support N-1 versions where reasonable
4. **Version Negotiation**: Components can check compatibility
5. **Fork ID**: Separate from API version, tied to consensus forks

## DTO vs Internal Types

**DTOs (Wire Format):**
- In `workstream-core/src/types/api.rs` or per-trait modules
- Serializable with `serde`
- Versioned
- Canonical encoding for consensus-critical data
- No internal references

**Internal Types:**
- In respective crates
- Can have complex structures
- Not exposed across boundaries

## Invariants

1. No internal crate types leak across trait boundaries
2. All DTOs are versioned
3. API versions checked on calls
4. Serialization is deterministic
5. Traits are object-safe where needed
6. Errors use `workstream-core::Error`

## Implementation Plan

1. Create `crates/workstream-core/src/traits/` directory
2. Create `mod.rs` and individual trait files
3. Create DTO types in `workstream-core/src/types/api/`
4. Add `async-trait` dependency (already present)
5. Update `workstream-core/src/lib.rs` to export traits
6. Add basic tests

## Test Plan

- [ ] All traits compile
- [ ] DTOs serialize/deserialize correctly
- [ ] Version checking works
- [ ] No internal type leakage (compile-time check)
- [ ] Example implementations compile

## Open Questions

1. Should we use `async_trait` or native async traits? (Rust version supports native async traits in traits now, but `async_trait` is more compatible)
2. Do we need sync versions of APIs?
3. Should traits be in core or separate crate?
4. How to handle streaming for large data?

## Follow-up Implementation Issues

- `feat(core): define versioned component traits` - Implement the traits
- `feat(core): api types and serialization` - DTO definitions
- `feat(core): api version negotiation` - Version checking logic

## Conclusion

The trait-based approach with versioned DTOs provides the right balance of flexibility and structure. This mirrors Ethereum's Engine API philosophy while being Rust-native and suitable for a zkRollup.

## References

- [Ethereum Engine API](https://github.com/ethereum/execution-apis/blob/main/src/engine/)
- [WorkStream Architecture](../../docs/ARCHITECTURE.md)
- [Ethereum Upgrade Patterns](../design-patterns/ethereum-upgrade-patterns-for-flowstream.md)
