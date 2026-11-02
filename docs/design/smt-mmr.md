# Design: SMT/MMR — Approaches and APIs

*Issue: #17*
*Type: Spike*
*Status: Proposed*
*Date: Mon Nov 2 2026*

## Problem Statement

WorkStream commits its full state every block. The sequencer builds blocks, the
prover proves STF transitions between state roots, and the node verifies proofs
against the canonical root it tracks. All three need one shared, precisely
specified definition of the two structures the architecture already commits to
(`docs/ARCHITECTURE.md` → *Global State Root*):

- **Sparse Merkle Tree (SMT)** for mutable lifecycle state: accounts, grants,
  projects, guides, policies, tasks in flight, claims, bundles, queues, leases,
  governance state.
- **Merkle Mountain Range (MMR)** for append-only records: finalized
  submissions, reviews, checker runs, contribution records, awards, audit
  history.

Today these exist only as placeholder stubs in `workstream-crypto` (they
synthesize a root by concatenating the previous root with a salt — no membership,
no proofs, no persistence). Before #34/#35/#36 can be implemented we must pin
down algorithms, hashing rules, proof formats, and API boundaries. The STF
(#15) and sequencer (#16) will consume these roots, so the format must be final
early.

## Goals

1. Choose tree algorithms that support membership **and** (for the SMT)
   non-membership proofs.
2. Keep hashing inside the mandated primitives: SHA-256/SHA-3, per the project
   rule ("SHA-256 everywhere").
3. Make every operation deterministic: no wall clocks, no randomness, no
   iteration-order dependence — everything must re-verify inside a zkVM.
4. Keep proofs small enough to carry through the sequencer→prover→node path and
   to witness values read from older state roots.
5. Let the placeholder API surface (`root`/`update`/`get`, plus
   `append`/`proof` for the MMR) carry over with minimal churn in
   `workstream-state`.

## Requirements

- Fixed, consensus-serialized node encodings (postcard, as standardized in the
  dependency-upgrade PR #43).
- Content-addressed node storage keyed by node hash; historical roots stay
  readable (needed for fork gating / reorg re-application and prover witnesses).
- Domain-separated hashing of leaves, inner nodes, and peak bags to prevent
  second-preimage and cross-structure forgery (leaf-in-inner-node, SMT node in
  MMR peak, etc.).
- Batch update support for block execution: the sequencer applies dozens to
  thousands of key changes per block; sequential one-key paths are acceptable
  for MVP but the design must not preclude the one-phase batch algorithm.

## Design Options

### SMT variants

| Option | Summary | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A. Naive full-depth tree** | Materialize all 2^256 leaves; default hash fills empties | Simplest verifier | Memory/time absurd; unusable | Rejected |
| **B. Fixed-depth compressed SMT ("shortcut")** | Depth 256 by key; empty subtrees are a single hash; leaves hold `(key, value_hash)` | Standard rollup choice (zkSync Lite, Polygon zKEVM exit tree, ethrex); small proofs; non-existence proofs | Slightly more complex update/delete logic | **Chosen** |
| **C. Height-32 shallow tree** | Truncate keys to 32-bit lanes, shallow tree | Tiny proofs | Collisions across keyspace; not sound for 256-bit key space | Rejected |
| **D. ZigZag/one-phase batch mutations** | Batch-update algorithm over sorted changed keys (arXiv:2310.13328) | O(1) amortized per update inside a batch; halves hash work | Additional complexity; can be layered on B | Keep as optimization phase inside #34 |

### MMR variants

| Option | Summary | Pros | Cons | Verdict |
|---|---|---|---|---|
| **A. Classic MMR + peaked bagging** | Leaves fold into perfect subtrees (peaks); peaks bagged right-to-left; proofs carry path-in-peak + outer peaks, bound to leaf index and size | Essentially optimal append-only accumulator (eprint 2025/234); proven in practice (Beam, Zcash ZIP-221, Ethereum historical accumulators); O(log n) append and proof | Root changes every append; historical roots must be retained to keep old proofs valid | **Chosen** |
| **B. RFC 6962 certificate log** | Append-only with consistency proofs between sizes | Great for transparency-style auditing | Does not give non-existence or compact batch scans we need; duplicate of A functionally | Rejected for state log |
| **C. CBMT (merkle-cbt)** | Complete binary Merkle tree over a fixed list | Already a workspace dep | Fixed-size list; append requires re-hash; not incremental | Rejected for main log; dep can stay for one-off block-content trees |

## Recommended Design

### Hashing rules (consensus-relevant, fixed at V1)

`H(x)` = SHA-256. All multi-field preimages are length-prefixed by construction
of `Hash::sha256_concat` (existing utility in `workstream-core`). Domain tags
are ASCII, versioned:

| Node | Preimage |
|---|---|
| SMT empty | `H("WSMT:v1:EMPTY")` |
| SMT leaf | `H("WSMT:v1:L" ∥ key(32) ∥ value_hash(32))` |
| SMT inner | `H("WSMT:v1:N" ∥ left(32) ∥ right(32))` |
| MMR leaf | `H("WSMMR:v1:L" ∥ index_u64_le ∥ payload(32))` |
| MMR inner | `H("WSMMR:v1:N" ∥ left(32) ∥ right(32))` |
| MMR root bag | `H("WSMMR:v1:PEAKS" ∥ leaf_count_u64_le ∥ peaks[..])` |

- `key` is always H256. Natural identifiers (e.g. actor id) are hashed with
  `H("WSMT:v1:K" ∥ raw_id)` before insertion so arbitrary-length ids spread
  uniformly over the 256-bit space.
- `value_hash` = the content hash of the canonical serialization (postcard) of
  the stored state item — matching the existing `ContentId` convention. Large
  objects (policies, guides) are stored out-of-tree by their
  content-addressable blob store; the tree commits only to the hash.
- Tags are binding: leaf/inner preimages differ per structure, and the MMR bag
  includes `leaf_count` to glue proofs to a specific size.

### SMT data model

```
enum Node {
    Leaf { key: H256, value_hash: H256 },
    Inner { left: H256, right: H256 },   // hashes of children
}
// Empty subtree = EMPTY constant, not stored.
```

- **Contents model:** each existing leaf occupies the terminal node of its
  key's address. Above leaves, `Inner` nodes hash sibling pairs; empty subtrees
  are the `EMPTY` constant, so references to empty subtrees are elided —
  that is what makes proofs short (no materialized default leaves).
- **Insert/update:** walk the key's bits from the most significant; the first
  empty subtree becomes the leaf; on collision, split (extend shared prefix
  with inner nodes). Delete: remove leaf and contract inner chain while the
  sibling is empty (restore `EMPTY` reference), matching compressed-SMT
  semantics.
- **Storage:** `NodeStore` over the node map `H256 → Node` (postcard-encoded).
  Nodes are content-addressed so old roots remain fully readable; garbage
  collection of unreachable nodes is a node-level concern for later issues
  (an epoch scheme can be added in #36's follow-up; not required for proofs).
- **Depth:** fixed 256 (H256 keys). Tests may use reduced depth for
  performance; the depth is bound into proofs implicitly (proofs must consume
  exactly `depth − shared_prefix_length` siblings).

### MMR data model

- Append-only leaf log at index `0..n`; leaves also carry their explicit
  `index` in the preimage (removes any ambiguity about the position).
- Structure == set of perfect subtrees ("peaks"); a proof for index `i` at
  size `n` contains: leaf index, `n`, the sibling path inside `i`'s peak
  (leaf-first), and the other peaks' hashes (left of the peak / right of the
  peak). Verification recomputes structure from `n` alone — this length-binds
  every proof element (a proof cannot be replayed at another index or size).
- Retention: keep the (root, n) checkpoint per block in the state snapshot;
  a reorg replays the MMR from the fork point (leaves are immutable, so
  replay is hash-cheap — no structural rewrite overhead).

### API sketch (V1)

```
// workstream-crypto/src/smt.rs
trait NodeStore {
    fn get(&self, h: &H256) -> Option<Node>;
    fn put(&mut self, node: &Node) -> H256;
}

struct SmTree<S> { store: S, root: Option<H256> }   // None = empty tree
impl<S: NodeStore> SmTree<S> {
    fn get(&self, key: &H256) -> Result<Option<H256>>;      // value_hash
    fn update(&mut self, key: &H256, value: &[u8]) -> Result<()>;
    fn commit(&self) -> H256;                                // current root
    fn prove(&self, key: &H256) -> Result<SmtProof>;
}

// one-phase batch update is a #34 stretch goal (arXiv:2310.13328); V1 ships
// sequential updates per key.

pub struct SmtProof { kind: SmtProofKind, leaf, siblings, dir_bits }

// verification is implementation-free (node/proof serialization only):
pub fn verify_smt_proof(root: H256, proof: &SmtProof) -> bool;

// workstream-crypto/src/merkle.rs (upgrade of placeholder)
struct MmrTree { nodes: ... }
impl MmrTree {
    fn append(&mut self, payload_hash: H256) -> u64 /* index */;
    fn leaf_count(&self) -> u64;
    fn root(&self) -> Option<H256>;
    fn prove(&self, index: u64) -> Result<MmrProof>;
}
pub fn verify_mmr_proof(root: H256, proof: &MmrProof) -> bool;

// workstream-state (consumed like today):
StateRoot::new(self.smt.root(), self.mmr.root())
```

- Verification functions take only **serialized DTOs** (postcard), so the
  sequencer, node, prover circuit preamble, and any external verifier use one
  implementation with no trait leakage — consistent with the V1 interface
  rule from #13.
- Placeholder struct names (`SparseMerkleTree`, `MerkleMountainRange`) are
  kept; their internals get replaced in #34/#36 while `workstream-state`
  keeps compiling.

## Complexity & Proof-Size Notes

- SMT update: expected O(log₂ n) hash ops for n occupied keys with uniformly
  spread keys; empty-tree first insert = O(1) (leaf only).
- SMT proof size: empty subtrees are elided, so a leaf's sibling list is
  ≈ the number of *occupied* leaves it sits above ≈ log₂ n for uniformly
  spread keys; for 1M live values that is ~20 × 32B ≈ 640B
  (+ leaf payload). Non-existence proofs are the same shape, proving the
  deepest existing leaf in the missing key's prefix.
- MMR leaf storage: n leaves + n − popcount(n) inner nodes ≈ under ~64B/leaf.
  Append hash work: ≤ O(log n) worst-case merges and bagging per append;
  proof ≈ (log₂ n) + (#peaks − 1) ≈ 2·log₂ n hashes; for 1M leaves that is
  ~40 × 32B ≈ 1.3KB. SHA-256 throughput makes hashing cost a non-issue at
  MVP scale; #36's tests will measure exact numbers.
- Cross-check: zkSync Lite and Polygon's exit tree use 32-level sparse trees;
  we opt for 256 depth because keys are already H256. Depth only affects
  sibling counts in proofs, not the API shape.

## Testing Strategy

1. **Hand-computed small vectors:** depth ≤ 8 fixed constants covering
   single insert, sibling split, delete/contract, empty-tree root equal to
   the `EMPTY` constant; MMR n = 0..16 exact peak/bag structure.
2. **Property tests (proptest):** random op sequences (update/delete at
   reduced depth vs a naive full-depth reference model) → roots match;
   proofs for every occupied key verify; non-existence proofs for every
   hole verify. This yields a true differential test across representations.
3. **Serialization stability:** node/proof DTOs postcard round-trip byte-stable;
   proof verification must reject altered direction bits/`leaf_count`.
4. **Determinism gate:** same op list in-process and re-run produces identical
   roots byte-for-byte; no HashMap iteration order influence (all hashing is
   key/address-ordered).
5. **zkVM harness smoke test (light, in #35):** build + verify a small proof
   inside a RISC Zero dev-mode guest run once after the core lands.

## Risks & Estimation

| Risk | Mitigation |
|---|---|
| Delete/contract bugs (compressed-SMT edge cases) | Small-vector reference model + contract case taxonomy in #34 tests |
| Proof replay across roots/sizes | `leaf_count`/size bound inside all roots; checked in verify |
| Node store blowup keeping every historical root | Content addressing + optional epoch GC as follow-up (noted in #36, not MVP) |
| Batch update complexity | Ship sequential updates first; OBU arXiv optimization as #34 stretch |

| Deliverable | Repo issue | Estimate |
|---|---|---|
| SMT core (node types, NodeStore, update/get, root hashing) | #34 | 3–4 d |
| SMT proofs (incl. + non-existence, verifier DTO, zkVM smoke) | #35 | 2 d |
| MMR (full structure, proofs, size-bound verification) | #36 | 2–3 d |
| Canonical-serialization migration of shared consensus types | #18 | 1–2 d |

## Open Questions

1. Do archives need unlimited historical node retention forever, or is
   epoch-GC with an N-epoch window acceptable for the AFL node MVP? (default:
   unbounded for MVP, document as known cost)
2. Should the sequencer include SMT **node digest tree** commitments in the
   block header as an extra integrity artifact, or rely on the single state
   root in the header? (default: single root, as in the architecture doc)
3. Do we need keccak/pedersen variants of the trees for L1 bridge/contract
   verification, or is SHA-256-only sufficient at M1? (default: SHA-256-only;
   keep domain-tag scheme versionable so a second hash domain can be added
   alongside instead of replacing it)
