# Checkpoint publication and restore policy (#127)

This record defines the crash boundary between external publication and the
writer's local tip commit. It applies to the connected runtime built from
issues #124–#126.

## Canonical publication identity

A block's publication key is `header.da_ref`, the domain-tagged SHA-256 of its
`ProofCommitment`. That commitment binds height, parent, fork/guest, pre/post
state roots and the exact ordered transaction set. It deliberately excludes
the proof envelope and `da_ref` itself, so the key can be derived before DA
publication and is identical for every deterministic replay of the same
transition.

The writer now separates one block into three explicit steps:

1. `Sequencer::prepare_block` executes the candidate transition, proves it and
   fixes the publication key.
2. `Journal::record_publication` durably records `(height, da_ref, block)`
   before any external DA write.
3. `PreparedBlock::publish` writes the content envelope to DA, then
   `Journal::finish` atomically advances the local checkpoint, block index,
   receipt status and publication acceptance.

If a crash occurs between 2 and 3, replay encounters the same pending signed
admission, derives the same key and bytes, and issues the same conditional DA
write. An existing identical object is idempotent; different bytes for the key
are a determinism failure. There is no second logical publication and no
double application to state.

## Checkpoint trust policy

A checkpoint snapshot is a **local acceleration hint, never an authority for
skipping verification**.

- The writer validates its snapshot metadata (height, recomputed state root,
  tip DA reference) before replaying pending admissions. A mismatch aborts
  startup with a determinism error.
- A fresh verifier restores from an immutable block archive plus an
  operator-supplied checkpoint. `workstream-restore` replays every archived
  block from genesis and requires full execution, state-root and attached
  proof verification before it even compares the resulting tip and root with
  the checkpoint.
- A checkpoint mismatch is fatal: the restore binary exits non-zero and does
  not write a restored state directory. A missing or malformed checkpoint is
  likewise fatal.
- The checkpoint must be obtained through a trusted operator channel (for
  example, the attested tip from an independently verified node). Copying a
  checkpoint from the same compromised source as the archive provides no
  additional security; the archive replay still detects invalid transitions.

Because verification starts at genesis, a false checkpoint cannot make an
invalid chain acceptable. Conversely, an intact verified chain cannot be
silently replaced by an archive whose commits disagree with the trusted tip.

## Archive format

```text
archive/
  manifest.json       { version: 1, blocks: [{ height, da_ref }, ...] }
  00000001.json       exact DA payload for block 1
  00000002.json       exact DA payload for block 2
  ...
```

The manifest must be contiguous from height 1. Each block file is the exact
published JSON payload (the content envelope is unwrapped and its SHA-256 is
verified during export). The manifest DA reference must equal the block
header's `da_ref`; otherwise restore fails before applying the block.

`python3 scripts/test-checkpoint-restore.py` exports this format from the
in-repo S3-compatible mock used by #126. Production operators should export
from the configured provider's versioned objects; do not synthesize archives
from writable producer-local journals.

## Dev fault injection

The following points are available **only in debug builds** and only when the
process has `WORKSTREAM_PROFILE=dev` plus an exact
`WORKSTREAM_DEV_CRASH_STAGE`:

- `admission` — after signed bytes are committed, before the acknowledgement.
- `proof-completed` — after a keyed proof result is durable, before the reply.
- `da-accepted` — after DA accepts the content envelope, before local commit.
- `local-commit` — after the journal checkpoint and receipt are committed.

`workstream_core::dev::crash_point` is a no-op in release builds and in every
non-dev profile. Faults use `abort` so no user-space buffers are flushed;
all evidence relied on by the drill is durable before each point.

## Verification evidence

`python3 scripts/test-checkpoint-restore.py` starts socket-only PostgreSQL, an
S3-compatible mock, the writer, prover and verifier, then exercises all four
crash windows. It asserts:

- the admission crash leaves one signed pending record and no publication;
- the proof crash leaves a durable keyed result with no witness and an
  unchanged writer tip;
- the DA crash leaves an object under the stable key with `accepted=0` and a
  checkpoint still at the previous height;
- the local-commit crash leaves both publication and checkpoint durable;
- replay yields one canonical block per height, four distinct DA keys, an
  empty pending queue, and matching writer/verifier tips and roots;
- a fresh `workstream-restore` verifies all four archived blocks from genesis
  and matches the trusted checkpoint;
- a tampered checkpoint is rejected after verification.

Residual gap: hosted CI does not exercise the S3-compatible mock in this drill
because PostgreSQL and Unix-socket service orchestration are local-process
facilities. The Compose gate remains the hosted evidence for the deployed
topology (#123); this drill is the deterministic crash/restore evidence.
