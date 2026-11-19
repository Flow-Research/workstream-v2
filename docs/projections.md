# Verified-block projections (#128)

PostgreSQL projections index verifier-accepted blocks after full proof, fork,
execution, and state-root verification. They are derived views only: the state
transition function, writer admission, receipt authority, and verifier never
read projection tables. Editing a projection cannot authorize a transaction.

## Model

- **Source of truth:** the immutable `verified_blocks` log stores the exact
  verified block bytes, accepted state root, and DA reference. It is populated
  only from `Node::apply_block` results in the connected verifier loop.
- **Atomic cursor:** `projection_meta.indexed_height` and all derived rows for
  a block are committed in one PostgreSQL transaction. A crash at
  `projection-mid-batch` (debug/dev only) aborts before commit, so a restart
  replays the same verified block without partial rows or cursor skew.
- **Authority boundary:** `workstream.node.getReceipt` continues to report
  `Verified` from the verifier's accepted transaction set and writer status
  from the writer journal. `projection_receipts` is a paginated read model of
  those verified outcomes, not an admission or authorization input.
- **Rebuild:** `workstream-reindex` wipes derived tables, resets the cursor,
  and replays `verified_blocks` through a fresh in-memory verifier before
  committing each block. The rebuilt state must match the original projection.

## Tables

`projection_events`, `projection_work_items`, `projection_grants`,
`projection_reviews`, and `projection_receipts` are derived from verified
events/transactions. `projection_status` exposes verified/indexed heights and
lag from committed metadata. Event order is preserved as
`(height, tx_index, ordinal)`; grant rows carry the transaction account as the
grantor because `actor.granted` / `actor.revoked` payloads do not include it.

## RPC

Connected nodes expose read-only projection methods when configured:

- `workstream.indexer.getStatus` → verified height, indexed height, lag,
  indexed state root/DA reference, schema version, timestamp.
- `workstream.indexer.getPage` → `{ kind, cursor?, event_type?, limit? }`
  returning stable `items` and `next_cursor`. Supported kinds: `events`,
  `work_items`, `grants`, `reviews`, `receipts`.

Pages are cursor-based and ordered by `(height, tx_index, ordinal)`. The
response cursor is independent of verified height so readers can observe lag.

## Operations

Set `WORKSTREAM_PROJECTIONS_SOCKET`, `WORKSTREAM_PROJECTIONS_PORT`,
`WORKSTREAM_PROJECTIONS_PASSWORD_FILE` (optional), and a PostgreSQL database
named `projections` owned by role `projection`. `scripts/init-projections.sh`
creates the role when bootstrapping a fresh PostgreSQL volume.

`python3 scripts/test-projections.py` exercises mid-batch restart, wipe/rebuild
comparison, pagination/status, and projection tampering that cannot change
authoritative receipt or admission behavior.

Residual gaps: hosted CI does not run the socket-only PostgreSQL projection
drill in this change; the drill is deterministic local evidence. The generic
standalone node RPC server does not yet expose projection reads; connected
mode is the supported runtime path.