# Single-host connected runtime

Run `bash scripts/compose-gate.sh` from a clean checkout with Docker Compose v2
or later to verify the localnet. It creates isolated volumes and short-lived
role certificates, waits for role readiness, submits a signed registration,
compares the writer's proof-bearing block and state root with the verifier's
published commitment and root, then tears down only its own project. The script
prints its artifact directory (build output, container status, service logs,
and receipt). CI retains these files for seven days, including on failure.
The container RPC is loopback-only; the probe runs inside the node container.

Run `python3 scripts/test-connected-runtime.py` from the repository root on
Linux or macOS to build all three binaries and exercise a signed work order
registration through the development proof backend.

For a manual run, set `WORKSTREAM_RUNTIME_DIR` in all three processes to the
same absolute private directory (`mktemp -d`). Use a trusted parent directory
with credentials isolated per process. The worker accepts proving requests on `worker.sock`;
the sequencer alone binds `writer.sock` and verifies each worker result before
publication. An existing socket causes startup to fail rather than replacing
another writer. Use a fresh directory for each new development chain.

### Service identities and limits

Both sockets require mutual TLS 1.3. Clients verify the CA and the target DNS
name (`sequencer.workstream.internal` or `prover.workstream.internal`). The
writer additionally pins the node's client certificate, and the worker pins
the writer's. A valid certificate for another role does not authorize a call.
Point each process's `WORKSTREAM_IDENTITY_DIR` at its own read-only credentials:
`ca.der`, `cert.der`, `key.der` (private permissions), and, for servers,
`allowed-client.der`. Provision keys separately; a shared OS account with read
access to another role's key can impersonate it. For temporary local tests use
`bash scripts/dev-service-identities.sh <new-directory>` and select the matching
role subdirectory. Coordinate leaf and peer-pin replacement at restart.

The loopback node RPC accepts 32 concurrent connections, with 256 KiB frames
and 10-second read/write deadlines. The writer and worker each process one IPC
request at a time. They bound TLS negotiation to 3 seconds, reading a request
to 10 seconds, writer requests to 256 KiB and proof messages to 16 MiB. Callers
wait up to 300 seconds for the first reply byte and 10 seconds for its frame.

Set `WORKSTREAM_NODE_RPC_PORT` on the node. Its loopback newline-delimited
JSON-RPC supports `workstream.sequencer.submitTransaction` (the versioned
submission DTO) and `workstream.node.verifiedTip` (local height and root).
The node fetches complete blocks from the writer, executes their transactions
and verifies their proofs independently. When the writer is unavailable, tip
queries still report the last locally verified height; submission fails.

### Durable proof jobs

The proof worker stores jobs in PostgreSQL, keyed by `(chain, guest,
commitment)`. The commitment binds height, roots and the exact transaction
set, so a completion from another tip or another guest can never satisfy a
different key. Witness bytes live in `proof_job_witness` and are removed in the
same transaction that stores the result or rejection. `proof_job_status`
exposes only height, attempts, queue age, prove duration and rejection reason.

The worker owns its chain with a PostgreSQL session advisory lock. On restart
it reclaims jobs that still have a witness and checks every completion against
its key before storing it. Duplicate requests for a completed key return the
stored proof. A second worker for the same chain exits rather than racing.

In Compose, `jobdb` listens only on a private Unix socket and authenticates the
worker with a short-lived password. Set `WORKSTREAM_JOBS_SOCKET`, optionally
`WORKSTREAM_JOBS_PORT`, and `WORKSTREAM_JOBS_PASSWORD_FILE`. The worker socket
is replaced only by the process holding the chain lock. `WORKSTREAM_PROFILE=dev`
also accepts `WORKSTREAM_DEV_PROOF_DELAY_MS` for deterministic fault injection
in local restart drills; production profiles ignore it.

The local drill in `scripts/test-connected-runtime.py` starts an ephemeral
cluster, SIGKILLs the worker mid-proof, and asserts that one job with a private
witness was retained, that the restarted worker reclaimed it (`attempts=2`),
that the witness was removed, and that the public view has no witness columns.

For the connected writer set `WORKSTREAM_WRITER_DATA` to a private directory
on persistent local storage. Compose provisions a writer-only volume. The
chain-specific SQLite journal commits signed bytes before `Pending`; a retry
of those bytes returns the same transaction ID. Recovery reloads the last
committed snapshot and the pending queue in order. Look up `tx_hash` via
`workstream.node.getReceipt`: the writer reports Unknown, Pending, Published
or Rejected, and the node reports Verified only after applying a block that
contains that ID. `workstream.sequencer.getMempoolStatus` reports pending
count and canonical signed bytes. Removing the writer volume deletes its journal.
Real receipts require the [proof profile](proof-profiles.md)
setup; the local smoke test does not exercise that prover.
