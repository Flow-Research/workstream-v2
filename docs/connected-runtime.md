# Single-host connected runtime

Run `python3 scripts/test-connected-runtime.py` from the repository root on
Linux or macOS to build all three binaries and exercise a signed work order
registration through the development proof backend.

For a manual run, set `WORKSTREAM_RUNTIME_DIR` in all three processes to the
same absolute private directory (`mktemp -d`). Use a trusted parent directory
and a dedicated OS account: processes with access to this directory share the
service trust boundary. The worker accepts proving requests on `worker.sock`;
the sequencer alone binds `writer.sock` and verifies each worker result before
publication. An existing socket causes startup to fail rather than replacing
another writer. Use a fresh directory for each new development chain.

Set `WORKSTREAM_NODE_RPC_PORT` on the node. Its loopback newline-delimited
JSON-RPC supports `workstream.sequencer.submitTransaction` (the versioned
submission DTO) and `workstream.node.verifiedTip` (local height and root).
The node fetches complete blocks from the writer, executes their transactions
and verifies their proofs independently. When the writer is unavailable, tip
queries still report the last locally verified height; submission fails.

The development archive and pending queue are in memory. A `Pending` response
is not a durable acknowledgement. This transport does not provide multi-host
service identities. Real receipts require the [proof profile](proof-profiles.md)
setup; the local smoke test does not exercise that prover.
