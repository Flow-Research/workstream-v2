# Object data availability (#126)

The `ObjectDaClient` adapter publishes blocks and direct transactions to any
S3-compatible provider (MinIO locally, hosted S3-compatible services in
production). It is selected when `WORKSTREAM_DA_ENDPOINT` is set; without that
variable the connected writer falls back to the development-only in-memory DA.

## Wire format and identity

Each object holds a versioned postcard envelope:

```text
{ version: 1, sha256: SHA256(payload), payload: <exact published bytes> }
```

- Writes use `If-None-Match: *`. A second write of the same logical key is
  accepted only after a read confirms the existing payload is byte-identical.
  Different bytes for the same `header.da_ref` are rejected with a typed
  validation error; the first write is never replaced.
- Reads verify the envelope digest before returning bytes. Corrupted or
  tampered objects fail closed.
- Logical keys are `<prefix>/blocks/<da_ref>` and `<prefix>/txs/<sha256(tx)>`.
  The block key is the producer-committed `header.da_ref`, so a node can fetch
  it without any producer-local state.
- Requests are signed with AWS Signature Version 4 (`host`,
  `x-amz-content-sha256`, `x-amz-date`) and sent over HTTP or HTTPS.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `WORKSTREAM_DA_ENDPOINT` | yes for object DA | `http://host:port` or `https://host:port` (no path) |
| `WORKSTREAM_DA_BUCKET` | yes | Existing bucket; must satisfy S3 naming rules |
| `WORKSTREAM_DA_ACCESS_KEY` / `WORKSTREAM_DA_ACCESS_KEY_FILE` | one | Access key; file variant keeps it out of process listings |
| `WORKSTREAM_DA_SECRET_KEY` / `WORKSTREAM_DA_SECRET_KEY_FILE` | one | Secret key; prefer a `0400` mounted file |
| `WORKSTREAM_DA_REGION` | no | SigV4 region, default `us-east-1` (MinIO accepts any fixed value) |
| `WORKSTREAM_DA_PREFIX` | no | Key prefix, default `workstream` |
| `WORKSTREAM_DA_CA_FILE` | yes for HTTPS | PEM bundle of trusted CAs; missing/invalid bundles fail closed |

Both the connected writer and the node must receive the same configuration.
The writer publishes; the node uses only `Request::DaRef(height)` over its
authenticated writer socket and then fetches the bytes from the provider. It
checks the height, non-zero reference, and `header.da_ref` equality before
applying the block. Deleting the writer's local block rows does not stop the
node.

## Credentials

Use a dedicated, least-privilege account. It needs permission to read and
write objects under the configured bucket/prefix and to issue bucket `HEAD`.
Mount secrets as read-only files and set the `*_FILE` variables in preference
to environment values. Rotate credentials by replacing the mounted files and
restarting the processes; no credential is persisted in the admission journal
or proof database.

## Retention

Objects are immutable by logical key and are addressed by the commitment in
the block header. A referenced object must outlive the chain's finality and
verification window. Configure bucket lifecycle rules so objects under the
configured prefix are **not** expired before that window; a conservative
policy is to retain all `blocks/` objects indefinitely and expire only
unreferenced `txs/` objects after the configured admission horizon. Bucket
versioning and object lock add defense in depth, but the adapter's conditional
write check is the primary overwrite guard. Deletion is an explicit operator
action after finality, never a routine cache eviction.

## Availability and restore

The writer fails closed when the provider is unavailable: the transaction
stays `Pending` in the admission journal and no block is produced. The node
retries on its normal sync loop and does not advance on a stale or missing
object. There is no local replica that can mask a provider outage.

To restore access, make the same bucket/prefix reachable again (or point the
configuration at a restored snapshot of that bucket) and restart the writer
and node. Do not repoint an existing chain at an empty bucket: already
committed references cannot be reconstructed from producer-local state. For
production, use a multi-zone provider, versioning, and tested bucket restore
procedures.

## Verification evidence

- `cargo test -p workstream-sequencer da::object` exercises SigV4 verification,
  payload-hash validation, idempotent writes, conflicting overwrite rejection,
  tampered-read rejection, malformed references, and bounded failure when the
  provider is down. The in-repo mock verifies signatures independently and
  enforces conditional PUT.
- `python3 scripts/test-object-da.py` starts the in-repo S3-compatible mock and
  a socket-only PostgreSQL proof database, publishes block 1, deletes the
  writer's local block bytes, and proves that a fresh node still verifies the
  block from DA. It then kills the provider, confirms the next admission stays
  pending and the verified tip is unchanged, restarts the provider from its
  own persisted store, and confirms block 2 is published and verified.

Residual gap: hosted CI cannot currently pull a MinIO image (Docker Hub denies
`minio/minio`, Quay returns `401`, and the upstream binary URL is unavailable
in this environment). The drill therefore uses the in-repo mock provider,
which implements the S3 wire behaviours this adapter relies on. Real MinIO and
hosted-S3 conformance, lifecycle policy enforcement, and credential rotation
remain operator acceptance items.
