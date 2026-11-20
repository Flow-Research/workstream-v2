# Worker fieldbook (#135)

Open `/worker` on the explorer-enabled HTTPS origin. Allow its exact origin in `WORKSTREAM_API_ORIGINS`. Enter a worker account to list released tasks with an indexed sponsor ClaimWork grant and the worker’s claimed/started tasks (up to 25). These projection hints can lag; the STF checks role, grants, assignment and task state when executing each action.

Preview and sign claim, start, bundle admission and submission separately. The desk hands each action to the same offline signer and signed-file flow as the sponsor desk. Follow each receipt to Verified before advancing the nonce. Upload uses a separate workspace credential; uploaded, submitted and verified are distinct states. The submission commits to the SHA-256 of the selected bytes.

**Recovery:** tab session storage retains public draft fields, a local upload acknowledgment, and a receipt bookmark across reloads. Files, signatures, keys and workspace tokens are never persisted by the desk. Clear the draft on a shared device. Retrying after a connection loss requires reselecting the same file; uploading it again is idempotent. The tab is not durable cross-device storage.

**Lease:** an operator can set `upload_deadlines(subject,task,digest,expires)` alongside a matching private upload grant. `expires` is UTC Unix time in seconds. The store checks it transactionally and returns HTTP 410 at expiry; renew the deadline before retrying. Without a deadline an existing grant retains its #133 semantics. An upload deadline governs private storage access, not the on-chain assignment or the digest of an already uploaded object. Protocol worker claims have no wall-clock expiry.

Run `python3 scripts/test-projections.py --worker-browser` with Python Playwright 1.58 and its Chromium installed. The local process drill uses a disposable cluster and ephemeral workspace issuer; the browser exercises the four independently signed fixture transactions, including interrupted upload, expiry, renewal and draft restore. Hosted CI does not run this browser drill.
