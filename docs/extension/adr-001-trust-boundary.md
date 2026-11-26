# ADR 001: Extension trust boundary and pilot distribution

Parent: #148. Status: proposed, with two open questions listed at the end.

## Context

The pilot wallet is a Manifest V3 Chromium extension. It must let a work-order
app ask for an account and a typed action without ever receiving signing key
material. The API it talks to (#130, PR #163) is a read/forward boundary: keys
stay client-side and the only write is already-signed transaction bytes.

## Contexts and trust boundary

| Context | Can access | Keys | Notes |
|---|---|---|---|
| Page script (dapp) | `globalThis.workstream` provider facade: connect, disconnect, account/chain discovery, typed requests, decision polling | Never | Talks only over `window.postMessage` with the content-script bridge. Receives public account and chain data after an origin grant, never a secret or raw storage value. |
| Content script (isolated world) | Page origin, message relay | Never | Injects `content/inpage.js` into the page world and forwards allowlisted message types to the background. Must not read extension storage or log message payloads. |
| Service worker | `chrome.storage.local`, grants, pending requests, approval-window map, signing capability | Only context allowed to sign | Sole authority for origin grants and decisions. Current signer is a mock; the real vault is #174. All state lives in storage so an idle restart is safe. |
| Popup | Extension version and read-only transaction list | Never | No signing, no storage writes; verifies and refreshes through service-worker messages. |
| Transaction tracker (service worker) | `chrome.storage.local` transaction records, `chrome.alarms`, API session token in worker memory, explorer links | Never | Records signed actions by request ID, submits once, polls receipts from #130, links #132 explorer bookmarks; session token is never persisted or sent to a page. |
| Approval UI | One request by ID: origin, chain, account, decoded action, approve/reject | Never | Renders from storage via a background message and returns a decision keyed by request ID. Closing the window is a rejection. |

Rule for future work: the service worker exposes one registration function
(`src/background/bootstrap.js`), and each feature registers its listeners from
its own module via `src/background/features.js`. Do not edit the service-worker
entry point to add features; MV3 listeners must be attached at module
evaluation time so an idle worker wakes correctly.

## Provider surface

The in-page provider exposes `connect()`, `disconnect()`, `getAccounts()`,
`getChainId()` and `request({ method, params, requestId })`. Grants are scoped
to the requesting origin and stored per origin. An origin without a grant gets
a structured error and no account. Supported methods are an explicit allowlist;
unsupported methods and chain mismatches are rejected before any approval UI is
opened. Every decision is keyed by `requestId`, so a retry returns the recorded
decision instead of signing twice.

## Decisions made here

- The manifest carries a pinned public key, giving the stable ID
  `kceihmiobchfkkjmcmehbbociojgadap` and the exact CORS origin
  `chrome-extension://kceihmiobchfkkjmcmehbbociojgadap`.
- All durable state uses `chrome.storage.local`. Nothing uses
  `chrome.storage.sync`, and nothing writes secrets to logs or page context.
- Idle-safe behaviour uses `chrome.alarms` (#174), never a timer that assumes
  the worker stays resident.
- Listener registration is centralised as described above.
- The page bridge carries a per-injection random token, and both sides require
  `event.source === window` and `event.origin === window.location.origin`.
  Replies target only the page origin. A script in another frame or document
  cannot forge a request or an approval reply.
- The approval page is not a web-accessible resource. It refuses to run in a
  frame, keeps both controls disabled until a top-level request loads, and
  re-enables them after a failed decision so the user can retry.
- Consumed state is written to `chrome.storage.local` before the tracker hook
  runs. A failed hook is replayed from the stored result rather than re-signing.
- A request ID is bound to a canonical hash of origin, account, chain, method
  and full params; reuse with different bytes fails as `REQUEST_ID_REUSE`.

## Open questions for the owner

1. **Pilot distribution:** unpacked extension only, or unlisted Chrome Web
   Store? Unpacked keeps the pilot small but asks each user to enable developer
   mode; an unlisted store listing gives updates but needs review time.
2. **Idle auto-lock default:** what duration should the vault use before #174
   implements it? This ADR does not pick one silently.

## Accepted residual risks and owners

| Risk | Owner | Treatment |
|---|---|---|
| Exact-origin CORS allowlist is empty by default; the extension origin must be added to `WORKSTREAM_API_ORIGINS` | #130 / pilot ops | PR #163 merged without the origin. No wildcard CORS, no API edits from the extension; operator config is still required |
| Sessions are in-process; a restart clears them and yields 401 | #130 / #175 | Tracker re-issues once and retries with the same `X-Request-Id` |
| Browser API listener is loopback-only by default | #130 / pilot ops | Not an extension change; operator-managed cert/DNS if exposed |
| TypeScript types are hand-mirrored from OpenAPI | #130 | Accepted for pilot, guarded by the schema-equality test |
| No hosted browser conformance suite | #176 (release gate) | CI artifact from localnet E2E is the evidence |
| Cross-language signing/backup vectors are not yet fixed | #131 | Comment posted on #131; #174 consumes those vectors |
| PR #163 is stacked on unmerged `roadmap/129-observability` | PR #163 | Process risk; rebase before merge |
| Content script is declared for `<all_urls>` so the provider can be injected | #148 | Broad declarative access is accepted for the pilot; authority is still gated by per-origin grants and explicit approval |
