# Restore and sign offline

Use `workstream-inspect` first. Check the network, account, nonce, fees, action types and payload hashes against the intended transaction. The payload hashes identify bytes; they are not decoded action parameters. If you cannot independently identify the payload, do not approve it.

```sh
workstream-inspect < draft.json
```

After review, copy `approval_digest` from that preview. In a fresh environment, supply the encrypted backup and its matching recovery identity (one age X25519 secret-key line, delivered separately). Select the intended network explicitly. For example, on network 42:

```sh
umask 077
workstream-sign --network 42 --approve "$approved_digest" \
  --backup backup.age --draft draft.json < recovery.identity > signed.json
```

The signer uses redirected stdin for the identity and emits signed transaction JSON on success. It does not submit the transaction. Check the exit status before using `signed.json`; `workstream-inspect < signed.json` verifies the signature and displays the signed transaction hash. A changed draft requires a new review.

## Connected-node diagnostics

Run `workstream-chain --port 8545 status` against the local connected node with projections enabled. It reports `verified_height`, `indexed_height`, `lag`, and `freshness`. These are successive local reads: a growing tip can briefly report lag. A current index does not prove the chain is advancing.

Use `doctor` to also check the writer queue, or `smoke` to read one receipt page. Neither submits a transaction or needs a wallet. `status` exits 0 for a readable stale view; `doctor` and `smoke` exit 2 for that condition. Failed reads, malformed replies, and timeouts exit 1. Only loopback connections are supported.

## Optional workspace login

The connected HTTPS API accepts an OIDC provider's access token at `GET /v1/workspace` in the `Authorization: Bearer` header. Set `WORKSTREAM_WORKSPACE_OIDC_CONFIG` to an operator-controlled JSON file containing `issuer` (exact HTTPS issuer), `audience` (the workspace resource), and `n` and `e` (the pinned RSA public JWK components). Without configuration, the endpoint denies all logins. An invalid configuration prevents API startup.

The endpoint checks the RS256 signature, `at+jwt` token type, issuer, single audience, expiry, issue time, optional not-before time, subject and `workspace:login` scope on every read. Success returns only the workspace subject. Token roles never enter the transaction validator, and workspace tokens cannot substitute for API session tokens. A valid API session still requires an independently signed protocol transaction.

The client obtains the token from its provider. Interactive authorization, automatic discovery, revocation before expiry and automatic signing-key rotation are not implemented here. Use short-lived tokens and deploy a new trusted public key when rotating. The TLS drill uses an ephemeral issuer and scans captured service output for known credentials and the fixture signing seed; this is regression evidence, not a guarantee about operator-side proxies or third-party logs.
