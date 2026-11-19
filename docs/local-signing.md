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
