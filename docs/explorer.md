# Read-only chain register

With projections and HTTPS configured on the connected node, set `WORKSTREAM_EXPLORER=1` and open `/explorer`. Enabling this publishes the displayed metadata to anyone who can reach the HTTPS listener. The explorer is disabled by default. Its routes accept reads only and require no cookie, login, script, or signing key.

Receipt bookmarks use `/explorer?kind=receipt&key=<transaction-hash>`. A lookup checks verifier inclusion first, then writer status. `Published` alone is not `Verified`. Receipt history is paginated from the projection; each row links to the durable transaction identity rather than a page position. The header reports the sampled verifier and index heights, with a separate textual stale indicator.

Account and task searches show up to 25 recent projected work events by actor or subject hash. An empty result means no matching local work record, not that an account cannot exist. Block lookup by positive height reports local archive presence, fork, proof-system version, guest hash and DA reference. It does not certify external archive retention or expose proof, event payload, or signed transaction bytes. These are local read models and do not grant capabilities.

`python3 scripts/test-projections.py` exercises receipt bookmarks across new TLS connections, verifier restart, local projection wipe and rebuild. This is a process drill, not a hosted visual-browser test.
