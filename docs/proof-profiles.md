# Selecting the proof runtime

Set the same environment on node, sequencer and prover. With no settings the
profile is `dev`: the MVP schedule and an in-memory proof backend. Use this
only for local testing. To require real receipts set:

| Setting | Testnet / production requirement |
|---|---|
| `WORKSTREAM_PROFILE` | `testnet` or `production` |
| `WORKSTREAM_CHAIN_ID` | Expected nonzero numeric chain ID |
| `WORKSTREAM_FORK_SCHEDULE` | Trusted local JSON `ForkSchedule`; every fork enables `risc0-receipts` |
| `WORKSTREAM_PROVER_BACKEND` | `risc0` (implicit for these profiles) |
| `WORKSTREAM_GUEST_IMAGE` | Path to the packaged RISC Zero image |
| `WORKSTREAM_GUEST_ID` | Independently approved image ID in hex |

Startup measures the image and checks every fork against the approved ID. The
current loader supports one guest image per deployment: a schedule requiring
multiple images is rejected rather than choosing an image by request. Schedule
and image approval must come from the operator's trusted release configuration.
Prover `zkvm = "auto"` follows the shared selection; other values assert it.
Successful startup logs the selected profile, chain, guest ID and backend mode.
This preflight does not attest to network connectivity or worker availability.
