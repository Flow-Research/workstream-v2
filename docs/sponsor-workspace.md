# Sponsor desk

With `WORKSTREAM_EXPLORER=1`, open `/sponsor` on the HTTPS listener. Add the desk's exact HTTPS origin to `WORKSTREAM_API_ORIGINS` for browser POST requests. The desk uses the existing facade session and writer journal. Workspace login confers no sponsor capability.

Follow the publication checklist: register the sponsor; create a project; grant an already registered worker the appropriate capabilities; ingest and activate a versioned guide; then create, screen and release the task. A compiled policy is selected by its immutable policy ID. A guide version is a separate project-scoped reference. Grant previews name the beneficiary and capability; a sponsor grant is not restricted to one task. An award has no preselected payee: the verified worker claim determines the beneficiary.

Preview one action at a time. The network comes from the connected node. Enter the confirmed next nonce manually; the desk uses nonce lane 0, fee asset 0 and maximum fee 1000. Save the unsigned JSON and follow `docs/local-signing.md`. Only select the resulting **signed transaction** file in the browser. The desk checks its canonical signing digest and signature, forwards the same bytes and opens the receipt by signed transaction hash. Refreshing a preview prepares the same draft; refreshing a receipt is a read. A retry after a lost acknowledgment uses the same signed bytes. Keep the receipt link and verify the outcome before preparing the next action.

Prerequisite guidance is a checklist, not an authoritative preflight: a grant or active guide can change before execution. The projection TLS drill tests the HTTP handoff with an independently signed fixture; it does not exercise a graphical browser or custody provider.
