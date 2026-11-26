import assert from "node:assert/strict";
import { test } from "node:test";
import { createGrantsFeature } from "../../src/background/grants.js";

const PAGE = { tab: { url: "https://dapp.example/app" }, url: "https://dapp.example/app" };
const UI = { url: "chrome-extension://test/approval.html" };

function setup({ onSigned, createWindow } = {}) {
  const data = new Map();
  const storage = {
    async get(key) {
      return { [key]: data.get(key) };
    },
    async set(values) {
      for (const [key, value] of Object.entries(values)) data.set(key, value);
    },
  };
  const windows = {
    opened: [],
    removed: [],
    async create(options) {
      const id = windows.opened.length + 1;
      if (createWindow) {
        const created = await createWindow(options, id);
        windows.opened.push({ id: created.id ?? id, options });
        return created;
      }
      windows.opened.push({ id, options });
      return { id };
    },
    async remove(id) {
      windows.removed.push(id);
    },
  };
  const runtime = { getURL: (path) => `chrome-extension://test/${path}` };
  let signCalls = 0;
  const signer = async (request) => {
    signCalls += 1;
    return { signature: `sig:${request.id}`, account: request.account };
  };
  const feature = createGrantsFeature({ storage, windows, runtime, signer, onSigned });
  return { feature, storage, windows, data, signCalls: () => signCalls };
}

function send(feature, message, sender = PAGE) {
  return new Promise((resolve) => {
    assert.equal(feature.onMessage(message, sender, resolve), true);
  });
}

let grantCounter = 0;

async function grantOrigin(feature) {
  grantCounter += 1;
  const pending = await send(feature, {
    type: "connect",
    requestId: `connect-grant-${grantCounter}`,
  });
  assert.equal(pending.status, "pending");
  const decided = await send(
    feature,
    { type: "decide", requestId: pending.requestId, decision: "approve" },
    UI,
  );
  assert.equal(decided.status, "approved");
  return pending.requestId;
}

test("connect without a grant opens approval and never returns an account", async () => {
  const { feature, windows } = setup();
  const result = await send(feature, { type: "connect", requestId: "connect-a" });
  assert.equal(result.status, "pending");
  assert.equal(windows.opened.length, 1);
  assert.match(windows.opened[0].options.url, /approval\.html\?id=connect-a/);
  const accounts = await send(feature, { type: "getAccounts" });
  assert.deepEqual(accounts.accounts, []);
});

test("approving connect grants the origin; rejecting it does not", async () => {
  const approved = setup();
  await grantOrigin(approved.feature);
  assert.deepEqual((await send(approved.feature, { type: "getAccounts" })).accounts, [
    "mock-account-1",
  ]);

  const rejected = setup();
  const pending = await send(rejected.feature, { type: "connect", requestId: "connect-b" });
  await send(rejected.feature, { type: "decide", requestId: pending.requestId, decision: "reject" }, UI);
  assert.deepEqual((await send(rejected.feature, { type: "getAccounts" })).accounts, []);
});

test("closing the approval window rejects a pending request", async () => {
  const { feature } = setup();
  const pending = await send(feature, { type: "request", requestId: "req-1" });
  assert.equal(pending.ok, false);
  assert.equal(pending.error.code, "UNAPPROVED_ORIGIN");

  await grantOrigin(feature);
  const request = await send(feature, {
    type: "request",
    requestId: "req-close",
    method: "workstream_createWorkItem",
    params: { chainId: "workstream-local-1", title: "Fix docs" },
  });
  assert.equal(request.status, "pending");
  await feature.onWindowRemoved(2);
  const decision = await send(feature, { type: "getDecision", requestId: "req-close" });
  assert.equal(decision.status, "rejected");
  assert.equal(decision.error.code, "POPUP_CLOSED");
  assert.equal((await send(feature, { type: "getDecision", requestId: "req-close" })).status, "rejected");
});

test("unapproved origins get an error and no account", async () => {
  const { feature } = setup();
  const result = await send(feature, {
    type: "request",
    requestId: "req-2",
    method: "workstream_createWorkItem",
    params: { chainId: "workstream-local-1" },
  });
  assert.equal(result.error.code, "UNAPPROVED_ORIGIN");
  assert.deepEqual((await send(feature, { type: "getAccounts" })).accounts, []);
});

test("unsupported actions and chain mismatches are rejected before approval", async () => {
  const { feature, windows } = setup();
  await grantOrigin(feature);
  const unsupported = await send(feature, {
    type: "request",
    requestId: "req-3",
    method: "workstream_drainVault",
    params: { chainId: "workstream-local-1" },
  });
  assert.equal(unsupported.error.code, "UNSUPPORTED_ACTION");

  const mismatch = await send(feature, {
    type: "request",
    requestId: "req-4",
    method: "workstream_createWorkItem",
    params: { chainId: "other-chain" },
  });
  assert.equal(mismatch.error.code, "CHAIN_MISMATCH");
  assert.equal(windows.opened.length, 1); // only the connect approval
});

test("approval shows the decoded action and signing happens once per request ID", async () => {
  const { feature, signCalls } = setup();
  await grantOrigin(feature);
  const pending = await send(feature, {
    type: "request",
    requestId: "req-5",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1", workItemId: "7" },
  });
  assert.equal(pending.status, "pending");
  const approval = await send(feature, { type: "getApproval", requestId: "req-5" }, UI);
  assert.equal(approval.request.decoded.method, "workstream_submitWork");
  assert.equal(approval.request.decoded.params.workItemId, "7");

  await send(feature, { type: "decide", requestId: "req-5", decision: "approve" }, UI);
  const first = await send(feature, { type: "getDecision", requestId: "req-5" });
  const retry = await send(feature, {
    type: "request",
    requestId: "req-5",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1", workItemId: "7" },
  });
  assert.deepEqual(retry, first);
  assert.equal(signCalls(), 1);
  assert.equal(first.result.signature, "sig:req-5");
});

test("rejection is remembered and cannot be overwritten by a later decision", async () => {
  const { feature, signCalls } = setup();
  await grantOrigin(feature);
  await send(feature, {
    type: "request",
    requestId: "req-6",
    method: "workstream_createWorkItem",
    params: { chainId: "workstream-local-1" },
  });
  await send(feature, { type: "decide", requestId: "req-6", decision: "reject" }, UI);
  const late = await send(feature, { type: "decide", requestId: "req-6", decision: "approve" }, UI);
  assert.equal(late.alreadyDecided, true);
  const decision = await send(feature, { type: "getDecision", requestId: "req-6" });
  assert.equal(decision.status, "rejected");
  assert.equal(signCalls(), 0);
});

test("disconnect and user revoke remove origin grants", async () => {
  const { feature, storage } = setup();
  await grantOrigin(feature);
  await send(feature, { type: "disconnect" });
  assert.deepEqual((await send(feature, { type: "getAccounts" })).accounts, []);

  await grantOrigin(feature);
  const result = await send(
    feature,
    { type: "revoke", targetOrigin: "https://dapp.example" },
    UI,
  );
  assert.equal(result.revoked, true);
  assert.deepEqual((await storage.get("grants")).grants, {});
});

test("claimed origin must match the sender tab and decisions are extension-only", async () => {
  const { feature } = setup();
  const mismatch = await send(feature, {
    type: "connect",
    requestId: "connect-x",
    origin: "https://evil.example",
  });
  assert.equal(mismatch.error.code, "ORIGIN_MISMATCH");

  const forbidden = await send(
    feature,
    { type: "decide", requestId: "connect-1", decision: "approve" },
    PAGE,
  );
  assert.equal(forbidden.error.code, "FORBIDDEN");
});

test("state and decision survive a service worker restart without re-signing", async () => {
  const first = setup();
  await grantOrigin(first.feature);
  await send(first.feature, {
    type: "request",
    requestId: "req-restart",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1" },
  });
  await send(first.feature, { type: "decide", requestId: "req-restart", decision: "approve" }, UI);

  const restarted = createGrantsFeature({
    storage: {
      async get(key) {
        return { [key]: first.data.get(key) };
      },
      async set(values) {
        for (const [key, value] of Object.entries(values)) first.data.set(key, value);
      },
    },
    windows: first.windows,
    runtime: { getURL: (p) => `chrome-extension://test/${p}` },
    signer: async () => {
      throw new Error("signer must not run on restart");
    },
  });

  const retry = await send(restarted, {
    type: "request",
    requestId: "req-restart",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1" },
  });
  assert.equal(retry.status, "approved");
  assert.equal(retry.result.signature, "sig:req-restart");
});

test("unknown request IDs are rejected", async () => {
  const { feature } = setup();
  const result = await send(feature, { type: "getDecision", requestId: "missing" });
  assert.equal(result.error.code, "UNKNOWN_REQUEST");
});

test("a request ID is bound to canonical params, account and chain", async () => {
  const { feature, signCalls } = setup();
  await grantOrigin(feature);
  const original = {
    type: "request",
    requestId: "req-bind",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1", title: "Fix docs", labels: ["a", "b"] },
  };
  const pending = await send(feature, original);
  assert.equal(pending.status, "pending");
  await send(feature, { type: "decide", requestId: "req-bind", decision: "approve" }, UI);

  // Key order is not part of the binding; a canonical hash ignores it.
  const reordered = await send(feature, {
    ...original,
    params: { labels: ["a", "b"], title: "Fix docs", chainId: "workstream-local-1" },
  });
  assert.equal(reordered.status, "approved");
  assert.equal(signCalls(), 1);

  const changed = await send(feature, {
    ...original,
    params: { ...original.params, title: "Different work" },
  });
  assert.equal(changed.error.code, "REQUEST_ID_REUSE");
  assert.equal(signCalls(), 1);
});

test("a connect ID cannot be stolen by another origin", async () => {
  const { feature, windows } = setup();
  const other = { tab: { url: "https://other.example/app" }, url: "https://other.example/app" };
  const first = await send(feature, { type: "connect", requestId: "connect-shared" });
  assert.equal(first.status, "pending");

  const stolen = await send(feature, { type: "connect", requestId: "connect-shared" }, other);
  assert.equal(stolen.error.code, "REQUEST_ID_REUSE");
  const approval = await send(feature, { type: "getApproval", requestId: "connect-shared" }, UI);
  assert.equal(approval.request.origin, "https://dapp.example");
  assert.equal(windows.opened.length, 1);

  const replay = await send(feature, { type: "connect", requestId: "connect-shared" });
  assert.equal(replay.status, "pending");
  assert.equal(windows.opened.length, 1);
});

test("a failing tracker hook cannot cause a second signature and is replayed", async () => {
  let deliveries = 0;
  const { feature, signCalls } = setup({
    onSigned: async () => {
      deliveries += 1;
      if (deliveries === 1) throw new Error("tracker unavailable");
    },
  });
  await grantOrigin(feature);
  const params = { chainId: "workstream-local-1", workItemId: "9" };
  await send(feature, {
    type: "request",
    requestId: "req-hook",
    method: "workstream_submitWork",
    params,
  });
  const decided = await send(feature, { type: "decide", requestId: "req-hook", decision: "approve" }, UI);
  assert.equal(decided.status, "approved");
  assert.equal(decided.deliveryPending, true);
  assert.equal(signCalls(), 1);
  assert.equal(deliveries, 1);

  const replay = await send(feature, {
    type: "request",
    requestId: "req-hook",
    method: "workstream_submitWork",
    params,
  });
  assert.equal(replay.status, "approved");
  assert.equal(replay.deliveryPending, undefined);
  assert.equal(signCalls(), 1);
  assert.equal(deliveries, 2);
});

test("overlapping approvals sign once", async () => {
  const { feature, signCalls } = setup();
  await grantOrigin(feature);
  await send(feature, {
    type: "request",
    requestId: "req-race",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1" },
  });
  const [first, second] = await Promise.all([
    send(feature, { type: "decide", requestId: "req-race", decision: "approve" }, UI),
    send(feature, { type: "decide", requestId: "req-race", decision: "approve" }, UI),
  ]);
  assert.equal(first.status, "approved");
  assert.equal(second.alreadyDecided, true);
  assert.equal(signCalls(), 1);
});

test("a failed approval window is reopened on replay without a duplicate", async () => {
  let attempts = 0;
  const { feature, windows } = setup({
    createWindow: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("popup blocked");
      return { id: attempts };
    },
  });
  const first = await send(feature, { type: "connect", requestId: "connect-retry" });
  assert.equal(first.ok, false);
  assert.equal(windows.opened.length, 0);

  const replay = await send(feature, { type: "connect", requestId: "connect-retry" });
  assert.equal(replay.status, "pending");
  assert.equal(windows.opened.length, 1);
});
