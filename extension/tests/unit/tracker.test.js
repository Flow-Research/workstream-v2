import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createApiClient } from "../../src/background/api-client.js";
import { createGrantsFeature } from "../../src/background/grants.js";
import { createTrackerFeature, TRACKER_ALARM } from "../../src/background/tracker.js";

const UI = { url: "chrome-extension://test/popup.html" };
const PAGE = { tab: { url: "https://dapp.example/app" }, url: "https://dapp.example/app" };
const REQUEST = {
  id: "tx-1",
  origin: "https://dapp.example",
  account: "mock-account-1",
  method: "workstream_submitWork",
};
const RESULT = { txHash: "mock-tx:tx-1", txBytes: [1, 2, 3] };

function makeStorage(seed = new Map()) {
  return {
    data: seed,
    async get(key) {
      return { [key]: seed.get(key) };
    },
    async set(values) {
      for (const [key, value] of Object.entries(values)) seed.set(key, value);
    },
  };
}

function makeAlarms() {
  const listeners = [];
  const created = [];
  return {
    listeners,
    created,
    addListener(listener) {
      listeners.push(listener);
    },
    create(name, options) {
      created.push({ name, options });
    },
  };
}

function makeClient() {
  const calls = { submissions: [], receipts: [] };
  const client = {
    calls,
    submissionEnvelope: {
      api_version: 1,
      data: { tx_hash: "mock-tx:tx-1", status: "submitted", height: null },
    },
    receiptEnvelope: {
      api_version: 1,
      read_height: 20,
      indexed_height: 20,
      stale: false,
      data: { tx_hash: "mock-tx:tx-1", status: "Verified", height: 19 },
    },
    submissionError: null,
    receiptError: null,
    async submit(body, requestId) {
      calls.submissions.push({ body, requestId });
      if (client.submissionError) throw client.submissionError;
      return {
        ...client.submissionEnvelope,
        data: { ...client.submissionEnvelope.data, tx_hash: `mock-tx:${requestId}` },
      };
    },
    async receipt(txHash, requestId) {
      calls.receipts.push({ txHash, requestId });
      if (client.receiptError) throw client.receiptError;
      return client.receiptEnvelope;
    },
  };
  return client;
}

function send(feature, message, sender = UI) {
  return new Promise((resolve) => {
    assert.equal(feature.onMessage(message, sender, resolve), true);
  });
}

async function waitFor(predicate) {
  for (let i = 0; i < 20; i += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("condition was not met");
}

function setup({ storage = makeStorage(), client = makeClient(), alarms = makeAlarms() } = {}) {
  const feature = createTrackerFeature({ storage, client, alarms, baseUrl: "https://localhost:8443" });
  return { feature, storage, client, alarms };
}

test("recording a signed action persists pending state and submits once with a stable request ID", async () => {
  const { feature, storage, client } = setup();
  await feature.record({ request: REQUEST, result: RESULT });
  await waitFor(() => client.calls.submissions.length === 1);

  const record = storage.data.get("transactions")["tx-1"];
  assert.equal(record.status, "pending");
  assert.equal(record.submitted, true);
  assert.equal(record.requestId, "tx-1");
  assert.match(record.explorerUrl, /\/explorer\?kind=receipt&key=mock-tx%3Atx-1/);
  assert.deepEqual(client.calls.submissions[0].body, {
    version: 1,
    api_version: 1,
    tx_bytes: [1, 2, 3],
  });
  assert.equal(client.calls.submissions[0].requestId, "tx-1");
});

test("state and submission survive a worker restart; verification gets an explorer link", async () => {
  const first = setup();
  await first.feature.record({ request: REQUEST, result: RESULT });
  await waitFor(() => first.client.calls.submissions.length === 1);

  const restarted = setup({ storage: first.storage, client: first.client });
  const response = await send(restarted.feature, { type: "refreshTransaction", id: "tx-1" });
  assert.equal(response.ok, true);
  assert.equal(response.transaction.status, "verified");
  assert.equal(response.transaction.label, "VERIFIED ✓");
  assert.equal(response.transaction.explorerUrl, first.storage.data.get("transactions")["tx-1"].explorerUrl);
  assert.equal(first.client.calls.submissions.length, 1); // no duplicate submission after restart
  assert.deepEqual(first.client.calls.receipts[0], {
    txHash: "mock-tx:tx-1",
    requestId: "tx-1:receipt",
  });

  const listed = await send(restarted.feature, { type: "getTransactions" });
  assert.equal(listed.transactions.length, 1);
  assert.equal(listed.transactions[0].label, "VERIFIED ✓");
});

test("verified, rejected and pending states are distinguishable by text", async () => {
  const { feature, client } = setup();
  await feature.record({ request: REQUEST, result: RESULT });
  await waitFor(() => client.calls.submissions.length === 1);

  client.receiptEnvelope = { ...client.receiptEnvelope, data: { status: "Rejected" } };
  const rejected = await send(feature, { type: "refreshTransaction", id: "tx-1" });
  assert.equal(rejected.transaction.status, "rejected");
  assert.equal(rejected.transaction.label, "REJECTED ✗");

  const other = setup();
  await other.feature.record({ request: { ...REQUEST, id: "tx-2" }, result: RESULT });
  await waitFor(() => other.client.calls.submissions.length === 1);
  const pending = await send(other.feature, { type: "getTransaction", id: "tx-2" });
  assert.equal(pending.transaction.label, "PENDING …");
});

test("a not-yet-indexed receipt stays pending instead of being called verified", async () => {
  const { feature, client } = setup();
  await feature.record({ request: REQUEST, result: RESULT });
  await waitFor(() => client.calls.submissions.length === 1);
  client.receiptError = new ApiError("NOT_FOUND", "no receipt yet", 404);
  const refreshed = await send(feature, { type: "refreshTransaction", id: "tx-1" });
  assert.equal(refreshed.transaction.status, "pending");
  assert.equal(refreshed.transaction.apiError.code, "NOT_FOUND");
});

test("the alarm refreshes pending transactions after a service-worker wake", async () => {
  const { feature, client, alarms } = setup();
  await feature.record({ request: REQUEST, result: RESULT });
  await waitFor(() => client.calls.submissions.length === 1);
  assert.deepEqual(alarms.created, [
    { name: TRACKER_ALARM, options: { periodInMinutes: 1 } },
  ]);
  alarms.listeners[0]({ name: TRACKER_ALARM });
  await waitFor(() => client.calls.receipts.length === 1);
});

test("tracker messages are extension-only", async () => {
  const { feature } = setup();
  const denied = await send(feature, { type: "getTransactions" }, PAGE);
  assert.equal(denied.ok, false);
  assert.equal(denied.error.code, "FORBIDDEN");
  assert.equal(feature.onMessage({ type: "unrelated" }, UI, () => {}), false);
});

test("approving a typed request records a tracked transaction once", async () => {
  const storage = makeStorage();
  const client = makeClient();
  const tracker = createTrackerFeature({ storage, client, alarms: makeAlarms() });
  const grants = createGrantsFeature({
    storage,
    windows: { create: async () => ({ id: 1 }), remove: async () => {} },
    runtime: { getURL: (path) => `chrome-extension://test/${path}` },
    signer: async (request) => ({
      signature: `sig:${request.id}`,
      txHash: `mock-tx:${request.id}`,
      txBytes: [9],
    }),
    onSigned: (request, result) => tracker.record({ request, result }),
  });

  const connect = await send(grants, { type: "connect", requestId: "connect-1" });
  await send(grants, { type: "decide", requestId: connect.requestId, decision: "approve" }, UI);
  const request = await send(grants, {
    type: "request",
    requestId: "tx-3",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1" },
  });
  assert.equal(request.status, "pending");
  await send(grants, { type: "decide", requestId: "tx-3", decision: "approve" }, UI);
  await waitFor(() => client.calls.submissions.length === 1);

  const record = storage.data.get("transactions")["tx-3"];
  assert.equal(record.status, "pending");
  assert.equal(record.txHash, "mock-tx:tx-3");
  assert.equal(record.account, "mock-account-1");
  assert.equal(client.calls.submissions[0].requestId, "tx-3");
  // A retry reuses the stored decision and must not track or submit again.
  const retry = await send(grants, {
    type: "request",
    requestId: "tx-3",
    method: "workstream_submitWork",
    params: { chainId: "workstream-local-1" },
  });
  assert.equal(retry.status, "approved");
  assert.equal(client.calls.submissions.length, 1);
});

test("401 re-issues one session and retries with the same X-Request-Id", async () => {
  const calls = [];
  let sessions = 0;
  function response(body, status = 200) {
    return { status, ok: status >= 200 && status < 300, json: async () => body };
  }
  const fetchImpl = async (url, options) => {
    calls.push({ url, headers: options.headers });
    if (url.endsWith("/v1/session")) {
      sessions += 1;
      return response({ api_version: 1, data: { token: "session-token" } });
    }
    if (!options.headers.Authorization) {
      return response({ api_version: 1, error: { code: "UNAUTHORIZED", message: "session expired" } }, 401);
    }
    return response({ api_version: 1, data: { tx_hash: "mock-tx:tx-1", status: "submitted", height: null } });
  };
  const client = createApiClient({ baseUrl: "https://localhost:8443", fetchImpl });
  const envelope = await client.submit({ version: 1, api_version: 1, tx_bytes: [1] }, "tx-1");

  assert.equal(envelope.data.tx_hash, "mock-tx:tx-1");
  assert.equal(sessions, 1);
  const submissions = calls.filter((call) => call.url.endsWith("/v1/submit"));
  assert.equal(submissions.length, 2);
  assert.equal(submissions[0].headers["X-Request-Id"], "tx-1");
  assert.equal(submissions[1].headers["X-Request-Id"], "tx-1");
  assert.equal(submissions[1].headers.Authorization, "Bearer session-token");
  assert.equal(client.hasSession(), true);
  assert.equal(calls.filter((call) => call.url.endsWith("/v1/session")).length, 1);
});
