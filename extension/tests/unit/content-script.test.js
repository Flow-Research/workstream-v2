import assert from "node:assert/strict";
import { before, test } from "node:test";

const listeners = [];
const posted = [];
const sent = [];
const inserted = [];

globalThis.window = {
  location: { origin: "https://dapp.example" },
  addEventListener(type, handler) {
    if (type === "message") listeners.push(handler);
  },
  postMessage(message, targetOrigin) {
    posted.push({ message, targetOrigin });
  },
};
globalThis.document = {
  head: {
    appendChild(node) {
      inserted.push(node);
    },
  },
  createElement() {
    return { dataset: {}, remove() {} };
  },
};
globalThis.chrome = {
  runtime: {
    getURL: (path) => `chrome-extension://test/${path}`,
    async sendMessage(message) {
      sent.push(message);
      return { ok: true, accounts: ["mock-account-1"] };
    },
  },
};

before(async () => {
  await import("../../src/content/content-script.js");
});

const token = () => inserted[0].dataset.workstreamChannel;
const CHANNEL = "workstream-provider";

function deliver(event) {
  for (const listener of listeners) listener(event);
}

function requestEvent(overrides = {}) {
  return {
    source: window,
    origin: window.location.origin,
    data: {
      channel: CHANNEL,
      token: token(),
      direction: "inpage->content",
      id: `msg-${sent.length}`,
      type: "getAccounts",
      payload: {},
      ...overrides,
    },
  };
}

async function settle() {
  for (let index = 0; index < 10; index += 1) await new Promise((resolve) => setImmediate(resolve));
}

test("injects the provider with a private per-injection token", () => {
  assert.equal(inserted.length, 1);
  assert.equal(inserted[0].dataset.workstream, "provider");
  assert.match(token(), /^[\w-]+$/);
  assert.ok(token().length > 8);
});

test("forwards only same-window, same-origin, tokenized requests", async () => {
  deliver(requestEvent());
  await settle();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].type, "getAccounts");
  // The origin is assigned by the bridge, never trusted from the page payload.
  assert.equal(sent[0].origin, window.location.origin);

  deliver({ ...requestEvent(), source: { frame: "third-party" } });
  deliver({ ...requestEvent(), origin: "https://evil.example" });
  deliver(requestEvent({ token: "guessed" }));
  deliver(requestEvent({ channel: "other-provider" }));
  deliver(requestEvent({ type: "decide" }));
  await settle();
  assert.equal(sent.length, 1);
});

test("replies carry the token and target only the page origin", async () => {
  deliver(requestEvent({ id: "reply-1" }));
  await settle();
  const last = posted.at(-1);
  assert.equal(last.targetOrigin, window.location.origin);
  assert.equal(last.message.channel, CHANNEL);
  assert.equal(last.message.token, token());
  assert.equal(last.message.direction, "content->inpage");
  assert.equal(last.message.id, "reply-1");
  assert.deepEqual(last.message.result, { ok: true, accounts: ["mock-account-1"] });
});
