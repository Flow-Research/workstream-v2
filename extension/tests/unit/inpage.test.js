import assert from "node:assert/strict";
import { before, test } from "node:test";

const listeners = [];
const posted = [];

globalThis.window = {
  addEventListener(type, handler) {
    if (type === "message") listeners.push(handler);
  },
  postMessage(message) {
    posted.push(message);
  },
};

before(async () => {
  await import("../../src/content/inpage.js");
});

function lastMessage() {
  return posted.at(-1);
}

function reply(id, result) {
  for (const listener of listeners) {
    listener({
      data: {
        channel: "workstream-provider",
        direction: "content->inpage",
        id,
        ok: true,
        result,
      },
    });
  }
}

function reject(id, code, message) {
  for (const listener of listeners) {
    listener({
      data: {
        channel: "workstream-provider",
        direction: "content->inpage",
        id,
        ok: false,
        error: { code, message },
      },
    });
  }
}

test("provider exposes only the public facade", () => {
  assert.deepEqual(Object.keys(globalThis.workstream).sort(), [
    "connect",
    "disconnect",
    "getAccounts",
    "getChainId",
    "getDecision",
    "request",
    "revoke",
  ]);
});

test("connect carries a request ID and resolves with the result", async () => {
  const promise = globalThis.workstream.connect();
  const message = lastMessage();
  assert.equal(message.type, "connect");
  assert.equal(message.payload.requestId.length > 0, true);
  reply(message.id, { status: "pending", requestId: message.payload.requestId });
  assert.deepEqual(await promise, { status: "pending", requestId: message.payload.requestId });
});

test("account and chain discovery unwrap replies", async () => {
  const accounts = globalThis.workstream.getAccounts();
  reply(lastMessage().id, { accounts: ["mock-account-1"] });
  assert.deepEqual(await accounts, ["mock-account-1"]);

  const chain = globalThis.workstream.getChainId();
  reply(lastMessage().id, { chainId: "workstream-local-1" });
  assert.equal(await chain, "workstream-local-1");
});

test("typed requests carry method, params and request ID", async () => {
  const promise = globalThis.workstream.request({
    method: "workstream_createWorkItem",
    params: { chainId: "workstream-local-1" },
  });
  const message = lastMessage();
  assert.equal(message.type, "request");
  assert.equal(message.payload.method, "workstream_createWorkItem");
  assert.equal(message.payload.params.chainId, "workstream-local-1");
  assert.ok(message.payload.requestId);
  reply(message.id, { status: "pending", requestId: message.payload.requestId });
  assert.equal((await promise).status, "pending");
});

test("errors keep their protocol code and no account is returned", async () => {
  const promise = globalThis.workstream.getAccounts();
  reject(lastMessage().id, "UNAPPROVED_ORIGIN", "no grant");
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, "UNAPPROVED_ORIGIN");
    return true;
  });
});

test("disconnect, revoke and decision polling use the bridge", async () => {
  const disconnect = globalThis.workstream.disconnect();
  assert.equal(lastMessage().type, "disconnect");
  reply(lastMessage().id, { disconnected: true });
  await disconnect;

  const revoke = globalThis.workstream.revoke("https://dapp.example");
  assert.equal(lastMessage().payload.targetOrigin, "https://dapp.example");
  reply(lastMessage().id, { revoked: true });
  await revoke;

  const decision = globalThis.workstream.getDecision("req-1");
  assert.equal(lastMessage().payload.requestId, "req-1");
  reply(lastMessage().id, { status: "approved", result: { signature: "sig:req-1" } });
  assert.equal((await decision).result.signature, "sig:req-1");
});
