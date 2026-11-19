// Origin grants and the in-page provider protocol.
// All durable state lives in chrome.storage.local. The mock signer is the only
// signing capability and it lives in this (service worker) module.

export const CHAIN_ID = "workstream-local-1";
export const MOCK_ACCOUNT = "mock-account-1";

const ALLOWED_METHODS = new Set(["workstream_createWorkItem", "workstream_submitWork"]);
const HANDLED_TYPES = new Set([
  "connect",
  "getAccounts",
  "getChainId",
  "disconnect",
  "revoke",
  "request",
  "getDecision",
  "getApproval",
  "decide",
]);

const ok = (reply, data = {}) => reply({ ok: true, ...data });
const fail = (reply, code, message) => reply({ ok: false, error: { code, message } });

function protocolError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function isExtensionSender(sender) {
  return String(sender?.url ?? "").startsWith("chrome-extension://");
}

function messageOrigin(message, sender) {
  const tabUrl = sender?.tab?.url;
  if (tabUrl) {
    let origin;
    try {
      origin = new URL(tabUrl).origin;
    } catch {
      throw protocolError("ORIGIN_MISMATCH", "Sender tab has no valid origin");
    }
    if (message.origin && message.origin !== origin) {
      throw protocolError("ORIGIN_MISMATCH", "Claimed origin does not match sender tab");
    }
    return origin;
  }
  return message.origin ?? null;
}

export function createGrantsFeature({ storage, windows, runtime, signer }) {
  const read = async (key, fallback) => (await storage.get(key))[key] ?? fallback;
  const write = (key, value) => storage.set({ [key]: value });

  async function openApproval(request) {
    const url = runtime.getURL(`approval.html?id=${encodeURIComponent(request.id)}`);
    const window = await windows.create({ url, type: "popup", width: 440, height: 560 });
    const windowMap = await read("windowMap", {});
    windowMap[String(window.id)] = request.id;
    await write("windowMap", windowMap);
  }

  async function newRequest(request) {
    const requests = await read("requests", {});
    requests[request.id] = request;
    await write("requests", requests);
    await openApproval(request);
  }

  async function updateRequest(requestId, patch) {
    const requests = await read("requests", {});
    const current = requests[requestId];
    if (!current) return null;
    requests[requestId] = { ...current, ...patch };
    await write("requests", requests);
    return requests[requestId];
  }

  async function decisionResult(request) {
    if (request.state === "pending") return { status: "pending", requestId: request.id };
    if (request.state === "rejected") {
      return { status: "rejected", requestId: request.id, error: request.error };
    }
    return { status: "approved", requestId: request.id, result: request.result };
  }

  async function handle(message, sender) {
    // Extension-owned UI messages (getApproval/decide) are not page requests
    // and therefore do not carry a page origin.
    const origin = isExtensionSender(sender) ? null : messageOrigin(message, sender);
    if (origin === null && !isExtensionSender(sender)) {
      throw protocolError("ORIGIN_MISMATCH", "Missing requesting origin");
    }

    switch (message.type) {
      case "connect": {
        const grants = await read("grants", {});
        if (grants[origin]) {
          return { granted: true, accounts: [grants[origin].account], chainId: grants[origin].chainId };
        }
        const request = {
          id: message.requestId,
          origin,
          chainId: CHAIN_ID,
          account: MOCK_ACCOUNT,
          kind: "connect",
          decoded: { method: "connect", fields: ["origin", "chainId", "account"] },
          state: "pending",
        };
        await newRequest(request);
        return { status: "pending", requestId: request.id };
      }

      case "getAccounts": {
        const grants = await read("grants", {});
        return { accounts: grants[origin] ? [grants[origin].account] : [] };
      }

      case "getChainId":
        return { chainId: CHAIN_ID };

      case "disconnect": {
        const grants = await read("grants", {});
        delete grants[origin];
        await write("grants", grants);
        return { disconnected: true, origin };
      }

      case "revoke": {
        const target = isExtensionSender(sender) ? message.targetOrigin : origin;
        if (!target) throw protocolError("INVALID_TARGET", "No origin to revoke");
        const grants = await read("grants", {});
        delete grants[target];
        await write("grants", grants);
        return { revoked: true, origin: target };
      }

      case "request": {
        const grants = await read("grants", {});
        if (!grants[origin]) throw protocolError("UNAPPROVED_ORIGIN", "Origin has no account grant");
        if (!ALLOWED_METHODS.has(message.method)) {
          throw protocolError("UNSUPPORTED_ACTION", `Unsupported method: ${message.method}`);
        }
        const params = message.params ?? {};
        if (params.chainId !== CHAIN_ID) {
          throw protocolError("CHAIN_MISMATCH", `Expected chain ${CHAIN_ID}`);
        }
        if (typeof message.requestId !== "string" || message.requestId.length === 0) {
          throw protocolError("INVALID_REQUEST_ID", "A request ID is required");
        }

        const requests = await read("requests", {});
        const existing = requests[message.requestId];
        if (existing) {
          if (existing.origin !== origin || existing.method !== message.method) {
            throw protocolError("REQUEST_ID_REUSE", "Request ID belongs to a different action");
          }
          return await decisionResult(existing);
        }

        const request = {
          id: message.requestId,
          origin,
          chainId: CHAIN_ID,
          account: grants[origin].account,
          method: message.method,
          params,
          decoded: { method: message.method, params },
          state: "pending",
        };
        await newRequest(request);
        return { status: "pending", requestId: request.id };
      }

      case "getDecision": {
        const requests = await read("requests", {});
        const request = requests[message.requestId];
        if (!request || request.origin !== origin) {
          throw protocolError("UNKNOWN_REQUEST", "Unknown request ID for this origin");
        }
        return await decisionResult(request);
      }

      case "getApproval": {
        if (!isExtensionSender(sender)) throw protocolError("FORBIDDEN", "Extension context only");
        const requests = await read("requests", {});
        const request = requests[message.requestId];
        if (!request) throw protocolError("UNKNOWN_REQUEST", "Unknown request ID");
        return { request };
      }

      case "decide": {
        if (!isExtensionSender(sender)) throw protocolError("FORBIDDEN", "Extension context only");
        const request = await read("requests", {}).then((requests) => requests[message.requestId]);
        if (!request) throw protocolError("UNKNOWN_REQUEST", "Unknown request ID");
        if (request.state !== "pending") {
          return { alreadyDecided: true, ...(await decisionResult(request)) };
        }
        if (message.decision === "reject") {
          await updateRequest(request.id, {
            state: "rejected",
            error: { code: "REJECTED", message: "User rejected the action" },
          });
        } else if (message.decision === "approve") {
          // Connecting grants an account but signs nothing. Transaction
          // requests are signed exactly once per request ID; retries read the
          // stored result instead of invoking the signer again.
          const result =
            request.kind === "connect"
              ? { granted: true, accounts: [request.account], chainId: request.chainId }
              : await signer(request);
          await updateRequest(request.id, { state: "consumed", result });
        } else {
          throw protocolError("INVALID_DECISION", "Decision must be approve or reject");
        }

        const windowMap = await read("windowMap", {});
        for (const [windowId, requestId] of Object.entries(windowMap)) {
          if (requestId === request.id) {
            delete windowMap[windowId];
            await write("windowMap", windowMap);
            await windows.remove?.(Number(windowId));
          }
        }

        if (request.kind === "connect" && message.decision === "approve") {
          const grants = await read("grants", {});
          grants[request.origin] = { account: request.account, chainId: request.chainId, grantedAt: Date.now() };
          await write("grants", grants);
        }
        return { ok: true, ...(await decisionResult(await read("requests", {}).then((r) => r[request.id]))) };
      }

      default:
        return { unhandled: true };
    }
  }

  return {
    onMessage(message, sender, reply) {
      if (!HANDLED_TYPES.has(message?.type)) return false;
      handle(message, sender).then(
        (result) => ok(reply, result),
        (error) => fail(reply, error.code ?? "INTERNAL", error.message),
      );
      return true;
    },
    async onWindowRemoved(windowId) {
      const windowMap = await read("windowMap", {});
      const requestId = windowMap[String(windowId)];
      if (!requestId) return;
      delete windowMap[String(windowId)];
      await write("windowMap", windowMap);
      const request = await read("requests", {}).then((requests) => requests[requestId]);
      if (request?.state === "pending") {
        await updateRequest(requestId, {
          state: "rejected",
          error: { code: "POPUP_CLOSED", message: "Approval window was closed" },
        });
      }
    },
  };
}
