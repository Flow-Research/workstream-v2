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

// A stable, dependency-free canonical form. The hash binds a caller-supplied
// request ID to the exact action it approved, not just to its method.
function stableStringify(value) {
  if (value === undefined) return "undefined";
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function canonicalHash(value) {
  const input = stableStringify(value);
  let a = 0x811c9dc5;
  let b = 0x01000193;
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    a = Math.imul(a ^ code, 0x01000193) >>> 0;
    b = Math.imul(b + code, 0x85ebca6b) >>> 0;
  }
  return `${a.toString(16).padStart(8, "0")}${b.toString(16).padStart(8, "0")}`;
}

function bindingHash(request) {
  return canonicalHash({
    kind: request.kind,
    origin: request.origin,
    account: request.account,
    chainId: request.chainId,
    method: request.method ?? null,
    params: request.params ?? null,
  });
}

function assertSameBinding(existing, candidate) {
  if (bindingHash(existing) !== candidate.requestHash) {
    throw protocolError("REQUEST_ID_REUSE", "Request ID belongs to a different action");
  }
}

function requireRequestId(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw protocolError("INVALID_REQUEST_ID", "A request ID is required");
  }
  return value;
}

export function createGrantsFeature({ storage, windows, runtime, signer, onSigned }) {
  const read = async (key, fallback) => (await storage.get(key))[key] ?? fallback;
  const write = (key, value) => storage.set({ [key]: value });
  const queues = new Map();

  // chrome.storage reads and writes are separate async calls. Serialize whole
  // map mutations (and each request's decision transition) so a stale snapshot
  // cannot erase a concurrent record or sign the same request twice.
  function serialized(key, fn) {
    const previous = queues.get(key) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(fn);
    queues.set(key, next);
    const cleanup = () => {
      if (queues.get(key) === next) queues.delete(key);
    };
    next.then(cleanup, cleanup);
    return next;
  }

  async function mutateMap(key, mutator) {
    return serialized(`map:${key}`, async () => {
      const map = await read(key, {});
      const result = await mutator(map);
      await write(key, map);
      return result;
    });
  }

  const readRequest = async (id) => (await read("requests", {}))[id];
  const withRequest = (id, fn) => serialized(`request:${id}`, fn);

  async function updateRequest(requestId, patch) {
    return mutateMap("requests", (requests) => {
      const current = requests[requestId];
      if (!current) return null;
      requests[requestId] = { ...current, ...patch };
      return requests[requestId];
    });
  }

  async function openApproval(request) {
    const url = runtime.getURL(`approval.html?id=${encodeURIComponent(request.id)}`);
    const window = await windows.create({ url, type: "popup", width: 440, height: 560 });
    await mutateMap("windowMap", (windowMap) => {
      windowMap[String(window.id)] = request.id;
    });
  }

  async function ensureApproval(request) {
    if (request.state !== "pending") return;
    const windowMap = await read("windowMap", {});
    if (Object.values(windowMap).includes(request.id)) return;
    // A failed windows.create leaves the request pending with no UI. Replaying
    // the request retries creation; a successful replay never duplicates it.
    await openApproval(request);
  }

  async function closeApprovalWindows(requestId) {
    const remove = [];
    await mutateMap("windowMap", (windowMap) => {
      for (const [windowId, mappedId] of Object.entries(windowMap)) {
        if (mappedId === requestId) {
          remove.push(Number(windowId));
          delete windowMap[windowId];
        }
      }
    });
    for (const windowId of remove) await windows.remove?.(windowId);
  }

  // Persist consumed state BEFORE calling side effects. If a hook fails, replay
  // finishes it from the stored result instead of signing a second time.
  async function finalize(request) {
    if (request.state !== "consumed") return request;

    if (request.kind === "connect") {
      await mutateMap("grants", (grants) => {
        const prior = grants[request.origin];
        grants[request.origin] = {
          account: request.account,
          chainId: request.chainId,
          grantedAt: prior?.grantedAt ?? Date.now(),
        };
      });
      return (await updateRequest(request.id, { completion: "complete" })) ?? request;
    }

    if (typeof onSigned === "function") {
      try {
        await onSigned(request, request.result);
      } catch (error) {
        await updateRequest(request.id, {
          sideEffectError: { code: error.code ?? "INTERNAL", message: error.message },
        });
        return (await readRequest(request.id)) ?? request;
      }
    }
    await updateRequest(request.id, { delivered: true, sideEffectError: null });
    return (await readRequest(request.id)) ?? request;
  }

  async function replay(request) {
    const finalized = await finalize(request);
    await ensureApproval(finalized);
    return finalized;
  }

  function decisionResult(request) {
    const result =
      request.state === "pending"
        ? { status: "pending", requestId: request.id }
        : request.state === "rejected"
          ? { status: "rejected", requestId: request.id, error: request.error }
          : { status: "approved", requestId: request.id, result: request.result };
    if (request.state === "consumed") {
      const pendingSideEffect =
        request.kind === "connect" ? request.completion !== "complete" : request.delivered !== true;
      if (pendingSideEffect) result.deliveryPending = true;
    }
    return result;
  }

  async function newRequest(request) {
    await mutateMap("requests", (requests) => {
      requests[request.id] = request;
    });
    await ensureApproval(request);
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
        const id = requireRequestId(message.requestId);
        const candidate = {
          id,
          origin,
          chainId: CHAIN_ID,
          account: MOCK_ACCOUNT,
          kind: "connect",
          decoded: { method: "connect", fields: ["origin", "chainId", "account"] },
          state: "pending",
        };
        candidate.requestHash = bindingHash(candidate);
        const outcome = await withRequest(id, async () => {
          const existing = await readRequest(id);
          if (existing) {
            assertSameBinding(existing, candidate);
            return replay(existing);
          }
          await newRequest(candidate);
          return candidate;
        });
        return outcome === candidate ? { status: "pending", requestId: id } : decisionResult(outcome);
      }

      case "getAccounts": {
        const grants = await read("grants", {});
        return { accounts: grants[origin] ? [grants[origin].account] : [] };
      }

      case "getChainId":
        return { chainId: CHAIN_ID };

      case "disconnect": {
        await mutateMap("grants", (grants) => {
          delete grants[origin];
        });
        return { disconnected: true, origin };
      }

      case "revoke": {
        const target = isExtensionSender(sender) ? message.targetOrigin : origin;
        if (!target) throw protocolError("INVALID_TARGET", "No origin to revoke");
        await mutateMap("grants", (grants) => {
          delete grants[target];
        });
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
        const id = requireRequestId(message.requestId);
        const candidate = {
          id,
          origin,
          chainId: CHAIN_ID,
          account: grants[origin].account,
          method: message.method,
          params,
          decoded: { method: message.method, params },
          state: "pending",
        };
        candidate.requestHash = bindingHash(candidate);
        const outcome = await withRequest(id, async () => {
          const existing = await readRequest(id);
          if (existing) {
            assertSameBinding(existing, candidate);
            return replay(existing);
          }
          await newRequest(candidate);
          return candidate;
        });
        return outcome === candidate ? { status: "pending", requestId: id } : decisionResult(outcome);
      }

      case "getDecision": {
        const id = requireRequestId(message.requestId);
        const request = await withRequest(id, async () => {
          const existing = await readRequest(id);
          if (!existing || existing.origin !== origin) {
            throw protocolError("UNKNOWN_REQUEST", "Unknown request ID for this origin");
          }
          return replay(existing);
        });
        return decisionResult(request);
      }

      case "getApproval": {
        if (!isExtensionSender(sender)) throw protocolError("FORBIDDEN", "Extension context only");
        const request = await readRequest(requireRequestId(message.requestId));
        if (!request) throw protocolError("UNKNOWN_REQUEST", "Unknown request ID");
        return { request };
      }

      case "decide": {
        if (!isExtensionSender(sender)) throw protocolError("FORBIDDEN", "Extension context only");
        const id = requireRequestId(message.requestId);
        return withRequest(id, async () => {
          const request = await readRequest(id);
          if (!request) throw protocolError("UNKNOWN_REQUEST", "Unknown request ID");
          if (request.state !== "pending") {
            const finalized = await finalize(request);
            return { alreadyDecided: true, ...decisionResult(finalized) };
          }
          if (message.decision === "reject") {
            await updateRequest(id, {
              state: "rejected",
              error: { code: "REJECTED", message: "User rejected the action" },
            });
          } else if (message.decision === "approve") {
            // Connecting grants an account but signs nothing. Transaction
            // requests are signed exactly once per request ID; retries read the
            // stored result instead of invoking the signer again.
            if (request.kind === "connect") {
              await updateRequest(id, {
                state: "consumed",
                result: { granted: true, accounts: [request.account], chainId: request.chainId },
                completion: "grant-pending",
              });
            } else {
              const result = await signer(request);
              // Durable before the tracker hook: a failing hook can be replayed
              // from storage, but it can never cause a second signature.
              await updateRequest(id, { state: "consumed", result, delivered: false });
            }
          } else {
            throw protocolError("INVALID_DECISION", "Decision must be approve or reject");
          }

          const finalized = await finalize(await readRequest(id));
          // Window cleanup happens after the required effect is durable.
          await closeApprovalWindows(id);
          return decisionResult(finalized);
        });
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
      const requestId = await mutateMap("windowMap", (windowMap) => {
        const id = windowMap[String(windowId)];
        if (id) delete windowMap[String(windowId)];
        return id;
      });
      if (!requestId) return;
      await withRequest(requestId, async () => {
        const request = await readRequest(requestId);
        if (request?.state === "pending") {
          await updateRequest(requestId, {
            state: "rejected",
            error: { code: "POPUP_CLOSED", message: "Approval window was closed" },
          });
        }
      });
    },
  };
}
