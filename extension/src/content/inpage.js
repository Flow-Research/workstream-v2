// In-page provider for #148. It exposes a small public facade and relays every
// call to the isolated-world content script. No extension storage, no keys and
// no privileged chrome.* API is reachable from this file.
(() => {
  const CHANNEL = "workstream-provider";
  const token = document.currentScript?.dataset?.workstreamChannel ?? "";
  if (!token) return;

  const pending = new Map();
  let fallbackId = 0;

  const newId = () =>
    globalThis.crypto?.randomUUID?.() ?? `ws-${Date.now()}-${fallbackId++}`;

  window.addEventListener("message", (event) => {
    // Only the injected script's own window may answer. A frame or another
    // document cannot forge the reply with postMessage.
    if (event.source !== window || event.origin !== window.location.origin) return;
    const message = event.data;
    if (
      message?.channel !== CHANNEL ||
      message.token !== token ||
      message.direction !== "content->inpage"
    ) {
      return;
    }
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    if (message.ok) {
      entry.resolve(message.result);
    } else {
      const error = new Error(message.error?.message ?? "WorkStream request failed");
      error.code = message.error?.code ?? "UNKNOWN";
      entry.reject(error);
    }
  });

  function call(type, payload = {}) {
    return new Promise((resolve, reject) => {
      const id = newId();
      pending.set(id, { resolve, reject });
      window.postMessage(
        {
          channel: CHANNEL,
          token,
          direction: "inpage->content",
          id,
          type,
          payload,
        },
        window.location.origin,
      );
    });
  }

  const provider = Object.freeze({
    connect: () => call("connect", { requestId: newId() }),
    disconnect: () => call("disconnect"),
    revoke: (origin) => call("revoke", { targetOrigin: origin }),
    getAccounts: async () => (await call("getAccounts")).accounts,
    getChainId: async () => (await call("getChainId")).chainId,
    request: ({ method, params }) =>
      call("request", { method, params, requestId: newId() }),
    getDecision: (requestId) => call("getDecision", { requestId }),
  });

  Object.defineProperty(globalThis, "workstream", {
    value: provider,
    configurable: true,
    writable: false,
  });
})();
