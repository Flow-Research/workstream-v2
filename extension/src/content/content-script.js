// Isolated-world bridge for the in-page provider (#148). It forwards an
// allowlisted set of message types to the service worker and injects the
// page-facing facade. It never touches keys or extension storage.
(() => {
  const CHANNEL = "workstream-provider";
  // Per-injection token: a page cannot guess the channel used by this bridge,
  // and a frame cannot reuse its parent's token.
  const token =
    globalThis.crypto?.randomUUID?.() ??
    `ws-bridge-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const ALLOWED_TYPES = new Set([
    "connect",
    "disconnect",
    "revoke",
    "getAccounts",
    "getChainId",
    "request",
    "getDecision",
  ]);

  window.addEventListener("message", async (event) => {
    if (event.source !== window || event.origin !== window.location.origin) return;
    const message = event.data;
    if (
      message?.channel !== CHANNEL ||
      message.token !== token ||
      message.direction !== "inpage->content"
    ) {
      return;
    }
    if (!ALLOWED_TYPES.has(message.type)) return;

    try {
      const result = await chrome.runtime.sendMessage({
        ...message.payload,
        type: message.type,
        origin: window.location.origin,
      });
      if (result?.ok === false) {
        const error = new Error(result.error?.message ?? "WorkStream request failed");
        error.code = result.error?.code ?? "UNKNOWN";
        throw error;
      }
      window.postMessage(
        {
          channel: CHANNEL,
          token,
          direction: "content->inpage",
          id: message.id,
          ok: true,
          result,
        },
        window.location.origin,
      );
    } catch (error) {
      window.postMessage(
        {
          channel: CHANNEL,
          token,
          direction: "content->inpage",
          id: message.id,
          ok: false,
          error: { code: error.code ?? "INTERNAL", message: error.message },
        },
        window.location.origin,
      );
    }
  });

  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("content/inpage.js");
  script.dataset.workstream = "provider";
  script.dataset.workstreamChannel = token;
  (document.head || document.documentElement).appendChild(script);
  script.remove();
})();
