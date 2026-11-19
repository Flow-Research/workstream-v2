// Isolated-world bridge for the in-page provider (#148). It forwards an
// allowlisted set of message types to the service worker and injects the
// page-facing facade. It never touches keys or extension storage.
(() => {
  const CHANNEL = "workstream-provider";
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
    const message = event.data;
    if (message?.channel !== CHANNEL || message.direction !== "inpage->content") return;
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
          direction: "content->inpage",
          id: message.id,
          ok: true,
          result,
        },
        "*",
      );
    } catch (error) {
      window.postMessage(
        {
          channel: CHANNEL,
          direction: "content->inpage",
          id: message.id,
          ok: false,
          error: { code: error.code ?? "INTERNAL", message: error.message },
        },
        "*",
      );
    }
  });

  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("content/inpage.js");
  script.dataset.workstream = "provider";
  (document.head || document.documentElement).appendChild(script);
  script.remove();
})();
