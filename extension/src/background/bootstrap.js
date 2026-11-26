// One registration surface for every MV3 background feature.
// Listeners are attached synchronously when this module is imported so that
// the service worker wakes correctly after an idle suspension.
export function createBootstrap(chromeApi) {
  const messageHandlers = [];
  const windowRemovedHandlers = [];

  chromeApi.runtime.onMessage.addListener((message, sender, reply) => {
    for (const handle of messageHandlers) {
      if (handle(message, sender, reply) === true) return true;
    }
    return false;
  });

  chromeApi.windows?.onRemoved?.addListener((windowId) => {
    for (const handle of windowRemovedHandlers) handle(windowId);
  });

  return {
    registerFeature(feature) {
      if (typeof feature.onMessage === "function") messageHandlers.push(feature.onMessage);
      if (typeof feature.onWindowRemoved === "function") {
        windowRemovedHandlers.push(feature.onWindowRemoved);
      }
    },
  };
}
