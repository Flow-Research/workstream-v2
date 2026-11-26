import { createBootstrap } from "./bootstrap.js";
import { createApiClient } from "./api-client.js";
import { createGrantsFeature } from "./grants.js";
import { createMockSigner } from "./mock-signer.js";
import { createTrackerFeature, DEFAULT_API_BASE } from "./tracker.js";

// Add background features here. Feature modules call registerFeature with
// their own handlers; the service-worker entry point stays unchanged.
export const bootstrap = createBootstrap(chrome);

const tracker = createTrackerFeature({
  storage: chrome.storage.local,
  alarms: chrome.alarms,
  createClient: (options) => createApiClient(options),
  baseUrl: DEFAULT_API_BASE,
});

bootstrap.registerFeature(tracker);
bootstrap.registerFeature(
  createGrantsFeature({
    storage: chrome.storage.local,
    windows: chrome.windows,
    runtime: chrome.runtime,
    signer: createMockSigner(),
    onSigned: (request, result) => tracker.record({ request, result }),
  }),
);
