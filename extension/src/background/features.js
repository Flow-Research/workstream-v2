import { createBootstrap } from "./bootstrap.js";
import { createGrantsFeature } from "./grants.js";
import { createMockSigner } from "./mock-signer.js";

// Add background features here. Feature modules call registerFeature with
// their own handlers; the service-worker entry point stays unchanged.
export const bootstrap = createBootstrap(chrome);

bootstrap.registerFeature(
  createGrantsFeature({
    storage: chrome.storage.local,
    windows: chrome.windows,
    runtime: chrome.runtime,
    signer: createMockSigner(),
  }),
);
