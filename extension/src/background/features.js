import { createBootstrap } from "./bootstrap.js";

// Add background features here. Feature modules call registerFeature with
// their own handlers; the service-worker entry point stays unchanged.
export const bootstrap = createBootstrap(chrome);
