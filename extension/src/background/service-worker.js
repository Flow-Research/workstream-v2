import { bootstrap } from "./features.js";

// Keep this entry point free of feature logic. All listeners are registered
// synchronously at module evaluation through bootstrap().
void bootstrap;
