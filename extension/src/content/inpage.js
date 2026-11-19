// Scaffold only. The in-page provider API is implemented in issue 3 (#148).
if (!globalThis.workstream) {
  globalThis.workstream = Object.freeze({ ready: false });
}
