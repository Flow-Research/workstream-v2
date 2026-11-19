// Scaffold bridge. The provider bridge is implemented in issue 3 (#148).
// It injects inpage.js into the page world and relays postMessage traffic to
// the service worker; nothing here handles keys or network requests.
const script = document.createElement("script");
script.src = chrome.runtime.getURL("content/inpage.js");
script.dataset.workstream = "provider";
(document.head || document.documentElement).appendChild(script);
script.remove();
