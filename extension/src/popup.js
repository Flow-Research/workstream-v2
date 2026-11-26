// Read-only view of tracked transactions. Popup never reads storage or keys;
// the service worker owns verification and the session token (#148 ADR).
const status = document.getElementById("status");
const list = document.getElementById("transactions");

function render(transactions) {
  list.replaceChildren();
  if (transactions.length === 0) {
    status.textContent = "No submitted actions yet.";
    return;
  }
  status.textContent = `${transactions.length} submitted action(s)`;
  for (const tx of transactions) {
    const item = document.createElement("li");

    const state = document.createElement("span");
    state.className = "state";
    state.textContent = tx.label;
    item.append(state, document.createTextNode(`  ${tx.txHash}`));

    const detail = document.createElement("div");
    detail.textContent = `${tx.method ?? "unknown"} · ${tx.origin ?? "unknown"}${tx.apiError ? ` · ${tx.apiError.code}` : ""}`;
    item.append(detail);

    if (tx.explorerUrl) {
      const link = document.createElement("a");
      link.href = tx.explorerUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Explorer receipt";
      item.append(link);
    }
    list.append(item);
  }
}

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error?.message ?? "Request failed");
  return response;
}

async function load() {
  try {
    const response = await send({ type: "getTransactions" });
    render(response.transactions);
  } catch (error) {
    status.textContent = error.message;
  }
}

document.getElementById("version").textContent = chrome.runtime.getManifest().version;
document.getElementById("refresh").addEventListener("click", async () => {
  try {
    const response = await send({ type: "getTransactions" });
    for (const tx of response.transactions.filter((item) => item.status === "pending")) {
      await send({ type: "refreshTransaction", id: tx.id });
    }
    await load();
  } catch (error) {
    status.textContent = error.message;
  }
});

void load();
