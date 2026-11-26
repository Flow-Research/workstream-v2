import "./styles.css";

type TxStatus = "pending" | "verified" | "rejected";
type Transaction = {
  id: string;
  txHash: string;
  status: TxStatus;
  label: string;
  method?: string | null;
  origin?: string | null;
  explorerUrl?: string;
  apiError?: { code: string; message?: string } | null;
};

type RuntimeResponse<T = Record<string, unknown>> = T & {
  ok?: boolean;
  error?: { code?: string; message?: string };
};

const statusEl = document.getElementById("status") as HTMLSpanElement;
const listEl = document.getElementById("transactions") as HTMLUListElement;
const versionEl = document.getElementById("version") as HTMLSpanElement;
const refreshBtn = document.getElementById("refresh") as HTMLButtonElement;

function buildMatrix() {
  const matrix = document.getElementById("matrix");
  if (!matrix) return;
  const chars = "WORKSTREAM ";
  const total = 64;
  for (let i = 0; i < total; i += 1) {
    const stream = document.createElement("div");
    stream.className = "matrix-stream horizontal";
    const len = 22 + (i % 10) * 4;
    for (let j = 0; j < len; j += 1) {
      const span = document.createElement("span");
      span.textContent = chars[(i + j) % chars.length];
      if (j % 7 === 0) span.className = "hot";
      stream.appendChild(span);
    }
    stream.style.top = `${(i * 37 % 105) - 2}%`;
    stream.style.left = "0";
    stream.style.animationDuration = `${7 + (i % 12) * 0.7}s`;
    stream.style.animationDelay = `${-((i * 13) % 60) * 0.2}s`;
    stream.style.opacity = `${0.45 + (i % 6) * 0.08}`;
    stream.style.fontSize = `${14 + (i % 2)}px`;
    matrix.appendChild(stream);
  }
}

async function hideLoader(afterMs: number) {
  const loader = document.getElementById("loader");
  if (!loader) return;
  await new Promise((resolve) => setTimeout(resolve, afterMs));
  loader.classList.add("hidden");
  setTimeout(() => loader.remove(), 340);
}

function badgeClass(status: TxStatus): string {
  if (status === "verified") return "badge-verified";
  if (status === "rejected") return "badge-rejected";
  return "badge-pending";
}

function badgeText(tx: Transaction): string {
  if (tx.status === "verified") return "VERIFIED";
  if (tx.status === "rejected") return "REJECTED";
  return "PENDING";
}

function render(transactions: Transaction[]) {
  listEl.replaceChildren();
  if (transactions.length === 0) {
    statusEl.textContent = "No activity";
    const empty = document.createElement("li");
    empty.className = "empty-state";
    const strong = document.createElement("strong");
    strong.textContent = "No submitted actions yet";
    const text = document.createElement("div");
    text.textContent = "Approved actions will appear here with receipt verification status.";
    empty.append(strong, text);
    listEl.append(empty);
    return;
  }

  statusEl.textContent = `${transactions.length} tracked`;
  for (const tx of transactions) {
    const item = document.createElement("li");
    item.className = "tx-card";

    const top = document.createElement("div");
    top.className = "tx-top";

    const hash = document.createElement("div");
    hash.className = "tx-hash";
    hash.textContent = tx.txHash;

    const badge = document.createElement("span");
    badge.className = `badge ${badgeClass(tx.status)}`;
    badge.textContent = badgeText(tx);
    badge.setAttribute("aria-label", tx.label || badgeText(tx));

    top.append(hash, badge);

    const meta = document.createElement("div");
    meta.className = "tx-meta";
    const parts = [tx.method ?? "unknown", tx.origin ?? "unknown"];
    if (tx.apiError?.code) parts.push(tx.apiError.code);
    meta.textContent = parts.join(" · ");

    item.append(top, meta);

    if (tx.explorerUrl) {
      const link = document.createElement("a");
      link.className = "tx-link";
      link.href = tx.explorerUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "View explorer receipt";
      item.append(link);
    }

    listEl.append(item);
  }
}

async function send<T = Record<string, unknown>>(message: unknown): Promise<RuntimeResponse<T>> {
  const response = (await chrome.runtime.sendMessage(message)) as RuntimeResponse<T> | undefined;
  if (!response?.ok) throw new Error(response?.error?.message ?? "Request failed");
  return response;
}

async function load() {
  try {
    const response = await send<{ transactions: Transaction[] }>({ type: "getTransactions" });
    render(response.transactions ?? []);
  } catch (error) {
    statusEl.textContent = error instanceof Error ? error.message : "Request failed";
  }
}

versionEl.textContent = chrome.runtime.getManifest().version;
buildMatrix();

refreshBtn.addEventListener("click", async () => {
  refreshBtn.disabled = true;
  statusEl.textContent = "Refreshing…";
  try {
    const response = await send<{ transactions: Transaction[] }>({ type: "getTransactions" });
    for (const tx of (response.transactions ?? []).filter((item) => item.status === "pending")) {
      await send({ type: "refreshTransaction", id: tx.id });
    }
    await load();
  } catch (error) {
    statusEl.textContent = error instanceof Error ? error.message : "Request failed";
  } finally {
    refreshBtn.disabled = false;
  }
});

const initialLoad = load();
void hideLoader(1900);
void initialLoad;
