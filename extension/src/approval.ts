import "./styles.css";

type ApprovalRequest = {
  id: string;
  origin: string;
  chainId: string;
  account: string;
  decoded: unknown;
};

type ApprovalResponse = {
  ok?: boolean;
  request?: ApprovalRequest;
  deliveryPending?: boolean;
  error?: { code?: string; message?: string };
};

const requestId = new URLSearchParams(location.search).get("id") ?? "";
const statusEl = document.getElementById("status") as HTMLParagraphElement;
const approveBtn = document.getElementById("approve") as HTMLButtonElement;
const rejectBtn = document.getElementById("reject") as HTMLButtonElement;
const versionEl = document.getElementById("version") as HTMLSpanElement;

const isTopLevel = () => window.top === window.self;
const setButtons = (disabled: boolean) => {
  approveBtn.disabled = disabled;
  rejectBtn.disabled = disabled;
};

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

function setStatus(message: string, isError = false) {
  statusEl.textContent = message;
  statusEl.className = isError ? "error-banner" : "muted";
}

function show(request: ApprovalRequest) {
  (document.getElementById("origin") as HTMLElement).textContent = request.origin;
  (document.getElementById("chain") as HTMLElement).textContent = request.chainId;
  (document.getElementById("account") as HTMLElement).textContent = request.account;
  (document.getElementById("action") as HTMLElement).textContent = JSON.stringify(request.decoded, null, 2);
  (document.getElementById("request-id") as HTMLElement).textContent = request.id;
}

async function decide(decision: "approve" | "reject") {
  // The worker's sender check proves extension origin, not user intent.
  // A framed approval page must never be able to send a decision.
  if (!isTopLevel()) return;
  setButtons(true);
  setStatus(decision === "approve" ? "Approving…" : "Rejecting…");
  try {
    const response = (await chrome.runtime.sendMessage({
      type: "decide",
      requestId,
      decision,
    })) as ApprovalResponse | undefined;
    if (response?.ok) {
      const verb = decision === "approve" ? "Approve" : "Reject";
      setStatus(response.deliveryPending ? `${verb} recorded; sync pending` : `${verb} recorded`);
      // Terminal decisions stay disabled; a failed call is retryable.
      setButtons(true);
    } else {
      setStatus(response?.error?.message ?? "Decision failed", true);
      setButtons(false);
    }
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Decision failed", true);
    setButtons(false);
  }
}

versionEl.textContent = chrome.runtime.getManifest().version;
buildMatrix();
setButtons(true);

approveBtn.addEventListener("click", () => void decide("approve"));
rejectBtn.addEventListener("click", () => void decide("reject"));

async function init() {
  if (!isTopLevel()) {
    setStatus("Approval UI cannot be framed", true);
    setButtons(true);
    return;
  }
  try {
    const response = (await chrome.runtime.sendMessage({
      type: "getApproval",
      requestId,
    })) as ApprovalResponse | undefined;
    if (response?.ok && response.request) {
      show(response.request);
      setStatus("Waiting for your decision.");
      setButtons(false);
    } else if (response?.error?.code === "UNKNOWN_REQUEST") {
      setStatus("Request not found", true);
      setButtons(true);
    } else {
      setStatus(response?.error?.message ?? "Request not found", true);
      setButtons(true);
    }
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Request not found", true);
    setButtons(true);
  }
}

const initial = init();
void hideLoader(1600);
void initial;
