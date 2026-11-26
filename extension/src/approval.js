const requestId = new URLSearchParams(location.search).get("id") ?? "";
const status = document.getElementById("status");
const approve = document.getElementById("approve");
const reject = document.getElementById("reject");

const isTopLevel = () => window.top === window.self;
const setBusy = (busy) => {
  approve.disabled = busy;
  reject.disabled = busy;
};

function show(request) {
  document.getElementById("origin").textContent = request.origin;
  document.getElementById("chain").textContent = request.chainId;
  document.getElementById("account").textContent = request.account;
  document.getElementById("action").textContent = JSON.stringify(request.decoded);
  document.getElementById("request-id").textContent = request.id;
}

async function decide(decision) {
  // The sender check in the worker proves extension origin, not user intent.
  // A framed approval page must never be able to send a decision.
  if (!isTopLevel()) return;
  setBusy(true);
  try {
    const response = await chrome.runtime.sendMessage({
      type: "decide",
      requestId,
      decision,
    });
    if (!response?.ok) {
      status.textContent = response?.error?.message ?? "Decision failed";
      setBusy(false);
      return;
    }
    status.textContent = response.deliveryPending
      ? `${decision} recorded; sync pending`
      : `${decision} recorded`;
    // Terminal decisions stay disabled; a failed call is retryable.
    approve.disabled = true;
    reject.disabled = true;
  } catch (error) {
    status.textContent = error.message;
    setBusy(false);
  }
}

async function load() {
  if (!isTopLevel()) {
    status.textContent = "Approval UI cannot be framed";
    approve.disabled = true;
    reject.disabled = true;
    return;
  }
  try {
    const response = await chrome.runtime.sendMessage({
      type: "getApproval",
      requestId,
    });
    if (response?.ok) {
      show(response.request);
      approve.disabled = false;
      reject.disabled = false;
    } else if (response?.error?.code === "UNKNOWN_REQUEST") {
      status.textContent = "Request not found";
    } else {
      status.textContent = response?.error?.message ?? "Request not found";
    }
  } catch (error) {
    status.textContent = error.message;
  }
}

approve.addEventListener("click", () => decide("approve"));
reject.addEventListener("click", () => decide("reject"));

await load();
