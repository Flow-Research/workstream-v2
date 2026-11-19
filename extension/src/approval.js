const requestId = new URLSearchParams(location.search).get("id") ?? "";
const status = document.getElementById("status");

function show(request) {
  document.getElementById("origin").textContent = request.origin;
  document.getElementById("chain").textContent = request.chainId;
  document.getElementById("account").textContent = request.account;
  document.getElementById("action").textContent = JSON.stringify(request.decoded);
  document.getElementById("request-id").textContent = request.id;
}

async function decide(decision) {
  const response = await chrome.runtime.sendMessage({
    type: "decide",
    requestId,
    decision,
  });
  status.textContent = response?.ok ? `${decision} recorded` : "Decision failed";
  document.getElementById("approve").disabled = true;
  document.getElementById("reject").disabled = true;
}

try {
  const response = await chrome.runtime.sendMessage({
    type: "getApproval",
    requestId,
  });
  if (response?.ok) show(response.request);
  else status.textContent = response?.error?.message ?? "Request not found";
} catch (error) {
  status.textContent = error.message;
}

document.getElementById("approve").addEventListener("click", () => decide("approve"));
document.getElementById("reject").addEventListener("click", () => decide("reject"));
