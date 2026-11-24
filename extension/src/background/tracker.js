// Transaction tracker for #148 / #175. Every submitted action is persisted in
// chrome.storage.local by its request ID, so state survives a service-worker
// restart. Verification comes from the #130 API and explorer links follow the
// #132 receipt bookmark route. Session tokens stay in worker memory.

export const TRACKER_ALARM = "workstream-transaction-refresh";
export const DEFAULT_API_BASE = "https://localhost:8443";

const HANDLED_TYPES = new Set(["getTransactions", "getTransaction", "refreshTransaction"]);
const isExtensionSender = (sender) => String(sender?.url ?? "").startsWith("chrome-extension://");

function explorerUrl(baseUrl, txHash) {
  try {
    const url = new URL(`/explorer?kind=receipt&key=${encodeURIComponent(txHash)}`, baseUrl);
    // Never hand a page a non-HTTP(S) link.
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : "";
  } catch {
    return "";
  }
}

function label(status) {
  if (status === "verified") return "VERIFIED ✓";
  if (status === "rejected") return "REJECTED ✗";
  return "PENDING …";
}

function summarise(record) {
  // Signed bytes stay in the service worker; the popup only needs public
  // identifiers, state and the explorer link.
  const { txBytes, ...publicRecord } = record;
  return { ...publicRecord, label: label(record.status) };
}

export function createTrackerFeature({
  storage,
  alarms,
  client,
  createClient,
  fetchImpl,
  baseUrl = DEFAULT_API_BASE,
  now = () => Date.now(),
}) {
  const read = async (key, fallback) => (await storage.get(key))[key] ?? fallback;
  const write = (key, value) => storage.set({ [key]: value });
  const clients = new Map();
  const inflight = new Set();

  function clientFor(apiBase) {
    if (client) return client;
    if (!clients.has(apiBase)) {
      clients.set(
        apiBase,
        createClient
          ? createClient({ baseUrl: apiBase, fetchImpl })
          : undefined,
      );
    }
    const result = clients.get(apiBase);
    if (!result) throw new Error("Tracker needs a client or createClient factory");
    return result;
  }

  const all = () => read("transactions", {});

  async function save(id, patch) {
    const transactions = await all();
    const current = transactions[id];
    if (!current) return null;
    transactions[id] = { ...current, ...patch, updatedAt: now() };
    await write("transactions", transactions);
    return transactions[id];
  }

  async function submit(id) {
    const guard = `submit:${id}`;
    if (inflight.has(guard)) return;
    const record = (await all())[id];
    if (!record || record.submitted || record.status !== "pending") return;
    inflight.add(guard);
    try {
      const apiBase = await read("apiBaseUrl", baseUrl);
      const envelope = await clientFor(apiBase).submit(
        { version: 1, api_version: 1, tx_bytes: record.txBytes ?? [] },
        record.requestId ?? id,
      );
      await save(id, {
        submitted: true,
        txHash: envelope.data?.tx_hash ?? record.txHash,
        apiStatus: envelope.data?.status ?? "submitted",
        apiError: null,
      });
    } catch (error) {
      // A duplicate response means the earlier submission landed; never send
      // it again. Other failures stay pending with a visible error.
      await save(id, {
        submitted: error.code === "DUPLICATE_REQUEST",
        apiError: { code: error.code ?? "INTERNAL", message: error.message },
      });
    } finally {
      inflight.delete(guard);
    }
  }

  async function refresh(id) {
    const guard = `refresh:${id}`;
    if (inflight.has(guard)) return (await all())[id];
    inflight.add(guard);
    try {
      let record = (await all())[id];
      if (!record || record.status !== "pending") return record ?? null;
      await submit(id);
      record = (await all())[id];

      const apiBase = await read("apiBaseUrl", baseUrl);
      const envelope = await clientFor(apiBase).receipt(record.txHash, `${record.requestId ?? id}:receipt`);
      const status = String(envelope.data?.status ?? "").toLowerCase();
      const patch = {
        readHeight: envelope.read_height,
        indexedHeight: envelope.indexed_height,
        stale: envelope.stale ?? false,
        apiError: null,
      };
      if (status.includes("verified")) patch.status = "verified";
      else if (status.includes("rejected") || status.includes("invalid")) patch.status = "rejected";
      return await save(id, patch);
    } catch (error) {
      const code = error.code ?? "INTERNAL";
      const patch = { apiError: { code, message: error.message } };
      // Only an explicit protocol rejection is final; a network failure or a
      // not-yet-indexed receipt leaves the record pending for a later refresh.
      if (code === "INVALID_TRANSACTION" || code === "NETWORK_MISMATCH") patch.status = "rejected";
      return await save(id, patch);
    } finally {
      inflight.delete(guard);
    }
  }

  async function refreshAll() {
    const transactions = await all();
    for (const record of Object.values(transactions)) {
      if (record.status === "pending") await refresh(record.id);
    }
  }

  async function handle(message) {
    switch (message.type) {
      case "getTransactions": {
        const transactions = await all();
        return { transactions: Object.values(transactions).map(summarise) };
      }
      case "getTransaction": {
        const record = (await all())[message.id];
        if (!record) return { transaction: null };
        return { transaction: summarise(record) };
      }
      case "refreshTransaction": {
        const record = await refresh(message.id);
        return { transaction: record ? summarise(record) : null };
      }
      default:
        return { unhandled: true };
    }
  }

  // Alarm listeners are attached at feature construction time (module
  // evaluation in the service worker) so an idle worker wakes correctly.
  const onAlarm = (alarm) => {
    if (alarm.name === TRACKER_ALARM) void refreshAll();
  };
  if (typeof alarms?.onAlarm?.addListener === "function") {
    alarms.onAlarm.addListener(onAlarm);
  } else if (typeof alarms?.addListener === "function") {
    alarms.addListener(onAlarm);
  }
  alarms?.create?.(TRACKER_ALARM, { periodInMinutes: 1 });

  return {
    async record({ request, result }) {
      const id = request.id;
      const transactions = await all();
      if (transactions[id]) return summarise(transactions[id]);
      const apiBase = await read("apiBaseUrl", baseUrl);
      const txHash = result.txHash ?? `mock-tx:${encodeURIComponent(id)}`;
      const timestamp = now();
      transactions[id] = {
        id,
        requestId: id,
        origin: request.origin ?? null,
        account: request.account ?? null,
        method: request.method ?? null,
        txHash,
        txBytes: result.txBytes ?? [],
        status: "pending",
        submitted: false,
        explorerUrl: explorerUrl(apiBase, txHash),
        createdAt: timestamp,
        updatedAt: timestamp,
      };
      await write("transactions", transactions);
      void submit(id);
      return summarise(transactions[id]);
    },

    onAlarm: refreshAll,

    onMessage(message, sender, reply) {
      if (!HANDLED_TYPES.has(message?.type)) return false;
      if (!isExtensionSender(sender)) {
        reply({ ok: false, error: { code: "FORBIDDEN", message: "Extension context only" } });
        return true;
      }
      handle(message).then(
        (result) => reply({ ok: true, ...result }),
        (error) => reply({ ok: false, error: { code: error.code ?? "INTERNAL", message: error.message } }),
      );
      return true;
    },
  };
}
