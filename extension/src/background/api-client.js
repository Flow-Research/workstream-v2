// Minimal browser client for the versioned HTTPS API from #130 (PR #163).
// The caller supplies X-Request-Id explicitly so a retry after a 401 is
// idempotent. This module holds no signing material; the session token is
// kept only in service-worker memory and is re-issued after a restart.

export class ApiError extends Error {
  constructor(code, message, status = 0, envelope = null) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.envelope = envelope;
  }
}

export function createApiClient({ baseUrl, fetchImpl = globalThis.fetch, sessionRequestId = (id) => `${id}:session` } = {}) {
  const root = String(baseUrl).replace(/\/$/, "");
  const doFetch = fetchImpl ?? globalThis.fetch;
  let token = null;

  async function parse(response) {
    try {
      return await response.json();
    } catch {
      throw new ApiError("INTERNAL", "API response was not JSON", response.status);
    }
  }

  function check(envelope, response) {
    if (envelope.api_version !== 1) {
      throw new ApiError(
        "UNSUPPORTED_VERSION",
        `unsupported api_version ${envelope.api_version}`,
        response.status,
        envelope,
      );
    }
    if (!response.ok || envelope.error) {
      throw new ApiError(
        envelope.error?.code ?? "INTERNAL",
        envelope.error?.message ?? "API error",
        response.status,
        envelope,
      );
    }
    return envelope;
  }

  async function issueSession(requestId = `session-${Date.now()}`) {
    const response = await doFetch(new URL("/v1/session", root).toString(), {
      method: "POST",
      headers: { "X-Request-Id": requestId },
    });
    const envelope = check(await parse(response), response);
    token = envelope.data?.token ?? null;
    if (!token) throw new ApiError("INTERNAL", "Session token missing", response.status, envelope);
    return envelope;
  }

  async function call(method, path, { body, requestId, params } = {}) {
    if (!requestId) throw new ApiError("INVALID_REQUEST", "A request ID is required");
    const url = new URL(path, root);
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }

    // At most one session re-issue per call; the original request ID is used
    // on both attempts so the API cannot apply a retried submission twice.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const headers = { "X-Request-Id": requestId };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (token) headers.Authorization = `Bearer ${token}`;

      const response = await doFetch(url.toString(), {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const envelope = await parse(response);

      if (response.status === 401 || envelope.error?.code === "UNAUTHORIZED") {
        if (attempt === 0) {
          token = null;
          await issueSession(sessionRequestId(requestId));
          continue;
        }
        throw new ApiError("UNAUTHORIZED", envelope.error?.message ?? "Unauthorized", response.status, envelope);
      }
      return check(envelope, response);
    }
    throw new ApiError("INTERNAL", "API call did not complete");
  }

  return {
    issueSession,
    call,
    submit: (body, requestId) => call("POST", "/v1/submit", { body, requestId }),
    receipt: (txHash, requestId) =>
      call("GET", "/v1/receipt", { requestId, params: { tx_hash: txHash } }),
    // Exposed for unit tests only; never persisted or sent to a page.
    hasSession: () => token !== null,
  };
}
