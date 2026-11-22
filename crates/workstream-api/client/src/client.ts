/**
 * WorkStream browser-safe API client (issue #130).
 *
 * GENERATED from `../openapi.json`; do not edit by hand. The client holds no
 * signing keys: callers sign locally with WebCrypto and submit the canonical
 * signed transaction bytes. Read models are projections and the verifier
 * journal remains the authority.
 */

/** Stable error codes, mirrored from the Rust `ErrorCode` enum. */
export type ErrorCode =
  | "INVALID_REQUEST"
  | "UNSUPPORTED_VERSION"
  | "INVALID_TRANSACTION"
  | "DUPLICATE_REQUEST"
  | "NOT_FOUND"
  | "STALE_PROJECTION"
  | "NETWORK_MISMATCH"
  | "UNAUTHORIZED"
  | "INTERNAL";

export interface ApiErrorBody {
  code: ErrorCode;
  message: string;
}

/** Versioned response envelope present on every response. */
export interface Envelope<T> {
  api_version: number;
  request_id: string;
  network: string;
  read_height: number;
  indexed_height: number;
  error?: ApiErrorBody;
  data?: T;
}

export interface SessionData {
  token: string;
  api_version: number;
  expires_in_secs: number;
}

export interface SubmitRequest {
  version: number;
  api_version: number;
  /** JSON bytes of an already-signed transaction; never a private key. */
  tx_bytes: number[];
}

export interface SubmitData {
  tx_hash: string;
  status: string;
  height: number | null;
}

export interface ReceiptData {
  tx_hash: string;
  status: string;
  height: number | null;
}

export interface ChainData {
  height: number;
  state_root: string;
  da_ref: string | null;
  indexed_height: number;
  lag: number;
  stale: boolean;
}

export interface PageData {
  kind: string;
  items: Record<string, unknown>[];
  next_cursor: string | null;
  stale: boolean;
}

/** Error thrown for a non-2xx response with a stable error body. */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly envelope: Envelope<never>;
  constructor(envelope: Envelope<never>) {
    super(envelope.error?.message ?? "API error");
    this.name = "ApiError";
    this.code = envelope.error?.code ?? "INTERNAL";
    this.envelope = envelope;
  }
}

export interface ClientOptions {
  /** Base origin, e.g. https://localhost:8443. */
  baseUrl: string;
  /** Explicit session token issued by issueSession(). */
  token?: string;
  /** Optional fetch implementation (tests can inject a stub). */
  fetch?: typeof fetch;
}

/** Thin typed client over the versioned JSON envelope contract. */
export class WorkstreamClient {
  private readonly baseUrl: string;
  private token: string | undefined;
  private readonly doFetch: typeof fetch;
  private requestCounter = 0;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.token = options.token;
    this.doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Install a session token obtained from issueSession(). */
  setToken(token: string): void {
    this.token = token;
  }

  private nextRequestId(): string {
    this.requestCounter += 1;
    const random = globalThis.crypto.getRandomValues(new Uint8Array(8));
    const tail = Array.from(random, (b) => b.toString(16).padStart(2, "0")).join("");
    return `web-${tail}-${this.requestCounter}`;
  }

  private async call<T>(
    method: "GET" | "POST",
    path: string,
    params?: Record<string, string | number | undefined>,
    body?: unknown,
    auth: boolean = true,
  ): Promise<Envelope<T>> {
    const url = new URL(path, this.baseUrl);
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    const headers: Record<string, string> = {
      "X-Request-Id": this.nextRequestId(),
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const response = await this.doFetch(url.toString(), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const envelope = (await response.json()) as Envelope<T>;
    if (envelope.api_version !== 1) {
      throw new ApiError({
        ...envelope,
        error: { code: "UNSUPPORTED_VERSION", message: `unsupported api_version ${envelope.api_version}` },
      } as Envelope<never>);
    }
    if (!response.ok || envelope.error) {
      throw new ApiError(envelope as Envelope<never>);
    }
    return envelope;
  }

  issueSession(): Promise<Envelope<SessionData>> {
    return this.call<SessionData>("POST", "/v1/session", undefined, undefined, false);
  }

  submit(request: SubmitRequest): Promise<Envelope<SubmitData>> {
    return this.call<SubmitData>("POST", "/v1/submit", undefined, request);
  }

  receipt(txHash: string): Promise<Envelope<ReceiptData>> {
    return this.call<ReceiptData>("GET", "/v1/receipt", { tx_hash: txHash });
  }

  chain(): Promise<Envelope<ChainData>> {
    return this.call<ChainData>("GET", "/v1/chain");
  }

  tasks(cursor?: string, limit?: number): Promise<Envelope<PageData>> {
    return this.call<PageData>("GET", "/v1/tasks", { cursor, limit });
  }

  reviews(cursor?: string, limit?: number): Promise<Envelope<PageData>> {
    return this.call<PageData>("GET", "/v1/reviews", { cursor, limit });
  }

  receipts(cursor?: string, limit?: number): Promise<Envelope<PageData>> {
    return this.call<PageData>("GET", "/v1/receipts", { cursor, limit });
  }

  events(cursor?: string, limit?: number): Promise<Envelope<PageData>> {
    return this.call<PageData>("GET", "/v1/events", { cursor, limit });
  }
}
