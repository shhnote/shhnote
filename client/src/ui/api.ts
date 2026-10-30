import { toBase64Url } from "../crypto/bytes.ts";
import type { PaddingPolicy } from "../crypto/padding.ts";

export interface InstanceConfig {
  fragment_version: number;
  padding: PaddingPolicy;
  inline_max: number;
  max_blob_bytes: number;
  claim_window_secs: number;
  min_ttl_secs: number;
  max_ttl_secs: number;
  default_ttl_secs: number;
  ttl_presets: number[];
  text_max_bytes: number;
  files_enabled: boolean;
}

export type Lifetime = "single_view" | "ttl";

export interface Revealed {
  blob: Uint8Array<ArrayBuffer>;
  claimToken: string | null;
  expiresInHours: number | null;
}

// Thrown for anything other than a successful response. `status` 0 means the request never
// got an answer (offline, blocked, aborted).
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(`${status} ${code}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function errorFor(response: Response): Promise<ApiError> {
  let code = "error";
  try {
    const body = (await response.json()) as { error?: { code?: string } };
    code = body.error?.code ?? code;
  } catch {
    /* not JSON */
  }
  return new ApiError(response.status, code);
}

// Anything with fetch's shape: the browser's own, Node's, or a test double.
export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

async function send(fetchImpl: Fetch, input: string, init: RequestInit): Promise<Response> {
  let response: Response;
  try {
    response = await fetchImpl(input, { ...init, credentials: "omit", cache: "no-store" });
  } catch {
    throw new ApiError(0, "network");
  }
  if (!response.ok) throw await errorFor(response);
  return response;
}

// Talks to one instance's API (SPEC §4). Identifiers travel only in request bodies.
export class Api {
  private readonly base: string;
  private readonly fetchImpl: Fetch;

  constructor(base: string, fetchImpl?: Fetch) {
    this.base = base.replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? ((input, init) => fetch(input, init));
  }

  static fromPage(): Api {
    const base = document.body.dataset["api"];
    if (!base) throw new Error("page has no data-api attribute");
    return new Api(base);
  }

  async config(): Promise<InstanceConfig> {
    const response = await send(this.fetchImpl, `${this.base}/config`, { method: "GET" });
    return (await response.json()) as InstanceConfig;
  }

  async create(meta: { lookupKey: Uint8Array; burnKey: Uint8Array; lifetime: Lifetime; ttlSeconds: number }, blob: Uint8Array): Promise<void> {
    const form = new FormData();
    const json = JSON.stringify({
      lookup_key: toBase64Url(meta.lookupKey),
      burn_key: toBase64Url(meta.burnKey),
      lifetime: meta.lifetime,
      ttl_seconds: meta.ttlSeconds,
    });
    // `meta` must come first; the server validates it before reading the blob.
    form.append("meta", new Blob([json], { type: "application/json" }));
    form.append("blob", new Blob([blob as BlobPart], { type: "application/octet-stream" }), "blob");
    await send(this.fetchImpl, `${this.base}/secrets`, { method: "POST", body: form });
  }

  async reveal(lookup: Uint8Array, claimToken?: string): Promise<Revealed> {
    const body: Record<string, string> = { lookup: toBase64Url(lookup) };
    if (claimToken) body["claim_token"] = claimToken;
    const response = await send(this.fetchImpl, `${this.base}/secrets/reveal`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const hours = response.headers.get("x-shh-expires-in-hours");
    return {
      blob: new Uint8Array(await response.arrayBuffer()),
      claimToken: response.headers.get("x-shh-claim-token"),
      expiresInHours: hours === null ? null : Number(hours),
    };
  }

  async confirm(lookup: Uint8Array, claimToken: string): Promise<void> {
    await send(this.fetchImpl, `${this.base}/secrets/confirm`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lookup: toBase64Url(lookup), claim_token: claimToken }),
    });
  }

  async report(lookup: Uint8Array): Promise<void> {
    await send(this.fetchImpl, `${this.base}/reports`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lookup: toBase64Url(lookup) }),
    });
  }

  async burn(burnToken: Uint8Array): Promise<void> {
    await send(this.fetchImpl, `${this.base}/secrets/burn`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ burn_token: toBase64Url(burnToken) }),
    });
  }
}
