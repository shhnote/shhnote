import { toBase64Url } from "../crypto/bytes.ts";
import type { Payload } from "../crypto/container.ts";
import type { PaddingPolicy } from "../crypto/padding.ts";
import { iterateStream } from "../crypto/stream.ts";

// Without an instance limit to go by, the largest blob any instance can serve
// (SHH_EXTERNAL_MAX_OBJECT's ceiling, SPEC §7.1).
export const DEFAULT_MAX_BLOB_BYTES = 4 * 1024 * 1024 * 1024;

// A sibling instance of the same operator (SPEC §9).
export interface Region {
  code: string;
  name: string;
  url: string;
}

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
  regions: Region[];
  server_version: string;
  web_mode: "full" | "api";
}

export type Lifetime = "single_view" | "ttl";

// The reveal answer with its headers read and the blob still to come: a single-view secret
// is claimed the moment the headers arrive, so the token is known before any byte of body.
// A TTL secret comes with no claim token and nothing else (SPEC §5.2).
export interface Revealed {
  body: AsyncIterable<Uint8Array>;
  // The bytes the server says it will send, when it says so.
  contentLength: number | null;
  claimToken: string | null;
}

// Thrown for anything other than a successful response. `status` 0 means the request never
// got a complete answer: `network` for no answer or a body cut short, `too_large` for a body
// over the cap. `claimToken` is set by the client library when the failure came after a
// single-view secret was claimed. `payload` is set when only the confirm failed: the secret
// was decrypted, and is handed over rather than lost.
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  claimToken?: string;
  payload?: Payload;

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

async function* cappedBody(response: Response, maxBytes: number): AsyncGenerator<Uint8Array> {
  // A fetch double may answer without a stream; the real one always has it.
  const source = response.body ? iterateStream(response.body) : [new Uint8Array(await response.arrayBuffer())];
  let seen = 0;
  try {
    for await (const piece of source) {
      seen += piece.length;
      if (seen > maxBytes) throw new ApiError(0, "too_large");
      yield piece;
    }
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, "network");
  }
}

// Talks to one instance's API (SPEC §4). Identifiers travel only in request bodies.
export class Api {
  private readonly base: string;
  private readonly fetchImpl: Fetch;

  constructor(base: string, fetchImpl?: Fetch) {
    this.base = base.replace(/\/+$/, "");
    this.fetchImpl = fetchImpl ?? ((input, init) => fetch(input, init));
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

  // `maxBytes` caps the body: what the server announces and what it actually sends must
  // both stay within it, so a misbehaving server cannot make the client buffer without end.
  async reveal(lookup: Uint8Array, claimToken?: string | null, maxBytes = DEFAULT_MAX_BLOB_BYTES): Promise<Revealed> {
    const body: Record<string, string> = { lookup: toBase64Url(lookup) };
    if (claimToken) body["claim_token"] = claimToken;
    const response = await send(this.fetchImpl, `${this.base}/secrets/reveal`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const length = response.headers.get("content-length");
    const contentLength = length === null ? null : Number(length);
    if (contentLength !== null && contentLength > maxBytes) throw new ApiError(0, "too_large");
    return {
      body: cappedBody(response, Math.min(maxBytes, contentLength ?? maxBytes)),
      contentLength,
      claimToken: response.headers.get("x-shh-claim-token"),
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

// `GET /config`, fetched once per API base and fetch implementation and shared by every
// caller on the page (or in the process). A failed fetch is not kept, so the next call tries
// again. The cache is keyed by the fetch implementation too, so a test double or a proxying
// fetch never sees another one's answer.
const defaultConfigs = new Map<string, Promise<InstanceConfig>>();
const customConfigs = new WeakMap<Fetch, Map<string, Promise<InstanceConfig>>>();

export function getConfig(apiBase: string, fetchImpl?: Fetch): Promise<InstanceConfig> {
  const base = apiBase.replace(/\/+$/, "");
  let cache = defaultConfigs;
  if (fetchImpl) {
    cache = customConfigs.get(fetchImpl) ?? new Map();
    customConfigs.set(fetchImpl, cache);
  }
  let pending = cache.get(base);
  if (!pending) {
    const fetched = new Api(base, fetchImpl).config();
    fetched.catch(() => {
      if (cache.get(base) === fetched) cache.delete(base);
    });
    cache.set(base, fetched);
    pending = fetched;
  }
  return pending;
}
