import { toBase64Url } from "../crypto/bytes.ts";
import type { Payload } from "../crypto/container.ts";
import type { PaddingPolicy } from "../crypto/padding.ts";
import { iterateStream } from "../crypto/stream.ts";

// The largest blob any instance can serve (SHH_EXTERNAL_MAX_OBJECT's ceiling, SPEC §7.1):
// only the cap when the instance's own `max_blob_bytes` cannot be had. `revealSecret` and
// `wireReveal` use that instead.
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
// over the cap, `invalid_config` for a `/config` whose shape or ranges cannot be trusted.
// `claimToken` is set by the client library when the failure came after a
// single-view secret was claimed. `payload` is set when only the confirm failed: the secret
// was decrypted, and is handed over rather than lost.
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  claimToken?: string;
  payload?: Payload;

  constructor(status: number, code: string, detail?: string) {
    super(detail ? `${status} ${code}: ${detail}` : `${status} ${code}`);
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
    let raw: unknown;
    try {
      raw = await response.json();
    } catch {
      throw new ApiError(0, "invalid_config");
    }
    return validateConfig(raw);
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
    // A length that is not a plain non-negative integer is treated as not announced, so the
    // as-received cap still applies (a comparison with NaN would let everything through).
    const length = Number(response.headers.get("content-length") ?? NaN);
    const contentLength = Number.isSafeInteger(length) && length >= 0 ? length : null;
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

// `/config` as the instance sent it is the one input the client takes on trust and uses as a
// bound (the body cap, the padding policy, the lifetimes), so every field is checked for its
// shape and range first; a wrong one fails closed as `invalid_config`, never as "no limit".
function validateConfig(raw: unknown): InstanceConfig {
  const bad = (what: string) => new ApiError(0, "invalid_config", `/config: ${what}`);
  if (typeof raw !== "object" || raw === null) throw bad("not an object");
  const c = raw as Record<string, unknown>;
  const count = (key: string, min = 0): number => {
    const v = c[key];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) throw bad(`${key} is not a whole number of at least ${min}`);
    return v;
  };
  const text = (key: string): string => {
    const v = c[key];
    if (typeof v !== "string") throw bad(`${key} is not a string`);
    return v;
  };
  const padding = c["padding"] as Record<string, unknown> | null | undefined;
  if (typeof padding !== "object" || padding === null) throw bad("padding is not an object");
  let policy: PaddingPolicy;
  if (padding["mode"] === "padme") {
    const min = padding["min"];
    if (typeof min !== "number" || !Number.isSafeInteger(min) || min < 1) throw bad("padding.min");
    policy = { mode: "padme", min };
  } else if (padding["mode"] === "buckets") {
    const ladder = padding["ladder"];
    if (!Array.isArray(ladder) || ladder.length === 0 || !ladder.every((b) => typeof b === "number" && Number.isSafeInteger(b) && b > 0)) {
      throw bad("padding.ladder");
    }
    policy = { mode: "buckets", ladder: [...(ladder as number[])] };
  } else {
    throw bad("padding.mode");
  }
  const presets = c["ttl_presets"];
  if (!Array.isArray(presets) || !presets.every((p) => typeof p === "number" && Number.isSafeInteger(p) && p > 0)) throw bad("ttl_presets");
  if (typeof c["files_enabled"] !== "boolean") throw bad("files_enabled");
  const regions = c["regions"] ?? [];
  if (!Array.isArray(regions) || !regions.every((r) => typeof r === "object" && r !== null && ["code", "name", "url"].every((k) => typeof (r as Record<string, unknown>)[k] === "string"))) {
    throw bad("regions");
  }
  const webMode = c["web_mode"];
  if (webMode !== "full" && webMode !== "api") throw bad("web_mode");
  return {
    fragment_version: count("fragment_version"),
    padding: policy,
    inline_max: count("inline_max"),
    // Never above what any instance can store (SPEC §7.1), whatever the instance claims.
    max_blob_bytes: Math.min(count("max_blob_bytes", 1), DEFAULT_MAX_BLOB_BYTES),
    claim_window_secs: count("claim_window_secs"),
    min_ttl_secs: count("min_ttl_secs"),
    max_ttl_secs: count("max_ttl_secs"),
    default_ttl_secs: count("default_ttl_secs"),
    ttl_presets: [...(presets as number[])],
    text_max_bytes: count("text_max_bytes"),
    files_enabled: c["files_enabled"] as boolean,
    regions: (regions as Region[]).map((r) => ({ code: r.code, name: r.name, url: r.url })),
    server_version: text("server_version"),
    web_mode: webMode,
  };
}

// `GET /config`, fetched once per API base and fetch implementation and shared by every
// caller on the page (or in the process). A failed fetch is not kept, so the next call tries
// again. The cache is keyed by the fetch implementation too, so a test double or a proxying
// fetch never sees another one's answer. `invalidateConfig` drops an answer the instance has
// since contradicted (a padding policy that changed, a limit that moved).
const defaultConfigs = new Map<string, Promise<InstanceConfig>>();
const customConfigs = new WeakMap<Fetch, Map<string, Promise<InstanceConfig>>>();

function configCache(fetchImpl?: Fetch): Map<string, Promise<InstanceConfig>> {
  if (!fetchImpl) return defaultConfigs;
  const cache = customConfigs.get(fetchImpl) ?? new Map();
  customConfigs.set(fetchImpl, cache);
  return cache;
}

export function invalidateConfig(apiBase: string, fetchImpl?: Fetch): void {
  configCache(fetchImpl).delete(apiBase.replace(/\/+$/, ""));
}

export function getConfig(apiBase: string, fetchImpl?: Fetch): Promise<InstanceConfig> {
  const base = apiBase.replace(/\/+$/, "");
  const cache = configCache(fetchImpl);
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
