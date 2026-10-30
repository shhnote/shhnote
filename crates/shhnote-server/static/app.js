// src/crypto/bytes.ts
function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
function u32be(value) {
  if (!Number.isInteger(value) || value < 0 || value > 4294967295) {
    throw new RangeError(`not a u32: ${value}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}
function readU32be(bytes, at) {
  if (at + 4 > bytes.length) throw new RangeError("read past end");
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at, false);
}
function own(bytes) {
  return new Uint8Array(bytes);
}
var B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i]));
function toBase64Url(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = a << 16 | b << 8 | c;
    out += B64URL[triple >> 18 & 63] + B64URL[triple >> 12 & 63];
    out += i + 1 < bytes.length ? B64URL[triple >> 6 & 63] : "";
    out += i + 2 < bytes.length ? B64URL[triple & 63] : "";
  }
  return out;
}
function fromBase64Url(text) {
  if (text.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor(text.length * 3 / 4));
  let bits = 0;
  let buffer = 0;
  let at = 0;
  for (const ch of text) {
    const value = B64URL_INDEX.get(ch);
    if (value === void 0) return null;
    buffer = buffer << 6 | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = buffer >> bits & 255;
    }
  }
  if (bits > 0 && (buffer & (1 << bits) - 1) !== 0) return null;
  return out;
}

// src/crypto/error.ts
var ShhError = class extends Error {
  code;
  constructor(code, message) {
    super(message ?? code);
    this.name = "ShhError";
    this.code = code;
  }
};

// src/crypto/fragment.ts
var VERSION = 1;
var FRAGMENT_CHARS = 44;
function encodeFragment(bytes) {
  if (bytes.length !== 32) throw new RangeError("fragment material must be 32 bytes");
  return toBase64Url(concat(new Uint8Array([VERSION]), bytes));
}
function decodeFragment(text) {
  const body = text.startsWith("#") ? text.slice(1) : text;
  if (body.length !== FRAGMENT_CHARS) throw new ShhError("invalid_fragment");
  const raw = fromBase64Url(body);
  if (raw === null || raw.length !== 33) throw new ShhError("invalid_fragment");
  if (raw[0] !== VERSION) throw new ShhError("unsupported_version", `version ${raw[0]}`);
  return raw.slice(1);
}

// src/ui/api.ts
var ApiError = class extends Error {
  status;
  code;
  constructor(status, code) {
    super(`${status} ${code}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
};
async function errorFor(response) {
  let code = "error";
  try {
    const body = await response.json();
    code = body.error?.code ?? code;
  } catch {
  }
  return new ApiError(response.status, code);
}
async function send(input, init) {
  let response;
  try {
    response = await fetch(input, { ...init, credentials: "omit", cache: "no-store" });
  } catch {
    throw new ApiError(0, "network");
  }
  if (!response.ok) throw await errorFor(response);
  return response;
}
var Api = class _Api {
  constructor(base) {
    this.base = base;
  }
  base;
  static fromPage() {
    const base = document.body.dataset["api"];
    if (!base) throw new Error("page has no data-api attribute");
    return new _Api(base);
  }
  async config() {
    const response = await send(`${this.base}/config`, { method: "GET" });
    return await response.json();
  }
  async create(meta, blob) {
    const form = new FormData();
    const json = JSON.stringify({
      lookup_key: toBase64Url(meta.lookupKey),
      burn_key: toBase64Url(meta.burnKey),
      lifetime: meta.lifetime,
      ttl_seconds: meta.ttlSeconds
    });
    form.append("meta", new Blob([json], { type: "application/json" }));
    form.append("blob", new Blob([blob], { type: "application/octet-stream" }), "blob");
    await send(`${this.base}/secrets`, { method: "POST", body: form });
  }
  async reveal(lookup2, claimToken) {
    const body = { lookup: toBase64Url(lookup2) };
    if (claimToken) body["claim_token"] = claimToken;
    const response = await send(`${this.base}/secrets/reveal`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    const hours = response.headers.get("x-shh-expires-in-hours");
    return {
      blob: new Uint8Array(await response.arrayBuffer()),
      claimToken: response.headers.get("x-shh-claim-token"),
      expiresInHours: hours === null ? null : Number(hours)
    };
  }
  async confirm(lookup2, claimToken) {
    await send(`${this.base}/secrets/confirm`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lookup: toBase64Url(lookup2), claim_token: claimToken })
    });
  }
  async report(lookup2) {
    await send(`${this.base}/reports`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lookup: toBase64Url(lookup2) })
    });
  }
  async burn(burnToken) {
    await send(`${this.base}/secrets/burn`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ burn_token: toBase64Url(burnToken) })
    });
  }
};

// src/ui/dom.ts
function $(selector, root = document) {
  const el = root.querySelector(selector);
  if (!el) throw new Error(`missing element: ${selector}`);
  return el;
}
function $$(selector, root = document) {
  return [...root.querySelectorAll(selector)];
}
function show(el) {
  el.hidden = false;
}
function hide(el) {
  el.hidden = true;
}
function setState(root, state) {
  for (const section of $$("[data-state]", root)) {
    section.hidden = section.dataset["state"] !== state;
  }
}
function setStatus(el, text) {
  el.textContent = text;
}
function wireCopy(button, getText, copiedLabel) {
  const original = button.textContent ?? "";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      button.textContent = copiedLabel;
      setTimeout(() => button.textContent = original, 1500);
    } catch {
    }
  });
}
function formatSize(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const number = new Intl.NumberFormat(document.documentElement.lang || "en", {
    maximumFractionDigits: unit === 0 ? 0 : 1
  }).format(size);
  return `${number} ${units[unit]}`;
}

// src/ui/i18n.ts
var strings = null;
function t(key, vars = {}) {
  if (strings === null) {
    const block = document.querySelector("script[data-i18n]");
    try {
      strings = block ? JSON.parse(block.textContent ?? "{}") : {};
    } catch {
      strings = {};
    }
  }
  let text = strings[key] ?? key;
  for (const [name, value] of Object.entries(vars)) {
    text = text.replaceAll(`{${name}}`, String(value));
  }
  return text;
}

// src/ui/burn.ts
function wireBurn(page) {
  const api = Api.fromPage();
  const form = $("[data-burn-form]", page);
  const status = $("[data-form-status]", form);
  let token;
  try {
    token = decodeFragment(location.hash);
  } catch {
    setState(page, "notfound");
    return;
  }
  show(form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    const button = $("button", form);
    button.disabled = true;
    setStatus(status, t("burn-working"));
    try {
      await api.burn(token);
      history.replaceState(null, "", location.pathname);
      setState(page, "done");
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        history.replaceState(null, "", location.pathname);
        setState(page, "notfound");
      } else {
        setStatus(status, t("reveal-error-network"));
        button.disabled = false;
      }
    }
  });
}

// src/ui/chrome.ts
function wireMenus() {
  const menus = $$("details[data-menu]");
  document.addEventListener("click", (event) => {
    for (const menu of menus) {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    for (const menu of menus) {
      if (menu.open) {
        menu.open = false;
        menu.querySelector("summary")?.focus();
      }
    }
  });
  for (const menu of menus) {
    menu.addEventListener("focusout", (event) => {
      if (!menu.contains(event.relatedTarget)) menu.open = false;
    });
  }
}
var THEMES = /* @__PURE__ */ new Set(["light", "dark", "light-hc", "dark-hc"]);
var THEME_KEY = "shhnote-theme";
function wireTheme() {
  const apply = (choice) => {
    if (THEMES.has(choice)) document.documentElement.dataset["theme"] = choice;
    else delete document.documentElement.dataset["theme"];
    for (const button of $$("[data-theme-choice]")) {
      button.setAttribute("aria-checked", String((button.dataset["themeChoice"] ?? "auto") === choice));
    }
  };
  let stored = "auto";
  try {
    stored = localStorage.getItem(THEME_KEY) ?? "auto";
  } catch {
  }
  apply(stored);
  for (const button of $$("[data-theme-choice]")) {
    button.addEventListener("click", () => {
      const choice = button.dataset["themeChoice"] ?? "auto";
      apply(choice);
      try {
        if (choice === "auto") localStorage.removeItem(THEME_KEY);
        else localStorage.setItem(THEME_KEY, choice);
      } catch {
      }
      button.closest("details")?.removeAttribute("open");
    });
  }
}
function wirePasswordToggles() {
  for (const wrapper of $$("[data-pwd-input]")) {
    const input = wrapper.querySelector("input");
    const button = wrapper.querySelector("[data-pwd-toggle]");
    if (!input || !button) continue;
    button.addEventListener("click", () => {
      const shown = input.type === "password";
      input.type = shown ? "text" : "password";
      wrapper.dataset["shown"] = String(shown);
      button.setAttribute("aria-pressed", String(shown));
      input.focus();
    });
  }
}

// src/crypto/kdf.ts
var encoder = new TextEncoder();
var INFO = {
  lookup: encoder.encode("shhnote/lookup/v1"),
  kekDirect: encoder.encode("shhnote/kek-direct/v1"),
  kekPass: encoder.encode("shhnote/kek-pass/v1")
};
var SALT_LEN = 16;
var ARGON2_DEFAULT = { m: 64 * 1024, t: 3, p: 1 };
var ARGON2_MIN = { m: 8 * 1024, t: 1, p: 1 };
var ARGON2_MAX = { m: 256 * 1024, t: 8, p: 4 };
function checkArgon2Bounds(params) {
  const within = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  if (!within(params.m, ARGON2_MIN.m, ARGON2_MAX.m) || !within(params.t, ARGON2_MIN.t, ARGON2_MAX.t) || !within(params.p, ARGON2_MIN.p, ARGON2_MAX.p)) {
    throw new ShhError("argon2_out_of_bounds");
  }
  return params;
}
var subtle = globalThis.crypto.subtle;
async function hkdfBase(ikm) {
  return subtle.importKey("raw", own(ikm), "HKDF", false, ["deriveBits", "deriveKey"]);
}
function hkdfAlgorithm(info) {
  return { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: own(info) };
}
async function hkdfBits(ikm, info) {
  const key = await hkdfBase(ikm);
  return new Uint8Array(await subtle.deriveBits(hkdfAlgorithm(info), key, 256));
}
async function hkdfAesKey(ikm, info, usages) {
  const key = await hkdfBase(ikm);
  return subtle.deriveKey(hkdfAlgorithm(info), key, { name: "AES-GCM", length: 256 }, false, usages);
}
async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", own(bytes)));
}

// src/crypto/padding.ts
var CHUNK_SIZE = 65536;
var TAG_LEN = 16;
var HEADER_LEN = 95;
var LENGTH_PREFIX = 4;
var DEFAULT_PADDING_MIN = 64 * 1024;
function padme(len) {
  if (len < 2) return len;
  const L = BigInt(len);
  const e = BigInt(L.toString(2).length - 1);
  const s = BigInt(e.toString(2).length);
  const mask = (1n << e - s) - 1n;
  return Number(L + mask & ~mask);
}
function paddedSize(len, policy) {
  if (policy.mode === "padme") return padme(Math.max(len, policy.min));
  return policy.ladder.find((b) => b >= len) ?? null;
}
function chunkCount(bucket) {
  return Math.max(1, Math.ceil(bucket / CHUNK_SIZE));
}
function blobLen(bucket) {
  return HEADER_LEN + bucket + TAG_LEN * chunkCount(bucket);
}
function pad(payload, policy) {
  if (payload.length > 4294967295) throw new ShhError("payload_too_large");
  const bucket = paddedSize(payload.length + LENGTH_PREFIX, policy);
  if (bucket === null) throw new ShhError("payload_too_large");
  const padded = new Uint8Array(bucket);
  padded.set(concat(u32be(payload.length), payload));
  return padded;
}
function unpad(padded) {
  if (padded.length < LENGTH_PREFIX) throw new ShhError("corrupt", "padding too short");
  const len = readU32be(padded, 0);
  if (len > padded.length - LENGTH_PREFIX) throw new ShhError("corrupt", "length prefix exceeds the bucket");
  return padded.subarray(LENGTH_PREFIX, LENGTH_PREFIX + len);
}

// src/crypto/blob.ts
var WRAP_IV_LEN = 12;
var WRAPPED_EK_LEN = 48;
var NONCE_PREFIX_LEN = 7;
function serializeHeader(h) {
  if (h.salt.length !== SALT_LEN || h.wrapIv.length !== WRAP_IV_LEN || h.wrappedEk.length !== WRAPPED_EK_LEN || h.noncePrefix.length !== NONCE_PREFIX_LEN) {
    throw new RangeError("header field has the wrong length");
  }
  const out = concat(h.salt, u32be(h.argon.m), u32be(h.argon.t), u32be(h.argon.p), h.wrapIv, h.wrappedEk, h.noncePrefix);
  if (out.length !== HEADER_LEN) throw new RangeError("header is not 95 bytes");
  return out;
}
function parseHeader(blob) {
  if (blob.length < HEADER_LEN) throw new ShhError("invalid_blob_length");
  const argon = checkArgon2Bounds({ m: readU32be(blob, 16), t: readU32be(blob, 20), p: readU32be(blob, 24) });
  return {
    salt: blob.slice(0, 16),
    argon,
    wrapIv: blob.slice(28, 40),
    wrappedEk: blob.slice(40, 88),
    noncePrefix: blob.slice(88, 95)
  };
}

// src/crypto/chunks.ts
var subtle2 = globalThis.crypto.subtle;
function nonce(prefix, index, last) {
  const out = new Uint8Array(12);
  out.set(prefix, 0);
  out.set(u32be(index), 7);
  out[11] = last ? 1 : 0;
  return out;
}
async function sealChunk(ek, prefix, index, last, chunk) {
  return new Uint8Array(await subtle2.encrypt({ name: "AES-GCM", iv: nonce(prefix, index, last), tagLength: 128 }, ek, own(chunk)));
}
async function openChunk(ek, prefix, index, last, sealed) {
  try {
    return new Uint8Array(await subtle2.decrypt({ name: "AES-GCM", iv: nonce(prefix, index, last), tagLength: 128 }, ek, own(sealed)));
  } catch {
    throw new ShhError("corrupt", `chunk ${index} failed to authenticate`);
  }
}
async function sealAll(ek, prefix, padded) {
  const count = Math.max(1, Math.ceil(padded.length / CHUNK_SIZE));
  const out = new Uint8Array(padded.length + count * TAG_LEN);
  let at = 0;
  for (let i = 0; i < count; i++) {
    const chunk = padded.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
    const sealed = await sealChunk(ek, prefix, i, i === count - 1, chunk);
    out.set(sealed, at);
    at += sealed.length;
  }
  return out;
}
async function openAll(ek, prefix, body) {
  const sealedLen = CHUNK_SIZE + TAG_LEN;
  const count = Math.ceil(body.length / sealedLen);
  if (count === 0 || body.length < count * TAG_LEN) throw new ShhError("invalid_blob_length");
  const out = new Uint8Array(body.length - count * TAG_LEN);
  let at = 0;
  for (let i = 0; i < count; i++) {
    const sealed = body.subarray(i * sealedLen, (i + 1) * sealedLen);
    const chunk = await openChunk(ek, prefix, i, i === count - 1, sealed);
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

// src/crypto/container.ts
var MANIFEST_VERSION = 1;
var MAX_MANIFEST_LEN = 1024 * 1024;
var encoder2 = new TextEncoder();
var decoder = new TextDecoder("utf-8", { fatal: true });
function manifestJson(payload) {
  const manifest = {
    v: MANIFEST_VERSION,
    text: payload.text,
    files: payload.files.map((f) => ({ name: f.name, type: f.type, size: f.bytes.length }))
  };
  return JSON.stringify(manifest);
}
function encodePayload(payload) {
  if (payload.text === null && payload.files.length === 0) throw new ShhError("empty_payload");
  const manifest = encoder2.encode(manifestJson(payload));
  if (manifest.length > MAX_MANIFEST_LEN) throw new ShhError("payload_too_large");
  return concat(u32be(manifest.length), manifest, ...payload.files.map((f) => f.bytes));
}
function decodePayload(bytes) {
  if (bytes.length < 4) throw new ShhError("corrupt", "payload too short");
  const manifestLen = readU32be(bytes, 0);
  if (manifestLen > MAX_MANIFEST_LEN) throw new ShhError("corrupt", "manifest too large");
  if (4 + manifestLen > bytes.length) throw new ShhError("corrupt", "manifest length exceeds payload");
  let manifest;
  try {
    manifest = JSON.parse(decoder.decode(bytes.subarray(4, 4 + manifestLen)));
  } catch (e) {
    throw new ShhError("manifest", String(e));
  }
  if (typeof manifest !== "object" || manifest === null || manifest.v !== MANIFEST_VERSION || !(manifest.text === null || typeof manifest.text === "string") || !Array.isArray(manifest.files)) {
    throw new ShhError("manifest", "unexpected manifest shape");
  }
  if (manifest.text === null && manifest.files.length === 0) throw new ShhError("empty_payload");
  let at = 4 + manifestLen;
  const files = [];
  for (const meta of manifest.files) {
    if (typeof meta.name !== "string" || typeof meta.type !== "string" || !Number.isInteger(meta.size) || meta.size < 0) {
      throw new ShhError("manifest", "bad file entry");
    }
    if (at + meta.size > bytes.length) throw new ShhError("corrupt", "file sizes exceed payload");
    files.push({ name: meta.name, type: meta.type, bytes: bytes.slice(at, at + meta.size) });
    at += meta.size;
  }
  if (at !== bytes.length) throw new ShhError("corrupt", "trailing bytes after the last file");
  return { text: manifest.text, files };
}

// src/crypto/secret.ts
var subtle3 = globalThis.crypto.subtle;
function random(len) {
  return globalThis.crypto.getRandomValues(new Uint8Array(len));
}
async function generateRandomness() {
  return {
    seed: random(32),
    burnToken: random(32),
    ek: await subtle3.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]),
    salt: random(SALT_LEN),
    wrapIv: random(WRAP_IV_LEN),
    noncePrefix: random(NONCE_PREFIX_LEN)
  };
}
function lookup(seed) {
  return hkdfBits(seed, INFO.lookup);
}
var credentialHash = sha256;
function kekDirect(seed, usages) {
  return hkdfAesKey(seed, INFO.kekDirect, usages);
}
function kekPass(seed, passphrase, salt, argon, argon2, usages) {
  const passKey = argon2.hash(passphrase, salt, argon);
  const ikm = concat(seed, passKey);
  passKey.fill(0);
  return hkdfAesKey(ikm, INFO.kekPass, usages).finally(() => ikm.fill(0));
}
async function encrypt(opts) {
  const { randomness: r } = opts;
  const argon = checkArgon2Bounds(opts.argon ?? ARGON2_DEFAULT);
  let kek;
  if (opts.passphrase) {
    if (!opts.argon2) throw new ShhError("argon2_unavailable", "a passphrase needs the Argon2 module");
    kek = await kekPass(r.seed, opts.passphrase, r.salt, argon, opts.argon2, ["wrapKey"]);
  } else {
    kek = await kekDirect(r.seed, ["wrapKey"]);
  }
  const header = {
    salt: r.salt,
    // In direct mode these are filler; the layout stays identical to a passphrase blob.
    argon,
    wrapIv: r.wrapIv,
    wrappedEk: new Uint8Array(await subtle3.wrapKey("raw", r.ek, kek, { name: "AES-GCM", iv: own(r.wrapIv) })),
    noncePrefix: r.noncePrefix
  };
  const padded = pad(encodePayload(opts.payload), opts.policy);
  const body = await sealAll(r.ek, r.noncePrefix, padded);
  padded.fill(0);
  const blob = concat(serializeHeader(header), body);
  if (blob.length !== blobLen(padded.length)) throw new Error("blob length mismatch");
  return {
    blob,
    bucket: padded.length,
    fragment: encodeFragment(r.seed),
    burnFragment: encodeFragment(r.burnToken),
    lookupKey: await credentialHash(await lookup(r.seed)),
    burnKey: await credentialHash(r.burnToken)
  };
}
async function unwrap(kek, header) {
  try {
    return await subtle3.unwrapKey("raw", own(header.wrappedEk), kek, { name: "AES-GCM", iv: own(header.wrapIv) }, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  } catch {
    return null;
  }
}
async function decrypt(blob, seed, passphrase, argon2) {
  const header = parseHeader(blob);
  let ek = await unwrap(await kekDirect(seed, ["unwrapKey"]), header);
  if (ek === null) {
    if (!passphrase) throw new ShhError("passphrase_required");
    if (!argon2) throw new ShhError("argon2_unavailable", "a passphrase needs the Argon2 module");
    ek = await unwrap(await kekPass(seed, passphrase, header.salt, header.argon, argon2, ["unwrapKey"]), header);
    if (ek === null) throw new ShhError("wrong_passphrase");
  }
  const padded = await openAll(ek, header.noncePrefix, blob.subarray(HEADER_LEN));
  try {
    return decodePayload(unpad(padded));
  } finally {
    padded.fill(0);
  }
}

// src/crypto/argon2.ts
var encoder3 = new TextEncoder();
var Argon2 = class _Argon2 {
  wasm;
  constructor(wasm) {
    this.wasm = wasm;
  }
  static async load(source) {
    const module = source instanceof WebAssembly.Module ? source : await WebAssembly.compile(source);
    const instance = await WebAssembly.instantiate(module, {});
    return new _Argon2(instance.exports);
  }
  // For the browser: `Argon2.fromResponse(fetch("/static/argon2.wasm"))`.
  static async fromResponse(response) {
    const module = await WebAssembly.compileStreaming(response);
    return _Argon2.load(module);
  }
  hash(passphrase, salt, params) {
    checkArgon2Bounds(params);
    const pwd = encoder3.encode(passphrase);
    const pwdPtr = this.wasm.shh_alloc(pwd.length);
    const saltPtr = this.wasm.shh_alloc(salt.length);
    const outPtr = this.wasm.shh_alloc(32);
    try {
      new Uint8Array(this.wasm.memory.buffer).set(pwd, pwdPtr);
      new Uint8Array(this.wasm.memory.buffer).set(salt, saltPtr);
      const status = this.wasm.shh_argon2id(pwdPtr, pwd.length, saltPtr, salt.length, params.m, params.t, params.p, outPtr);
      if (status === 1) throw new ShhError("argon2_out_of_bounds");
      if (status !== 0) throw new ShhError("argon2_unavailable", `argon2 failed with status ${status}`);
      return new Uint8Array(this.wasm.memory.buffer.slice(outPtr, outPtr + 32));
    } finally {
      const view = new Uint8Array(this.wasm.memory.buffer);
      view.fill(0, pwdPtr, pwdPtr + pwd.length);
      view.fill(0, outPtr, outPtr + 32);
      this.wasm.shh_free(pwdPtr, pwd.length);
      this.wasm.shh_free(saltPtr, salt.length);
      this.wasm.shh_free(outPtr, 32);
    }
  }
};

// src/ui/argon2-loader.ts
var loading = null;
function loadArgon2() {
  const version = document.body.dataset["assetVersion"] ?? "";
  loading ??= Argon2.fromResponse(fetch(`/static/argon2.wasm?v=${version}`, { cache: "force-cache" })).catch((e) => {
    loading = null;
    throw e;
  });
  return loading;
}

// src/ui/create.ts
function wireCreate(form, dropzone) {
  const api = Api.fromPage();
  const status = $("[data-form-status]", form);
  const submit = $("button[type=submit]", form);
  const result = $("[data-create-result]");
  const wrapper = $("[data-create-wrapper]");
  show(wrapper);
  let filesEnabled = true;
  void api.config().then((config) => {
    filesEnabled = config.files_enabled;
    if (!filesEnabled) {
      dropzone?.reset();
      for (const zone of $$("[data-dropzone]", form)) hide(zone);
    }
  }, () => {
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const text = String(data.get("note") ?? "").replace(/\r\n/g, "\n");
    const passphrase = String(data.get("passphrase") ?? "");
    const lifetime = data.get("burn") ? "single_view" : "ttl";
    const ttlSeconds = Number(data.get("expiry"));
    const files = filesEnabled ? dropzone?.files ?? [] : [];
    if (text.length === 0 && files.length === 0) {
      setStatus(status, t("create-error-empty"));
      return;
    }
    submit.disabled = true;
    try {
      setStatus(status, t("create-encrypting"));
      const [config, randomness, argon2, fileBytes] = await Promise.all([
        api.config(),
        generateRandomness(),
        passphrase ? loadArgon2() : Promise.resolve(void 0),
        Promise.all(files.map(async (f) => ({ name: f.name, type: f.type || "application/octet-stream", bytes: new Uint8Array(await f.arrayBuffer()) })))
      ]);
      const encrypted = await encrypt({
        randomness,
        payload: { text: text.length > 0 ? text : null, files: fileBytes },
        policy: config.padding,
        passphrase: passphrase || null,
        ...argon2 ? { argon2 } : {}
      });
      if (encrypted.blob.length > config.max_blob_bytes) {
        setStatus(status, t("create-error-too-large"));
        return;
      }
      setStatus(status, t("create-uploading"));
      await api.create(
        { lookupKey: encrypted.lookupKey, burnKey: encrypted.burnKey, lifetime, ttlSeconds },
        encrypted.blob
      );
      const expiryLabel = $("select[name=expiry]", form).selectedOptions[0]?.textContent ?? "";
      showResult(api, result, encrypted.fragment, encrypted.burnFragment, {
        hasPassphrase: passphrase.length > 0,
        singleView: lifetime === "single_view",
        expiryLabel
      });
      form.reset();
      dropzone?.reset();
      hide(wrapper);
      setStatus(status, "");
    } catch (e) {
      setStatus(status, messageFor(e));
    } finally {
      submit.disabled = false;
    }
  });
}
function showResult(api, result, fragment, burnFragment, info) {
  const shareLink = `${location.origin}/s#${fragment}`;
  const burnLink = `${location.origin}/burn#${burnFragment}`;
  $("[data-share-link]", result).textContent = shareLink;
  $("[data-burn-link]", result).textContent = burnLink;
  $("[data-open-link]", result).href = shareLink;
  $("[data-chip-lifetime]", result).textContent = t(info.singleView ? "result-chip-single" : "result-chip-multi");
  $("[data-chip-expiry]", result).textContent = t("result-chip-expires", { period: info.expiryLabel });
  if (info.hasPassphrase) show($("[data-passphrase-reminder]", result));
  wireCopy($("[data-copy=share]", result), () => shareLink, t("result-copied"));
  wireCopy($("[data-copy=burn]", result), () => burnLink, t("result-copied"));
  const destroy = $("[data-destroy]", result);
  const status = $("[data-result-status]", result);
  destroy.addEventListener("click", async () => {
    destroy.disabled = true;
    try {
      await api.burn(decodeFragment(burnFragment));
      setStatus(status, t("result-destroyed"));
    } catch (e) {
      setStatus(status, messageFor(e));
      destroy.disabled = false;
    }
  });
  show(result);
  result.scrollIntoView({ block: "start" });
}
function messageFor(e) {
  if (e instanceof ApiError) {
    if (e.status === 0) return t("create-error-network");
    if (e.status === 413) return t("create-error-too-large");
    return t("create-error-failed");
  }
  if (e instanceof ShhError && (e.code === "payload_too_large" || e.code === "empty_payload")) {
    return t(e.code === "empty_payload" ? "create-error-empty" : "create-error-too-large");
  }
  console.error(e);
  return t("create-error-failed");
}

// src/ui/dropzone.ts
var Dropzone = class _Dropzone {
  constructor(zone) {
    this.zone = zone;
    const input = $("input[type=file]", zone);
    this.list = $("[data-file-list]", zone.parentElement ?? document);
    input.addEventListener("change", () => {
      this.add(input.files);
      input.value = "";
    });
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("is-dragging"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("is-dragging");
      this.add(event.dataTransfer?.files ?? null);
    });
  }
  zone;
  files = [];
  list;
  static wireAll() {
    return $$("[data-dropzone]").map((zone) => new _Dropzone(zone));
  }
  add(files) {
    if (files) this.files.push(...files);
    this.render();
  }
  render() {
    this.list.replaceChildren();
    this.files.forEach((file, index) => {
      const item = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = `${file.name} (${formatSize(file.size)})`;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = t("form-files-remove");
      remove.addEventListener("click", () => {
        this.files.splice(index, 1);
        this.render();
      });
      item.append(name, remove);
      this.list.append(item);
    });
  }
  reset() {
    this.files.length = 0;
    this.render();
    this.zone.classList.remove("is-dragging");
  }
};

// src/ui/report.ts
function wireReport(page) {
  const api = Api.fromPage();
  const form = $("[data-report-form]", page);
  const input = $("input[name=link]", form);
  const status = $("[data-form-status]", form);
  if (location.hash.length > 1) {
    input.value = `${location.origin}/s${location.hash}`;
    history.replaceState(null, "", location.pathname);
  }
  show(form);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    let seed;
    try {
      const hash = input.value.trim().split("#")[1] ?? "";
      seed = decodeFragment(`#${hash}`);
    } catch {
      setStatus(status, t("report-error-invalid"));
      return;
    }
    const button = $("button", form);
    button.disabled = true;
    setStatus(status, t("report-working"));
    try {
      await api.report(await lookup(seed));
      input.value = "";
      setState(page, "done");
    } catch {
      setStatus(status, t("reveal-error-network"));
      button.disabled = false;
    }
  });
}

// src/ui/reveal.ts
function wireReveal(page) {
  const api = Api.fromPage();
  const armed = $("[data-reveal-form]", page);
  const armedStatus = $("[data-form-status]", armed);
  const passForm = $("[data-passphrase-form]", page);
  const passInput = $("input[name=passphrase]", passForm);
  const passStatus = $("[data-form-status]", passForm);
  let seed;
  try {
    seed = decodeFragment(location.hash);
  } catch {
    setState(page, "notfound");
    return;
  }
  show(armed);
  let blob = null;
  let claimToken = null;
  let expiresInHours = null;
  armed.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    const button = $("button", armed);
    const working = $("[data-working-status]", page);
    button.disabled = true;
    try {
      setState(page, "working");
      setStatus(working, t("reveal-fetching"));
      const revealed = await api.reveal(await lookup(seed));
      blob = revealed.blob;
      claimToken = revealed.claimToken;
      expiresInHours = revealed.expiresInHours;
      setStatus(working, t("reveal-decrypting"));
      await tryDecrypt(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setState(page, "notfound");
      } else {
        setState(page, "armed");
        setStatus(armedStatus, e instanceof ApiError ? t("reveal-error-network") : t("reveal-error-corrupt"));
        button.disabled = false;
      }
    }
  });
  passForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("button", passForm);
    button.disabled = true;
    try {
      setStatus(passStatus, t("reveal-decrypting"));
      await tryDecrypt(passInput.value);
    } catch (e) {
      console.error(e);
      setStatus(passStatus, t("reveal-error-corrupt"));
    } finally {
      button.disabled = false;
    }
  });
  async function tryDecrypt(passphrase) {
    if (!blob) return;
    try {
      const argon2 = passphrase ? await loadArgon2() : void 0;
      const payload = await decrypt(blob, seed, passphrase, argon2);
      await display(payload);
    } catch (e) {
      if (e instanceof ShhError && e.code === "passphrase_required") {
        setState(page, "passphrase");
        passInput.focus();
        return;
      }
      if (e instanceof ShhError && e.code === "wrong_passphrase") {
        setStatus(passStatus, t("reveal-wrong-passphrase"));
        passInput.select();
        return;
      }
      throw e;
    }
  }
  async function display(payload) {
    blob = null;
    history.replaceState(null, "", location.pathname);
    const revealed = $("[data-state=revealed]", page);
    const lifetime = $("[data-lifetime]", revealed);
    const lifetimeText = $("[data-lifetime-text]", lifetime);
    if (claimToken !== null) {
      lifetimeText.textContent = t("reveal-single-view");
    } else if (expiresInHours !== null) {
      lifetime.classList.remove("badge--danger");
      lifetimeText.textContent = expiresInHours <= 1 ? t("reveal-expires-one") : t("reveal-expires-many", { hours: expiresInHours });
    }
    if (payload.text !== null) {
      const block = $("[data-text-block]", revealed);
      const pre = $("[data-text]", block);
      pre.textContent = payload.text;
      wireCopy($("[data-copy=text]", block), () => payload.text ?? "", t("result-copied"));
      show(block);
    }
    const list = $("[data-files]", revealed);
    for (const file of payload.files) {
      const item = document.createElement("li");
      item.className = "file-card";
      const icon = document.createElement("span");
      icon.className = "file-card__icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = "\u25A3";
      const meta = document.createElement("div");
      meta.className = "file-card__meta";
      const name = document.createElement("div");
      name.className = "file-card__name";
      name.textContent = file.name;
      const sub = document.createElement("div");
      sub.className = "file-card__sub";
      sub.textContent = `${file.type || "application/octet-stream"} \xB7 ${formatSize(file.bytes.length)}`;
      meta.append(name, sub);
      const link = document.createElement("a");
      link.className = "btn btn--ghost btn--sm";
      link.href = URL.createObjectURL(new Blob([file.bytes], { type: file.type || "application/octet-stream" }));
      link.download = file.name.replaceAll(/[/\\]/g, "_") || "file";
      link.textContent = t("reveal-download");
      item.append(icon, meta, link);
      list.append(item);
    }
    setState(page, "revealed");
    if (claimToken !== null) {
      const token = claimToken;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await api.confirm(await lookup(seed), token);
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 1e3 * (attempt + 1)));
        }
      }
    }
  }
}

// src/ui/tabs.ts
function wireTabs() {
  for (const container of $$("[data-tabs]")) {
    const tabList = container.querySelector("[role=tablist]");
    if (!tabList) continue;
    const tabs = $$("[role=tab]", tabList);
    const panels = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls") ?? ""));
    const select = (index, focus) => {
      tabs.forEach((tab, i) => {
        const selected = i === index;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        const panel = panels[i];
        if (panel) panel.hidden = !selected;
      });
      if (focus) tabs[index]?.focus();
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => {
        select(index, false);
        history.replaceState(null, "", `#${panels[index]?.id ?? ""}`);
      });
      tab.addEventListener("keydown", (event) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
        if (step) select((index + step + tabs.length) % tabs.length, true);
      });
    });
    for (const link of $$("[data-tab-link]", container)) {
      link.addEventListener("click", (event) => {
        const index = tabs.findIndex((tab) => tab.id === link.dataset["tabLink"]);
        if (index < 0) return;
        event.preventDefault();
        select(index, true);
        history.replaceState(null, "", `#${panels[index]?.id ?? ""}`);
        container.scrollIntoView({ block: "start" });
      });
    }
    window.addEventListener("hashchange", () => {
      const index = panels.findIndex((panel) => panel && `#${panel.id}` === location.hash);
      if (index >= 0) select(index, false);
    });
    const fromHash = panels.findIndex((panel) => panel && `#${panel.id}` === location.hash);
    select(Math.max(fromHash, 0), false);
    tabList.hidden = false;
    container.classList.add("is-ready");
  }
}

// src/main.ts
wireTheme();
wireMenus();
wirePasswordToggles();
for (const link of $$("a[data-keep-hash]")) {
  link.addEventListener("click", () => {
    if (location.hash) link.hash = location.hash;
  });
}
var dropzones = Dropzone.wireAll();
wireTabs();
var createForm = document.querySelector("[data-create-form]");
if (createForm) wireCreate(createForm, dropzones[0]);
var revealPage = document.querySelector("[data-reveal-page]");
if (revealPage) wireReveal(revealPage);
var burnPage = document.querySelector("[data-burn-page]");
if (burnPage) wireBurn(burnPage);
var reportPage = document.querySelector("[data-report-page]");
if (reportPage) wireReport(reportPage);
