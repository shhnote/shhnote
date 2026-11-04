// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for the
// client: the negative cases the conformance vectors do not pin, and the library behaviour the
// spec promises. Skipped tests are waiting for the step that fixes their finding (the skip
// reason names it); un-skip them with the fix.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it, mock } from "node:test";

import { Argon2 } from "../src/crypto/argon2.ts";
import { serializeHeader } from "../src/crypto/blob.ts";
import { concat, fromBase64Url, toBase64Url, u32be } from "../src/crypto/bytes.ts";
import { sealChunk } from "../src/crypto/chunks.ts";
import { decodePayload, encodePayload } from "../src/crypto/container.ts";
import { ShhError } from "../src/crypto/error.ts";
import { decodeFragment, encodeFragment } from "../src/crypto/fragment.ts";
import { ARGON2_MIN, INFO, checkArgon2Bounds, hkdfAesKey } from "../src/crypto/kdf.ts";
import { CHUNK_SIZE, pad } from "../src/crypto/padding.ts";
import { decrypt, decryptStream, encrypt, lookup } from "../src/crypto/secret.ts";
import { burnSecret, createSecret, parseFragment, revealSecret } from "../src/client.ts";
import { Api, ApiError, type InstanceConfig, getConfig } from "../src/lib/api.ts";
import { sanitiseFileName } from "../src/lib/filename.ts";
import { ClaimStore } from "../src/ui/claims.ts";
import { fillTtl, messageFor, ttlChoices } from "../src/ui/create.ts";
import { configForReveal } from "../src/ui/reveal.ts";
import { COPIED_MS, formatDuration, pageSettings, wireCopy } from "../src/ui/dom.ts";
import { createT } from "../src/ui/i18n.ts";
import * as ui from "../src/ui/index.ts";
import { wireTabs } from "../src/ui/tabs.ts";

const subtle = globalThis.crypto.subtle;
const wasmBytes = new Uint8Array(readFileSync(new URL("../../target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm", import.meta.url)));
const argon2 = await Argon2.load(wasmBytes);

const enc = new TextEncoder();
const seed = new Uint8Array(32).fill(7);
const rawEk = new Uint8Array(32).fill(9);
const prefix = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
const wrapIv = new Uint8Array(12).fill(3);
const salt = new Uint8Array(16).fill(5);

const isCode = (code: string) => (e: unknown) => e instanceof ShhError && e.code === code;

// Builds a blob around an arbitrary padded plaintext, with control over which chunks are
// sealed, in which order and with which last flags.
async function headerFor(kekIkm: Uint8Array = seed, info: Uint8Array = INFO.kekDirect): Promise<Uint8Array> {
  const ek = await subtle.importKey("raw", rawEk, { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const kek = await hkdfAesKey(kekIkm, info, ["wrapKey"]);
  const wrappedEk = new Uint8Array(await subtle.wrapKey("raw", ek, kek, { name: "AES-GCM", iv: wrapIv }));
  return serializeHeader({ salt, argon: ARGON2_MIN, wrapIv, wrappedEk, noncePrefix: prefix });
}

async function ekKey(): Promise<CryptoKey> {
  return subtle.importKey("raw", rawEk, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
}

interface Plan {
  index: number;
  last: boolean;
  slice: number; // which plaintext chunk
}

async function blobFrom(padded: Uint8Array, plan?: Plan[]): Promise<Uint8Array<ArrayBuffer>> {
  const ek = await ekKey();
  const count = Math.max(1, Math.ceil(padded.length / CHUNK_SIZE));
  const steps = plan ?? [...Array(count).keys()].map((i) => ({ index: i, last: i === count - 1, slice: i }));
  const sealed: Uint8Array[] = [];
  for (const s of steps) {
    sealed.push(await sealChunk(ek, prefix, s.index, s.last, padded.subarray(s.slice * CHUNK_SIZE, (s.slice + 1) * CHUNK_SIZE)));
  }
  return concat(await headerFor(), ...sealed);
}

function paddedOf(payload: Uint8Array, bucket: number, payloadLen = payload.length): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bucket);
  out.set(concat(u32be(payloadLen), payload));
  return out;
}

const threeChunk = () => pad(encodePayload({ text: "x".repeat(150_000), files: [] }), { mode: "padme", min: 4096 });

describe("spec: chunk layer beyond the vectors", () => {
  it("a hand-built multi-chunk blob decrypts", async () => {
    const padded = threeChunk();
    assert.equal(Math.ceil(padded.length / CHUNK_SIZE), 3);
    const out = await decrypt(await blobFrom(padded), seed);
    assert.equal(out.text, "x".repeat(150_000));
  });

  it("chunk contents swapped under their original indices never yield the original text", async () => {
    // These authenticate (each chunk is just different plaintext), so the container parse has
    // to catch the damage; whatever it reports, it must not be the original.
    const padded = threeChunk();
    const swappedSlices = [
      { index: 0, last: false, slice: 1 },
      { index: 1, last: false, slice: 0 },
      { index: 2, last: true, slice: 2 },
    ];
    const result = await decrypt(await blobFrom(padded, swappedSlices), seed).then(
      (p) => p.text,
      (e: unknown) => (e instanceof ShhError ? e.code : String(e)),
    );
    assert.notEqual(result, "x".repeat(150_000));
  });

  it("payload_len = bucket - 4 is the edge: it passes unpad and fails in the container", async () => {
    const payload = encodePayload({ text: "y".repeat(140_000), files: [] });
    const bucket = 3 * CHUNK_SIZE;
    await assert.rejects(decrypt(await blobFrom(paddedOf(payload, bucket, bucket - 4)), seed), isCode("corrupt"));
  });
});

// Feeds a blob to the streaming decoder in pieces of the given size.
function pieces(blob: Uint8Array, size: number): AsyncIterable<Uint8Array> {
  return (async function* () {
    for (let at = 0; at < blob.length; at += size) {
      yield blob.subarray(at, Math.min(at + size, blob.length));
    }
  })();
}

describe("spec: streaming decryption (SPEC §2.7, §10)", () => {
  it("decrypts the same whatever the piece size", async () => {
    const files = [
      { name: "a.bin", type: "application/octet-stream", bytes: new Uint8Array(70_000).map((_, i) => i & 0xff) },
      { name: "empty", type: "text/plain", bytes: new Uint8Array(0) },
      { name: "b.bin", type: "application/octet-stream", bytes: new Uint8Array(3).fill(9) },
    ];
    const padded = pad(encodePayload({ text: "streamed", files }), { mode: "padme", min: 4096 });
    const blob = await blobFrom(padded);
    for (const size of [1, 7, 94, 95, 96, 4096, CHUNK_SIZE + 15, CHUNK_SIZE + 16, CHUNK_SIZE + 17, blob.length]) {
      const out = await decryptStream(pieces(blob, size), seed);
      assert.equal(out.text, "streamed", `${size}`);
      assert.equal(out.files.length, 3, `${size}`);
      assert.deepEqual([...out.files[0]!.bytes], [...files[0]!.bytes], `${size}`);
      assert.equal(out.files[1]!.bytes.length, 0, `${size}`);
      assert.deepEqual([...out.files[2]!.bytes], [9, 9, 9], `${size}`);
    }
  });

  it("fails like the one-shot path when the stream ends early", async () => {
    const blob = await blobFrom(threeChunk());
    const cases: [number, string][] = [
      [50, "invalid_blob_length"],
      [95, "invalid_blob_length"],
      [95 + CHUNK_SIZE + 16 + 5, "invalid_blob_length"],
      [95 + 2 * (CHUNK_SIZE + 16), "corrupt"],
      [95 + CHUNK_SIZE + 16 + 1000, "corrupt"],
    ];
    for (const [cut, code] of cases) {
      await assert.rejects(decryptStream(pieces(blob.subarray(0, cut), 1000), seed), isCode(code), `${cut}`);
      await assert.rejects(decrypt(blob.subarray(0, cut), seed), isCode(code), `${cut} one-shot`);
    }
  });

  it("refuses a payload length that runs past the bucket, streamed", async () => {
    const payload = encodePayload({ text: "y".repeat(140_000), files: [] });
    const bucket = 3 * CHUNK_SIZE;
    const blob = await blobFrom(paddedOf(payload, bucket, bucket - 3));
    await assert.rejects(decryptStream(pieces(blob, 10_000), seed), isCode("corrupt"));
  });
});

describe("spec: container beyond the vectors", () => {
  const withManifest = (json: string, tail: Uint8Array = new Uint8Array(0)) => {
    const m = enc.encode(json);
    return concat(u32be(m.length), m, tail);
  };

  it("a null file entry stays inside the error contract (S-47)", () => {
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":null,"files":[null]}')), isCode("manifest"));
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":null,"files":[1]}')), isCode("manifest"));
  });

  it("encoding an empty payload is refused", () => {
    assert.throws(() => encodePayload({ text: null, files: [] }), isCode("empty_payload"));
  });

  it("duplicate and empty file names are accepted by the protocol layer (SPEC §2.5: display data)", () => {
    const p = decodePayload(withManifest('{"v":1,"text":null,"files":[{"name":"","type":"","size":1},{"name":"","type":"","size":1},{"name":"a","type":"","size":0},{"name":"a","type":"","size":0}]}', new Uint8Array(2)));
    assert.deepEqual(p.files.map((f) => f.name), ["", "", "a", "a"]);
  });
});

describe("spec: fragment beyond the vectors", () => {
  const good = encodeFragment(seed, "share");

  it("accepts exactly 44 base64url chars, with or without a leading #", () => {
    assert.equal(good.length, 44);
    assert.deepEqual(decodeFragment(good, "share"), seed);
    assert.deepEqual(decodeFragment(`#${good}`, "share"), seed);
  });

  it("rejects whitespace, a doubled # and the empty string", () => {
    assert.throws(() => decodeFragment(`${good} `, "share"), isCode("invalid_fragment"));
    assert.throws(() => decodeFragment(` ${good.slice(1)}`, "share"), isCode("invalid_fragment"));
    assert.throws(() => decodeFragment(`${good.slice(0, 20)}\n${good.slice(21)}`, "share"), isCode("invalid_fragment"));
    assert.throws(() => decodeFragment(`##${good.slice(1)}`, "share"), isCode("invalid_fragment"));
    assert.throws(() => decodeFragment("", "share"), isCode("invalid_fragment"));
  });

  it("base64url decoder rejects non-canonical trailing bits", () => {
    assert.equal(fromBase64Url("AB"), null);
    assert.deepEqual(fromBase64Url("AA"), new Uint8Array([0]));
  });

  it("parseFragment uses the first # and ignores path and query", () => {
    assert.deepEqual(parseFragment(`https://h.example/s?q=${good.slice(0, 10)}#${good}`).seed, seed);
    assert.deepEqual(parseFragment(`https://h.example/en/s#${good}`).seed, seed);
    assert.throws(() => parseFragment(`https://h.example/s/${good}`), isCode("invalid_fragment"));
    assert.throws(() => parseFragment(`https://h.example/s?k=${good}`), isCode("invalid_fragment"));
    assert.throws(() => parseFragment(`https://h.example/s#${good}#x`), isCode("invalid_fragment"));
  });
});

describe("spec: argon2", () => {
  it("bounds are enforced in JS before the WASM call", () => {
    for (const bad of [
      { m: 4096, t: 3, p: 1 },
      { m: 256 * 1024 + 1, t: 3, p: 1 },
      { m: 8192.5, t: 3, p: 1 },
      { m: 8192, t: 0, p: 1 },
      { m: 8192, t: 9, p: 1 },
      { m: 8192, t: 1, p: 5 },
      { m: Number.NaN, t: 1, p: 1 },
    ]) {
      assert.throws(() => checkArgon2Bounds(bad), isCode("argon2_out_of_bounds"));
      assert.throws(() => argon2.hash("x", salt, bad), isCode("argon2_out_of_bounds"));
    }
  });

  it("work memory is wiped before the WASM call returns", () => {
    const wasm = (argon2 as unknown as { wasm: { memory: WebAssembly.Memory } }).wasm;
    argon2.hash("correct horse", salt, ARGON2_MIN);
    const mem = new Uint8Array(wasm.memory.buffer);
    let nonZero = 0;
    for (let i = 0; i < mem.length; i += 64) if (mem[i] !== 0) nonZero++;
    const sampledKiB = (nonZero * 64) / 1024;
    // 8 MiB of Argon2 blocks were used; only the module's own data may remain.
    assert.ok(sampledKiB < 256, `${sampledKiB} KiB still non-zero`);
  });

  it("an empty passphrase is refused at the boundary, never read as 'none' (SPEC §2.10, S-46)", async () => {
    const header = await headerFor(seed, INFO.kekDirect);
    const padded = pad(encodePayload({ text: "direct", files: [] }), { mode: "padme", min: 4096 });
    const blob = concat(header, await sealChunk(await ekKey(), prefix, 0, true, padded));
    // Refused even on a direct blob, before anything is read.
    await assert.rejects(decrypt(blob, seed, "", argon2), isCode("empty_passphrase"));
    assert.equal((await decrypt(blob, seed, null)).text, "direct");
    // The library entry points refuse it without contacting the server.
    const { calls, fetchImpl } = recorder(() => new Response(null, { status: 404 }));
    const api = { apiBase: "https://h.example/api/v1", fetch: fetchImpl, argon2 };
    await assert.rejects(createSecret({ ...api, payload: { text: "x", files: [] }, lifetime: "ttl", ttlSeconds: 3600, passphrase: "" }), isCode("empty_passphrase"));
    await assert.rejects(revealSecret(`#${encodeFragment(seed, "share")}`, { ...api, passphrase: "" }), isCode("empty_passphrase"));
    assert.equal(calls.length, 0, "nothing left the client");
  });
});

// A fetch double that records every request and answers from a script.
function recorder(answer: (url: string, body: unknown) => Response) {
  const calls: { url: string; body: unknown }[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : init?.body;
    calls.push({ url, body });
    return answer(url, body);
  };
  return { calls, fetchImpl };
}

// A recorder for an instance: `/config` is answered with `config` (a current instance by
// default) and left out of `calls`, so a test sees only the requests about the secret.
function instance(answer: (url: string, body: unknown) => Response, config: InstanceConfig = instanceConfig) {
  const inner = recorder(answer);
  const configCalls: string[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    if (url.endsWith("/config")) {
      configCalls.push(url);
      return Response.json(config);
    }
    return inner.fetchImpl(url, init);
  };
  return { calls: inner.calls, configCalls, fetchImpl };
}

describe("spec: client library", () => {
  it("burnSecret refuses a share link without contacting the server", async () => {
    const shareLink = `https://h.example/s#${encodeFragment(seed, "share")}`;
    const { calls, fetchImpl } = recorder(() => new Response(null, { status: 204 }));
    await assert.rejects(burnSecret(shareLink, { apiBase: "https://h.example/api/v1", fetch: fetchImpl }), isCode("wrong_kind"));
    assert.equal(calls.length, 0, "nothing left the client");
  });

  it("revealSecret refuses a burn link without contacting the server", async () => {
    const burnLink = `https://h.example/burn#${encodeFragment(seed, "burn")}`;
    const { calls, fetchImpl } = recorder(() => new Response(null, { status: 404 }));
    await assert.rejects(revealSecret(burnLink, { apiBase: "https://h.example/api/v1", fetch: fetchImpl }), isCode("wrong_kind"));
    assert.equal(calls.length, 0, "nothing left the client");
  });

  it("revealSecret keeps the claim token through confirm:false, a wrong passphrase and a dropped body", async () => {
    const passKey = argon2.hash("right", salt, ARGON2_MIN);
    const header = await headerFor(concat(seed, passKey), INFO.kekPass);
    const padded = pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 });
    const blob = concat(header, await sealChunk(await ekKey(), prefix, 0, true, padded));

    const { calls, fetchImpl } = instance(
      () => new Response(blob, { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }),
    );
    const opts = { apiBase: "https://h.example/api/v1", fetch: fetchImpl, argon2 };
    const link = `https://h.example/s#${encodeFragment(seed, "share")}`;

    // confirm:false: the caller gets the claim token, so it can re-download or confirm later.
    const r = (await revealSecret(link, { ...opts, passphrase: "right", confirm: false })) as { singleView: boolean; claimToken?: string | null };
    assert.equal(r.singleView, true);
    assert.equal(r.claimToken, "CLAIM");

    // Wrong passphrase: the error carries the claim token, and a retry re-downloads with it
    // instead of consuming a fresh reveal.
    let carried: string | undefined;
    await assert.rejects(revealSecret(link, { ...opts, passphrase: "wrong" }), (e: unknown) => {
      carried = (e as { claimToken?: string }).claimToken;
      return e instanceof ShhError && e.code === "wrong_passphrase" && carried === "CLAIM";
    });
    const retried = await revealSecret(link, { ...opts, passphrase: "right", claimToken: carried ?? null });
    assert.equal(retried.payload.text, "s");
    const reveals = calls.filter((c) => c.url.endsWith("/secrets/reveal"));
    assert.ok(reveals.some((c) => (c.body as { claim_token?: string }).claim_token === "CLAIM"), "a retry carries claim_token");

    // Dropped body: the failure is reported as an ApiError that still carries the claim token.
    const broken = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(blob.subarray(0, 100));
        controller.error(new Error("connection reset"));
      },
    });
    const dropped = instance(() => new Response(broken, { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }));
    await assert.rejects(
      revealSecret(link, { ...opts, fetch: dropped.fetchImpl, passphrase: "right" }),
      (e: unknown) => e instanceof ApiError && (e as { claimToken?: string }).claimToken === "CLAIM",
    );
  });

  it("revealSecret refuses a body over the cap, announced or not", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const announced = instance(() => new Response(blob, { status: 200, headers: { "content-length": String(blob.length) } }));
    const link = `https://h.example/s#${encodeFragment(seed, "share")}`;
    await assert.rejects(
      revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: announced.fetchImpl, maxBlobBytes: blob.length - 1 }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const silent = instance(() => new Response(blob, { status: 200 }));
    await assert.rejects(
      revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: silent.fetchImpl, maxBlobBytes: blob.length - 1 }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const fits = instance(() => new Response(blob, { status: 200 }));
    const r = await revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: fits.fetchImpl, maxBlobBytes: blob.length });
    assert.equal(r.payload.text, "s");
  });

  it("revealSecret sends only lookup = HKDF(seed) to the given base", async () => {
    const { calls, fetchImpl } = instance(() => new Response(null, { status: 404 }));
    await assert.rejects(revealSecret(encodeFragment(seed, "share"), { apiBase: "https://api.h.example/v1/", fetch: fetchImpl }), (e: unknown) => e instanceof ApiError && e.status === 404);
    assert.equal(calls[0]!.url, "https://api.h.example/v1/secrets/reveal");
    const body = calls[0]!.body as Record<string, string>;
    assert.deepEqual(Object.keys(body), ["lookup"]);
    assert.notEqual(body["lookup"], toBase64Url(seed));
  });
});

const instanceConfig: InstanceConfig = {
  fragment_version: 1,
  padding: { mode: "padme", min: 65536 },
  inline_max: 2097152,
  max_blob_bytes: 2097152,
  claim_window_secs: 900,
  min_ttl_secs: 60,
  max_ttl_secs: 1209600,
  default_ttl_secs: 86400,
  ttl_presets: [3600, 86400],
  text_max_bytes: 65536,
  files_enabled: true,
  regions: [],
  server_version: "0.3.0",
  web_mode: "full",
};

describe("spec: shared instance config (revision 3, B1)", () => {
  it("getConfig fetches once per base and fetch implementation", async () => {
    const { calls, fetchImpl } = recorder(() => Response.json(instanceConfig));
    const first = await getConfig("https://cfg-a.example/api/v1", fetchImpl);
    const second = await getConfig("https://cfg-a.example/api/v1/", fetchImpl);
    assert.deepEqual(first, instanceConfig);
    assert.equal(second, first, "the same answer, not a second fetch");
    assert.equal(calls.length, 1);
    await getConfig("https://cfg-b.example/api/v1", fetchImpl);
    assert.equal(calls.length, 2, "another base is another instance");
    const other = recorder(() => Response.json(instanceConfig));
    await getConfig("https://cfg-a.example/api/v1", other.fetchImpl);
    assert.equal(other.calls.length, 1, "another fetch never sees the first one's answer");
  });

  it("getConfig does not keep a failure", async () => {
    let fail = true;
    const { calls, fetchImpl } = recorder(() => (fail ? new Response(null, { status: 503 }) : Response.json(instanceConfig)));
    await assert.rejects(getConfig("https://cfg-c.example/api/v1", fetchImpl), (e: unknown) => e instanceof ApiError && e.status === 503);
    fail = false;
    assert.deepEqual(await getConfig("https://cfg-c.example/api/v1", fetchImpl), instanceConfig);
    assert.equal(calls.length, 2);
  });

  it("createSecret uses the shared config", async () => {
    const { calls, fetchImpl } = recorder((url) =>
      url.endsWith("/config") ? Response.json(instanceConfig) : new Response(null, { status: 201 }),
    );
    const apiBase = "https://cfg-d.example/api/v1";
    await getConfig(apiBase, fetchImpl);
    const created = await createSecret({ apiBase, fetch: fetchImpl, payload: { text: "x", files: [] }, lifetime: "ttl", ttlSeconds: 3600 });
    assert.equal(decodeFragment(created.fragment).length, 32);
    assert.deepEqual(
      calls.map((c) => c.url),
      [`${apiBase}/config`, `${apiBase}/secrets`],
    );
  });
});

describe("spec: page strings (revision 3, B1)", () => {
  const rootWith = (json: string | null) =>
    ({ querySelector: () => (json === null ? null : { textContent: json }) }) as unknown as ParentNode;

  it("createT reads the strings block under the root and fills variables", () => {
    const t = createT(rootWith('{"reveal-download": "Download", "result-chip-expires": "Expires in {period}"}'));
    assert.equal(t("reveal-download"), "Download");
    assert.equal(t("result-chip-expires", { period: "1 day" }), "Expires in 1 day");
  });

  it("createT falls back to the key for a missing block, a missing key or invalid JSON", () => {
    assert.equal(createT(rootWith(null))("reveal-download"), "reveal-download");
    assert.equal(createT(rootWith("{}"))("reveal-download"), "reveal-download");
    assert.equal(createT(rootWith("{not json"))("burn-working"), "burn-working");
    assert.equal(createT()("burn-working"), "burn-working", "no document in Node: keys, no crash");
  });
});

describe("spec: controller options (revision 3, B2)", () => {
  // An element whose ancestors carry these `data-shh-*` attributes; Node has no DOM.
  const pageWith = (attrs: Record<string, string>) =>
    ({
      closest: (selector: string) => {
        const name = /^\[(data-shh-[a-z-]+)\]$/.exec(selector)?.[1] ?? "";
        return name in attrs ? { getAttribute: () => attrs[name] } : null;
      },
    }) as unknown as Element;
  const builtIn = pageWith({
    "data-shh-api": "https://h.example/api/v1",
    "data-shh-asset-version": "abc123",
    "data-shh-max-blob-bytes": "2097152",
  });

  it("falls back to the page's data-shh-* attributes", () => {
    assert.deepEqual(pageSettings(builtIn), {
      apiBase: "https://h.example/api/v1",
      argon2Url: "/static/argon2.wasm?v=abc123",
      maxBlobBytes: 2097152,
    });
  });

  it("options win over the attributes", () => {
    const options = { apiBase: "https://api.other.example/v1", argon2Url: "/assets/argon2.wasm", maxBlobBytes: 65536 };
    assert.deepEqual(pageSettings(builtIn, options), options);
  });

  it("without an asset version the module is /argon2.wasm, and no limit is invented", () => {
    const bare = pageWith({ "data-shh-api": "https://h.example/api/v1" });
    assert.deepEqual(pageSettings(bare), { apiBase: "https://h.example/api/v1", argon2Url: "/argon2.wasm", maxBlobBytes: undefined });
    assert.equal(pageSettings(bare, { maxBlobBytes: 1024 }).maxBlobBytes, 1024);
  });

  it("refuses to guess an API base", () => {
    assert.throws(() => pageSettings(pageWith({})), /apiBase/);
    assert.equal(pageSettings(pageWith({}), { apiBase: "https://h.example/api/v1" }).argon2Url, "/argon2.wasm");
  });
});

describe("spec: controller options and hooks (revision 3, D3a)", () => {
  // A root with one `[data-shh-form=<name>]` form inside and no data-shh-* attributes anywhere.
  function bareRoot(name: string) {
    const form = {
      hidden: true,
      querySelector: () => ({ textContent: "", disabled: false }),
      addEventListener: () => {},
    };
    const sections: { dataset: Record<string, string>; hidden: boolean }[] = [{ dataset: { shhState: "notfound" }, hidden: true }];
    const root = {
      closest: () => null,
      querySelector: (selector: string) => (selector === `[data-shh-form=${name}]` ? form : null),
      querySelectorAll: () => sections,
    };
    return { root: root as unknown as HTMLElement, form, sections };
  }
  const t = (key: string) => key;
  const options = { t, apiBase: "https://api.other.example/v1" };
  const withLocation = (run: () => void) => {
    const g = globalThis as { location?: unknown; history?: unknown };
    const saved = [g.location, g.history];
    g.location = { hash: "", pathname: "/burn", origin: "https://site.example" };
    g.history = { replaceState: () => {} };
    try {
      run();
    } finally {
      [g.location, g.history] = saved;
    }
  };

  it("wireBurn and wireReport take apiBase as an option, with no data-shh-api on the page", () => {
    withLocation(() => {
      const burn = bareRoot("burn");
      assert.throws(() => ui.wireBurn(burn.root, { t }), /apiBase/);
      ui.wireBurn(burn.root, options);
      assert.equal(burn.sections[0]!.hidden, false, "an empty fragment ends in notfound");

      const report = bareRoot("report");
      assert.throws(() => ui.wireReport(report.root, { t }), /apiBase/);
      ui.wireReport(report.root, options);
      assert.equal(report.form.hidden, false, "the form is shown");
    });
  });

  it("wireTabs marks a wired container with data-shh-ready, not a class", () => {
    const attributes: Record<string, string> = {};
    const tab = { id: "t1", tabIndex: -1, setAttribute: () => {}, getAttribute: () => "p1", addEventListener: () => {}, focus: () => {} };
    const tabList = { hidden: true, querySelectorAll: () => [tab] };
    const container = {
      classList: { add: () => assert.fail("wireTabs added a class") },
      querySelector: () => tabList,
      querySelectorAll: () => [],
      setAttribute: (name: string, value: string) => (attributes[name] = value),
    };
    const root = { querySelectorAll: () => [container] } as unknown as ParentNode;
    const g = globalThis as { document?: unknown; window?: unknown; location?: unknown; history?: unknown };
    const saved = [g.document, g.window, g.location, g.history];
    g.document = { getElementById: () => ({ id: "p1", hidden: true }) };
    g.window = { addEventListener: () => {} };
    g.location = { hash: "" };
    try {
      wireTabs(root);
    } finally {
      [g.document, g.window, g.location, g.history] = saved;
    }
    assert.deepEqual(attributes, { "data-shh-ready": "true" });
    assert.equal(tabList.hidden, false);
  });

  it("/ui exports the helpers a frontend needs to match the reference pages", () => {
    assert.equal(ui.COPIED_MS, COPIED_MS);
    assert.equal(ui.formatDuration(3600, "en"), "1 hour");
    assert.deepEqual(ui.ttlChoices(instanceConfig), ttlChoices(instanceConfig));
    assert.equal(ui.fillTtl, fillTtl);
  });
});

describe("spec: protocol check in the controllers (revision 3, D3b)", () => {
  // `getConfig` without a fetch implementation uses the global one, as the pages do.
  async function withFetch<T>(fetchImpl: typeof fetch, run: () => Promise<T>): Promise<T> {
    const previous = globalThis.fetch;
    globalThis.fetch = fetchImpl;
    try {
      return await run();
    } finally {
      globalThis.fetch = previous;
    }
  }
  const answering = (config: unknown, urls: string[]) =>
    (async (url: string | URL | Request) => {
      urls.push(String(url));
      return Response.json(config);
    }) as typeof fetch;

  it("the reveal page reads /config before anything else and refuses another fragment version", async () => {
    const urls: string[] = [];
    const base = "https://d3b-newer.example/api/v1";
    await withFetch(answering({ ...instanceConfig, fragment_version: 99 }, urls), () =>
      assert.rejects(configForReveal(base), (e: unknown) => e instanceof ShhError && e.code === "unsupported_protocol"),
    );
    assert.deepEqual(urls, [`${base}/config`]);
  });

  it("the reveal page gets null, not a fallback, when /config cannot be read", async () => {
    const failing = (async () => {
      throw new TypeError("offline");
    }) as typeof fetch;
    assert.equal(await withFetch(failing, () => configForReveal("https://d3b-offline.example/api/v1")), null);
  });

  it("the reveal page gets the config when the version is supported", async () => {
    const config = await withFetch(answering(instanceConfig, []), () => configForReveal("https://d3b-ok.example/api/v1"));
    assert.equal(config?.max_blob_bytes, instanceConfig.max_blob_bytes);
  });

  it("the create page names the problem instead of a generic failure", () => {
    const t = (key: string) => key;
    assert.equal(messageFor(t, new ShhError("unsupported_protocol", "newer")), "error-unsupported-protocol");
  });
});

describe("spec: lifetimes from the instance (revision 3, B2)", () => {
  it("offers the instance's presets shortest first, with its default preselected", () => {
    assert.deepEqual(ttlChoices(instanceConfig), { seconds: [3600, 86400], selected: 86400 });
  });

  it("adds a default that is not a preset, and drops presets outside the bounds", () => {
    const config = { ...instanceConfig, ttl_presets: [1209600, 900, 30, 3600], default_ttl_secs: 7200, max_ttl_secs: 86400 };
    assert.deepEqual(ttlChoices(config), { seconds: [900, 3600, 7200], selected: 7200 });
  });

  it("fills the select with labelled options, the default selected and kept for form.reset()", () => {
    // Node has no DOM: a stand-in for `Option` and for the select.
    class FakeOption {
      text: string;
      value: string;
      defaultSelected: boolean;
      selected: boolean;
      constructor(text: string, value: string, defaultSelected: boolean, selected: boolean) {
        this.text = text;
        this.value = value;
        this.defaultSelected = defaultSelected;
        this.selected = selected;
      }
    }
    const g = globalThis as { Option?: unknown };
    const previous = g.Option;
    g.Option = FakeOption;
    try {
      let options: FakeOption[] = [];
      const select = { replaceChildren: (...children: FakeOption[]) => (options = children) } as unknown as HTMLSelectElement;
      fillTtl(select, { ...instanceConfig, ttl_presets: [600, 7200, 172800], default_ttl_secs: 7200 }, "en");
      assert.deepEqual(
        options.map((o) => [o.value, o.text, o.defaultSelected, o.selected]),
        [
          ["600", "10 minutes", false, false],
          ["7200", "2 hours", true, true],
          ["172800", "2 days", false, false],
        ],
      );
    } finally {
      g.Option = previous;
    }
  });

  it("words any lifetime in its largest whole unit, in the page's language", () => {
    assert.equal(formatDuration(900, "en"), "15 minutes");
    assert.equal(formatDuration(3600, "en"), "1 hour");
    assert.equal(formatDuration(86400, "en"), "1 day");
    assert.equal(formatDuration(259200, "en"), "3 days");
    assert.equal(formatDuration(5400, "en"), "90 minutes");
    assert.equal(formatDuration(90, "en"), "90 seconds");
    assert.equal(formatDuration(86400, "de"), "1 Tag");
    assert.equal(formatDuration(259200, "de"), "3 Tage");
  });
});

describe("spec: copy buttons (revision 3, B3)", () => {
  // A stand-in button and clipboard; Node has no DOM.
  function fakeButton() {
    let onClick: (() => Promise<void>) | undefined;
    const button = {
      textContent: "Copy",
      dataset: {} as Record<string, string>,
      addEventListener: (_type: string, handler: () => Promise<void>) => (onClick = handler),
    };
    return { button, click: () => onClick!() };
  }
  function withClipboard(writeText: (text: string) => Promise<void>, run: () => Promise<void>) {
    Object.defineProperty(globalThis.navigator, "clipboard", { value: { writeText }, configurable: true });
    return run().finally(() => Reflect.deleteProperty(globalThis.navigator, "clipboard"));
  }

  it("marks the button data-shh-copied for a moment and never touches its content", async () => {
    mock.timers.enable({ apis: ["setTimeout"] });
    try {
      const copied: string[] = [];
      const { button, click } = fakeButton();
      wireCopy(button as unknown as HTMLButtonElement, () => "the link", "ignored label");
      await withClipboard(async (text) => void copied.push(text), click);
      assert.deepEqual(copied, ["the link"]);
      assert.equal(button.dataset["shhCopied"], "true");
      assert.equal(button.textContent, "Copy");
      mock.timers.tick(COPIED_MS);
      assert.equal(button.dataset["shhCopied"], undefined, "restored after the feedback window");
      assert.equal(button.textContent, "Copy");
    } finally {
      mock.timers.reset();
    }
  });

  it("says nothing when the clipboard refuses", async () => {
    const { button, click } = fakeButton();
    wireCopy(button as unknown as HTMLButtonElement, () => "x");
    await withClipboard(() => Promise.reject(new Error("denied")), click);
    assert.equal(button.dataset["shhCopied"], undefined);
  });
});

describe("spec: claim token across a reload (revision 3, B4)", () => {
  // `sessionStorage` as Node lacks it: one instance plays the tab's storage across "reloads".
  class FakeStorage {
    readonly items = new Map<string, string>();
    get length() {
      return this.items.size;
    }
    key(i: number) {
      return [...this.items.keys()][i] ?? null;
    }
    getItem(k: string) {
      return this.items.get(k) ?? null;
    }
    setItem(k: string, v: string) {
      this.items.set(k, v);
    }
    removeItem(k: string) {
      this.items.delete(k);
    }
  }
  const asStorage = (s: FakeStorage) => s as unknown as Storage;

  it("a reload between attempts sends the claim token from the first one", async () => {
    const storage = new FakeStorage();
    let now = 1_000_000;
    const clock = () => now;
    const { calls, fetchImpl } = recorder((_url, body) =>
      (body as { claim_token?: string }).claim_token
        ? new Response(new Uint8Array(4), { status: 200 })
        : new Response(new Uint8Array(4), { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }),
    );
    const api = new Api("https://h.example/api/v1", fetchImpl);
    const lookupValue = await lookup(seed);
    const key = await ClaimStore.keyFor(lookupValue);

    // First page: the press claims the secret, the token is stored, then the attempt fails.
    const first = new ClaimStore(asStorage(storage), clock);
    const claimed = await api.reveal(lookupValue, first.get(key));
    assert.equal(claimed.claimToken, "CLAIM");
    first.set(key, claimed.claimToken!, now + 900_000);

    // Reload: a fresh page in the same tab finds the token and downloads again with it.
    now += 60_000;
    const second = new ClaimStore(asStorage(storage), clock);
    second.prune();
    await api.reveal(lookupValue, second.get(key));
    assert.deepEqual(
      calls.map((c) => (c.body as Record<string, string>)["claim_token"] ?? null),
      [null, "CLAIM"],
    );
  });

  it("keeps only the token and its expiry, under SHA-256(lookup), and nothing past the window", async () => {
    const storage = new FakeStorage();
    let now = 0;
    const store = new ClaimStore(asStorage(storage), () => now);
    const lookupValue = await lookup(seed);
    const key = await ClaimStore.keyFor(lookupValue);
    assert.equal(key, `shh-claim:${toBase64Url(await subtle.digest("SHA-256", lookupValue).then((b) => new Uint8Array(b)))}`);
    store.set(key, "CLAIM", 900_000);
    assert.deepEqual(JSON.parse(storage.getItem(key)!), { claimToken: "CLAIM", expiresAt: 900_000 });
    assert.ok(![...storage.items.values()].join().includes(toBase64Url(lookupValue)), "the lookup itself is never stored");

    now = 900_000;
    assert.equal(store.get(key), null, "the window has closed");
    assert.equal(storage.items.size, 0, "and the entry is gone");
  });

  it("prune clears expired and unreadable claims and leaves other keys alone", () => {
    const storage = new FakeStorage();
    storage.setItem("shh-claim:old", JSON.stringify({ claimToken: "A", expiresAt: 10 }));
    storage.setItem("shh-claim:live", JSON.stringify({ claimToken: "B", expiresAt: 1_000 }));
    storage.setItem("shh-claim:junk", "{not json");
    storage.setItem("shhnote-theme", "dark");
    new ClaimStore(asStorage(storage), () => 100).prune();
    assert.deepEqual([...storage.items.keys()].sort(), ["shh-claim:live", "shhnote-theme"]);
  });

  it("delete forgets a claim, and a storage that throws only loses the reload case", () => {
    const storage = new FakeStorage();
    const store = new ClaimStore(asStorage(storage), () => 0);
    store.set("shh-claim:x", "T", 1_000);
    store.delete("shh-claim:x");
    assert.equal(store.get("shh-claim:x"), null);

    const hostile = {
      get length(): number {
        throw new Error("SecurityError");
      },
      key: () => {
        throw new Error("SecurityError");
      },
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
      removeItem: () => {
        throw new Error("SecurityError");
      },
    } as unknown as Storage;
    const blocked = new ClaimStore(hostile, () => 0);
    assert.doesNotThrow(() => {
      blocked.prune();
      blocked.set("shh-claim:x", "T", 1_000);
      blocked.delete("shh-claim:x");
    });
    assert.equal(blocked.get("shh-claim:x"), null);
    assert.equal(new ClaimStore(null).get("shh-claim:x"), null, "no storage at all");
  });
});

describe("spec: protocol version (revision 3, B5)", () => {
  const future = { ...instanceConfig, fragment_version: 2 };

  it("createSecret refuses an instance with another fragment version before uploading", async () => {
    const { calls, configCalls, fetchImpl } = instance(() => new Response(null, { status: 201 }), future);
    await assert.rejects(
      createSecret({ apiBase: "https://v2.example/api/v1", fetch: fetchImpl, payload: { text: "x", files: [] }, lifetime: "ttl", ttlSeconds: 3600 }),
      isCode("unsupported_protocol"),
    );
    assert.equal(configCalls.length, 1);
    assert.equal(calls.length, 0, "nothing was uploaded");
  });

  it("revealSecret refuses before the reveal request, so a single-view secret is not consumed", async () => {
    const { calls, fetchImpl } = instance(() => new Response(new Uint8Array(4), { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }), future);
    await assert.rejects(
      revealSecret(`#${encodeFragment(seed, "share")}`, { apiBase: "https://v2.example/api/v1", fetch: fetchImpl }),
      isCode("unsupported_protocol"),
    );
    assert.equal(calls.length, 0, "no reveal was sent");
  });

  it("revealSecret checks the version once per instance, not on every call", async () => {
    const { calls, configCalls, fetchImpl } = instance(() => new Response(null, { status: 404 }));
    const opts = { apiBase: "https://v1.example/api/v1", fetch: fetchImpl };
    for (let i = 0; i < 2; i++) {
      await assert.rejects(revealSecret(`#${encodeFragment(seed, "share")}`, opts), (e: unknown) => e instanceof ApiError && e.status === 404);
    }
    assert.equal(configCalls.length, 1);
    assert.equal(calls.length, 2);
  });
});

describe("spec: scrubbing (revision 3, B6)", () => {
  it("a failed confirm throws with the claim token and the decrypted payload", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const { calls, fetchImpl } = instance((url) =>
      url.endsWith("/secrets/confirm")
        ? new Response(null, { status: 503 })
        : new Response(blob, { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }),
    );
    await assert.rejects(
      revealSecret(`#${encodeFragment(seed, "share")}`, { apiBase: "https://h.example/api/v1", fetch: fetchImpl }),
      (e: unknown) => e instanceof ApiError && e.status === 503 && e.claimToken === "CLAIM" && e.payload?.text === "s",
    );
    assert.deepEqual(
      calls.map((c) => c.url.replace("https://h.example/api/v1", "")),
      ["/secrets/reveal", "/secrets/confirm"],
    );
  });

  it("encrypt leaves the caller's buffers intact and the blob unchanged by the in-place padding", async () => {
    const r = {
      seed,
      burnToken: new Uint8Array(32).fill(2),
      ek: await subtle.importKey("raw", rawEk, { name: "AES-GCM", length: 256 }, true, ["encrypt"]),
      salt,
      wrapIv,
      noncePrefix: prefix,
    };
    const file = { name: "a.bin", type: "application/octet-stream", bytes: new Uint8Array([1, 2, 3]) };
    const { blob } = await encrypt({ randomness: r, payload: { text: "note", files: [file] }, policy: { mode: "padme", min: 65536 } });
    assert.deepEqual([...file.bytes], [1, 2, 3], "wiping the file is the page's job, after encrypt returns");
    const back = await decrypt(blob, seed, null);
    assert.equal(back.text, "note");
    assert.deepEqual([...back.files[0]!.bytes], [1, 2, 3]);
  });
});

describe("spec: body cap from the instance (revision 3, B7)", () => {
  it("revealSecret without maxBlobBytes refuses a body over the instance's max_blob_bytes", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const link = `#${encodeFragment(seed, "share")}`;
    const small = { ...instanceConfig, max_blob_bytes: blob.length - 1 };
    const announced = instance(() => new Response(blob, { status: 200, headers: { "content-length": String(blob.length) } }), small);
    await assert.rejects(
      revealSecret(link, { apiBase: "https://cap-a.example/api/v1", fetch: announced.fetchImpl }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const silent = instance(() => new Response(blob, { status: 200 }), small);
    await assert.rejects(
      revealSecret(link, { apiBase: "https://cap-b.example/api/v1", fetch: silent.fetchImpl }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const exact = instance(() => new Response(blob, { status: 200 }), { ...instanceConfig, max_blob_bytes: blob.length });
    const r = await revealSecret(link, { apiBase: "https://cap-c.example/api/v1", fetch: exact.fetchImpl });
    assert.equal(r.payload.text, "s");
  });

  it("revealSecret does not reveal without the instance's config", async () => {
    const { calls, fetchImpl } = recorder((url) => (url.endsWith("/config") ? new Response(null, { status: 503 }) : new Response(null, { status: 200 })));
    await assert.rejects(
      revealSecret(`#${encodeFragment(seed, "share")}`, { apiBase: "https://cap-d.example/api/v1", fetch: fetchImpl }),
      (e: unknown) => e instanceof ApiError && e.status === 503,
    );
    assert.deepEqual(calls.map((c) => c.url.split("/v1")[1]), ["/config"], "no reveal was sent");
  });
});

describe("spec: download names (SPEC §10)", () => {
  it("controls, bidi overrides, look-alike slashes, reserved names and long names are cleaned", () => {
    const rlo = "invoice‮fdp.exe";
    assert.ok(!sanitiseFileName(rlo).includes("‮"));
    assert.ok(!/[\u0000-\u001f]/.test(sanitiseFileName("a\u0000b\u001b[31m")));
    assert.ok(!sanitiseFileName("..∕..∕etc").includes("∕"));
    assert.notEqual(sanitiseFileName("CON"), "CON");
    assert.ok(sanitiseFileName("x".repeat(10_000)).length <= 255);
    assert.ok(!sanitiseFileName("../../a").startsWith("."));
    assert.equal(sanitiseFileName(""), "file");
    assert.equal(sanitiseFileName("Bericht 2026.pdf"), "Bericht 2026.pdf");
    assert.ok(new TextEncoder().encode(sanitiseFileName("ü".repeat(300))).length <= 255);
  });
});
