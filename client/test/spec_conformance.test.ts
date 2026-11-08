import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { Argon2 } from "../src/crypto/argon2.ts";
import { serializeHeader } from "../src/crypto/blob.ts";
import { concat, toBase64Url, u32be } from "../src/crypto/bytes.ts";
import { sealChunk } from "../src/crypto/chunks.ts";
import { decodePayload, encodePayload } from "../src/crypto/container.ts";
import { ShhError } from "../src/crypto/error.ts";
import { encodeFragment } from "../src/crypto/fragment.ts";
import { ARGON2_MIN, INFO, hkdfAesKey } from "../src/crypto/kdf.ts";
import { CHUNK_SIZE, HEADER_LEN, pad } from "../src/crypto/padding.ts";
import { decryptBody, lookup } from "../src/crypto/secret.ts";
import { readHeader } from "../src/crypto/stream.ts";
import { createSecret, revealSecret } from "../src/client.ts";
import { Api, ApiError, DEFAULT_MAX_BLOB_BYTES, type InstanceConfig, getConfig } from "../src/lib/api.ts";
import { loadArgon2 } from "../src/lib/argon2-loader.ts";
import { createT } from "../src/ui/i18n.ts";

const subtle = globalThis.crypto.subtle;
const wasmBytes = new Uint8Array(readFileSync(new URL("../../target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm", import.meta.url)));

const enc = new TextEncoder();
const seed = new Uint8Array(32).fill(7);
const rawEk = new Uint8Array(32).fill(9);
const prefix = new Uint8Array([1, 2, 3, 4, 5, 6, 7]);
const wrapIv = new Uint8Array(12).fill(3);
const salt = new Uint8Array(16).fill(5);

const isCode = (code: string) => (e: unknown) => e instanceof ShhError && e.code === code;

async function headerFor(): Promise<Uint8Array> {
  const ek = await subtle.importKey("raw", rawEk, { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const kek = await hkdfAesKey(seed, INFO.kekDirect, ["wrapKey"]);
  const wrappedEk = new Uint8Array(await subtle.wrapKey("raw", ek, kek, { name: "AES-GCM", iv: wrapIv }));
  return serializeHeader({ salt, argon: ARGON2_MIN, wrapIv, wrappedEk, noncePrefix: prefix });
}

async function ekKey(usages: KeyUsage[] = ["encrypt"]): Promise<CryptoKey> {
  return subtle.importKey("raw", rawEk, { name: "AES-GCM", length: 256 }, false, usages);
}

// A blob around a padded plaintext, sealed chunk by chunk in order.
async function blobFrom(padded: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const ek = await ekKey();
  const count = Math.max(1, Math.ceil(padded.length / CHUNK_SIZE));
  const sealed: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    sealed.push(await sealChunk(ek, prefix, i, i === count - 1, padded.subarray(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)));
  }
  return concat(await headerFor(), ...sealed);
}

function pieces(blob: Uint8Array, size: number): AsyncIterable<Uint8Array> {
  return (async function* () {
    for (let at = 0; at < blob.length; at += size) yield blob.subarray(at, Math.min(at + size, blob.length));
  })();
}

function recorder(answer: (url: string, body: unknown) => Response) {
  const calls: { url: string; body: unknown }[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : init?.body;
    calls.push({ url, body });
    return answer(url, body);
  };
  return { calls, fetchImpl };
}

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
  server_version: "0.4.0",
  web_mode: "full",
};

function instance(answer: (url: string, body: unknown) => Response, config: unknown = instanceConfig) {
  const inner = recorder(answer);
  const fetchImpl = async (url: string, init?: RequestInit) => (url.endsWith("/config") ? Response.json(config) : inner.fetchImpl(url, init));
  return { calls: inner.calls, fetchImpl };
}

// A one-bucket blob whose length prefix and manifest claim a file of `claimed` bytes that
// is never there: what a hostile sender uploads to make a recipient reserve memory.
async function lyingBlob(claimed: number): Promise<Uint8Array<ArrayBuffer>> {
  const manifest = enc.encode(JSON.stringify({ v: 1, text: null, files: [{ name: "big", type: "", size: claimed }] }));
  const payloadLen = 4 + manifest.length + claimed;
  const padded = new Uint8Array(65536);
  padded.set(concat(u32be(payloadLen), u32be(manifest.length), manifest));
  return blobFrom(padded);
}

describe("body cap and memory bound (D-4)", () => {
  it("the decoder, bounded by the response length as both revealSecret and wireReveal pass it, reserves nothing of a lying manifest", async () => {
    const claimed = 48 * 1024 * 1024;
    const blob = await lyingBlob(claimed);
    const ek = await ekKey(["decrypt"]);

    // What both the library and the reference page do: the cap is
    // min(blobLen(max_blob_bytes), Content-Length), so the length prefix is refused before
    // any file buffer exists. Measured right after the failure.
    const bounded = await readHeader(pieces(blob, 4096));
    const beforeBounded = process.memoryUsage().arrayBuffers;
    await assert.rejects(decryptBody(ek, bounded.header, bounded.rest, Math.min(DEFAULT_MAX_BLOB_BYTES, blob.length)), isCode("corrupt"));
    assert.ok(process.memoryUsage().arrayBuffers - beforeBounded < claimed / 2, "nothing of the claimed size was reserved");

    // Even a caller that passes a large cap is protected by the decoder's own check of the
    // manifest's sizes against that cap, before allocating.
    const loose = await readHeader(pieces(blob, 4096));
    const beforeLoose = process.memoryUsage().arrayBuffers;
    await assert.rejects(decryptBody(ek, loose.header, loose.rest, claimed / 2), isCode("corrupt"));
    assert.ok(process.memoryUsage().arrayBuffers - beforeLoose < claimed / 2, "the manifest's sizes were not checked against the bound");
  });

  it("a non-numeric max_blob_bytes from /config fails closed, and one above the ceiling is clamped", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const link = `#${encodeFragment(seed, "share")}`;
    // A sane instance refuses a body over its maximum.
    const strict = instance(() => new Response(blob, { status: 200 }), { ...instanceConfig, max_blob_bytes: 100 });
    await assert.rejects(revealSecret(link, { apiBase: "https://cap-1.example/api/v1", fetch: strict.fetchImpl }), (e: unknown) => e instanceof ApiError && e.code === "too_large");
    // A hostile or broken /config fails closed: nothing is revealed, so the single-view
    // secret is not claimed, and the error names the config.
    const hostile = instance(() => new Response(blob, { status: 200 }), { ...instanceConfig, max_blob_bytes: "unlimited" });
    await assert.rejects(revealSecret(link, { apiBase: "https://cap-2.example/api/v1", fetch: hostile.fetchImpl }), (e: unknown) => e instanceof ApiError && e.code === "invalid_config");
    assert.ok(!hostile.calls.some((c) => c.url.endsWith("/secrets/reveal")), "a reveal was sent on an untrusted config");
    // And a numeric value above DEFAULT_MAX_BLOB_BYTES is clamped to the ceiling.
    const huge = instance(() => new Response(blob, { status: 200 }), { ...instanceConfig, max_blob_bytes: 2 ** 50 });
    assert.equal((await getConfig("https://cap-3.example/api/v1", huge.fetchImpl)).max_blob_bytes, DEFAULT_MAX_BLOB_BYTES);
    assert.equal((await revealSecret(link, { apiBase: "https://cap-3.example/api/v1", fetch: huge.fetchImpl })).payload.text, "s");
  });

  it("a malformed Content-Length counts as not announced, so Api.reveal applies the as-received cap", async () => {
    const body = new Uint8Array(1000);
    const { fetchImpl } = recorder(() => new Response(body, { status: 200, headers: { "content-length": "abc" } }));
    const api = new Api("https://cap-4.example/api/v1", fetchImpl);
    const revealed = await api.reveal(await lookup(seed), null, 10);
    // Not a usable length, so it is treated as not announced and the as-received cap
    // applies.
    assert.equal(revealed.contentLength, null);
    await assert.rejects(
      (async () => {
        for await (const piece of revealed.body) void piece;
      })(),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
  });
});

describe("/config caching and precedence", () => {
  it("a padding policy changed on the instance is re-read after the first refusal, so later creates succeed", async () => {
    let policy: InstanceConfig["padding"] = { mode: "padme", min: 65536 };
    let refused = 0;
    const { fetchImpl } = recorder((url, body) => {
      if (url.endsWith("/config")) return Response.json({ ...instanceConfig, padding: policy });
      // The server checks the blob length against its current policy (SPEC §4).
      const form = body as FormData;
      const blob = form.get("blob") as Blob;
      const ok = policy.mode === "padme" ? blob.size === HEADER_LEN + 65536 + 16 : blob.size === HEADER_LEN + policy.ladder[0]! + 16 * Math.ceil(policy.ladder[0]! / CHUNK_SIZE);
      if (!ok) refused++;
      return ok ? new Response(null, { status: 201 }) : Response.json({ error: { code: "invalid_blob_length" } }, { status: 400 });
    });
    const opts = { apiBase: "https://stale.example/api/v1", fetch: fetchImpl, payload: { text: "x", files: [] }, lifetime: "ttl" as const, ttlSeconds: 3600 };
    await createSecret(opts);
    // The admin switches to a bucket ladder; the first refusal makes the client re-read
    // /config and pad again, and later creates use the fresh answer.
    policy = { mode: "buckets", ladder: [131072] };
    for (let i = 0; i < 3; i++) await createSecret(opts);
    assert.equal(refused, 1, "only the first attempt after the change is refused");
  });
});

describe("Argon2 module origin", () => {
  // Node has no `location`, so the caller is the origin; in a page the module must be
  // same-origin (SPEC §10).
  it("outside a page, loadArgon2 fetches the module from whatever URL it is given, cross-origin included", async () => {
    const g = globalThis as { fetch: typeof fetch };
    const saved = g.fetch;
    const urls: string[] = [];
    g.fetch = (async (input: string | URL | Request) => {
      urls.push(String(input));
      return new Response(wasmBytes, { status: 200, headers: { "content-type": "application/wasm" } });
    }) as typeof fetch;
    try {
      const argon2 = await loadArgon2("https://cdn.example/argon2.wasm");
      assert.ok(argon2 instanceof Argon2);
      assert.deepEqual(urls, ["https://cdn.example/argon2.wasm"]);
    } finally {
      g.fetch = saved;
    }
  });
});

// Both implementations must decide the same for the same bytes (SPEC §2.14);
// crates/shhnote-core/tests/spec_manifest_parity.rs has the Rust side of each case.
describe("manifest parsing parity with the Rust core", () => {
  const withManifest = (json: string, tail: Uint8Array = new Uint8Array(0)) => {
    const m = enc.encode(json);
    return concat(u32be(m.length), m, tail);
  };

  it("a file size of -0 is refused, as serde_json refuses it", () => {
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":"t","files":[{"name":"a","type":"","size":-0}]}')), isCode("manifest"));
  });

  it("deep nesting in an ignored key is accepted on both sides, and stays inside the error contract", () => {
    // serde_json skips ignored values iteratively and V8's JSON.parse is iterative too.
    for (const depth of [200, 500_000]) {
      const deep = `${"[".repeat(depth)}${"]".repeat(depth)}`;
      const p = decodePayload(withManifest(`{"v":1,"text":"t","files":[],"x":${deep}}`));
      assert.equal(p.text, "t", `${depth}`);
    }
  });

  it("a duplicated unknown key is ignored, as serde_json ignores it; a duplicated known key is still refused", () => {
    assert.equal(decodePayload(withManifest('{"v":1,"text":"t","files":[],"x":1,"x":2}')).text, "t");
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":"t","files":[{"name":"a","type":"","size":0,"size":0}]}')), isCode("manifest"));
  });

  it("the parity cases the vectors pin still hold", () => {
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":"t","files":[],"text":"u"}')), isCode("manifest"));
    assert.throws(() => decodePayload(withManifest('{"v":1.0,"text":"t","files":[]}')), isCode("manifest"));
    assert.throws(() => decodePayload(withManifest('{"v":1,"files":[]}')), isCode("manifest"));
    assert.throws(() => decodePayload(withManifest('﻿{"v":1,"text":"t","files":[]}')), isCode("manifest"));
    assert.throws(() => decodePayload(withManifest('{"v":1,"text":"\\ud800","files":[]}')), isCode("manifest"));
  });
});

describe("what stays in memory and in storage", () => {
  it("revealSecret with confirm:false returns the token and sends no confirm", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const link = `#${encodeFragment(seed, "share")}`;
    const { calls, fetchImpl } = instance(() => new Response(blob, { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }));
    const r = await revealSecret(link, { apiBase: "https://nc.example/api/v1", fetch: fetchImpl, confirm: false });
    assert.deepEqual({ singleView: r.singleView, claimToken: r.claimToken }, { singleView: true, claimToken: "CLAIM" });
    assert.deepEqual(calls.map((c) => c.url.split("/v1")[1]), ["/secrets/reveal"]);
  });

  it("createT treats a block whose JSON is null like any other gap", () => {
    const block = { textContent: "null" };
    const root = { querySelector: () => block } as unknown as ParentNode;
    assert.equal(createT(root)("reveal-download"), "reveal-download");
  });

  it("the burn-token hash and lookup hash leave the client; the seed and token never do", async () => {
    const { calls, fetchImpl } = instance(() => new Response(null, { status: 201 }));
    const created = await createSecret({ apiBase: "https://m.example/api/v1", fetch: fetchImpl, payload: { text: "x", files: [] }, lifetime: "ttl", ttlSeconds: 3600 });
    const form = calls[0]!.body as FormData;
    const meta = JSON.parse(await (form.get("meta") as Blob).text()) as Record<string, string>;
    const seedText = toBase64Url(new Uint8Array(32));
    assert.notEqual(meta["lookup_key"], created.fragment.slice(1));
    assert.notEqual(meta["burn_key"], created.burnFragment.slice(1));
    assert.ok(!JSON.stringify(meta).includes(created.fragment.slice(1)) && !JSON.stringify(meta).includes(created.burnFragment.slice(1)));
    assert.notEqual(meta["lookup_key"], seedText);
  });
});
