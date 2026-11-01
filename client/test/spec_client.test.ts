// Regression tests from the security review (docs/security-review/findings/SUMMARY.md) for the
// client: the negative cases the conformance vectors do not pin, and the library behaviour the
// spec promises. Skipped tests are waiting for the step that fixes their finding (the skip
// reason names it); un-skip them with the fix.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { Argon2 } from "../src/crypto/argon2.ts";
import { serializeHeader } from "../src/crypto/blob.ts";
import { concat, fromBase64Url, toBase64Url, u32be } from "../src/crypto/bytes.ts";
import { sealChunk } from "../src/crypto/chunks.ts";
import { decodePayload, encodePayload } from "../src/crypto/container.ts";
import { ShhError } from "../src/crypto/error.ts";
import { decodeFragment, encodeFragment } from "../src/crypto/fragment.ts";
import { ARGON2_MIN, INFO, checkArgon2Bounds, hkdfAesKey } from "../src/crypto/kdf.ts";
import { CHUNK_SIZE, pad } from "../src/crypto/padding.ts";
import { decrypt, decryptStream } from "../src/crypto/secret.ts";
import { burnSecret, createSecret, parseFragment, revealSecret } from "../src/client.ts";
import { ApiError } from "../src/lib/api.ts";
import { sanitiseFileName } from "../src/lib/filename.ts";

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

    const { calls, fetchImpl } = recorder(
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
    const dropped = recorder(() => new Response(broken, { status: 200, headers: { "x-shh-claim-token": "CLAIM" } }));
    await assert.rejects(
      revealSecret(link, { ...opts, fetch: dropped.fetchImpl, passphrase: "right" }),
      (e: unknown) => e instanceof ApiError && (e as { claimToken?: string }).claimToken === "CLAIM",
    );
  });

  it("revealSecret refuses a body over the cap, announced or not", async () => {
    const blob = await blobFrom(pad(encodePayload({ text: "s", files: [] }), { mode: "padme", min: 4096 }));
    const announced = recorder(() => new Response(blob, { status: 200, headers: { "content-length": String(blob.length) } }));
    const link = `https://h.example/s#${encodeFragment(seed, "share")}`;
    await assert.rejects(
      revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: announced.fetchImpl, maxBlobBytes: blob.length - 1 }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const silent = recorder(() => new Response(blob, { status: 200 }));
    await assert.rejects(
      revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: silent.fetchImpl, maxBlobBytes: blob.length - 1 }),
      (e: unknown) => e instanceof ApiError && e.code === "too_large",
    );
    const fits = recorder(() => new Response(blob, { status: 200 }));
    const r = await revealSecret(link, { apiBase: "https://h.example/api/v1", fetch: fits.fetchImpl, maxBlobBytes: blob.length });
    assert.equal(r.payload.text, "s");
  });

  it("revealSecret sends only lookup = HKDF(seed) to the given base", async () => {
    const { calls, fetchImpl } = recorder(() => new Response(null, { status: 404 }));
    await assert.rejects(revealSecret(encodeFragment(seed, "share"), { apiBase: "https://api.h.example/v1/", fetch: fetchImpl }), (e: unknown) => e instanceof ApiError && e.status === 404);
    assert.equal(calls[0]!.url, "https://api.h.example/v1/secrets/reveal");
    const body = calls[0]!.body as Record<string, string>;
    assert.deepEqual(Object.keys(body), ["lookup"]);
    assert.notEqual(body["lookup"], toBase64Url(seed));
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
