import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { Argon2 } from "../src/crypto/argon2.ts";
import { parseHeader, serializeHeader } from "../src/crypto/blob.ts";
import { concat, equal, fromHex, toHex } from "../src/crypto/bytes.ts";
import { type Payload, decodePayload, encodePayload, manifestJson } from "../src/crypto/container.ts";
import { ShhError } from "../src/crypto/error.ts";
import { type Kind, VERSION, decodeFragment, encodeFragment } from "../src/crypto/fragment.ts";
import { INFO, hkdfBits } from "../src/crypto/kdf.ts";
import { type PaddingPolicy, blobLen, chunkCount, isValidPaddedSize, padme } from "../src/crypto/padding.ts";
import { credentialHash, decrypt, encrypt, importEk, lookup } from "../src/crypto/secret.ts";

interface Vector {
  name: string;
  inputs: {
    seed: string;
    burn_token: string;
    passphrase: string | null;
    argon2: { m: number; t: number; p: number };
    text: string | null;
    files: { name: string; type: string; bytes_base64: string }[];
    ek: string;
    salt: string;
    wrap_iv: string;
    nonce_prefix: string;
    padding: { mode: "padme"; min: number } | { mode: "buckets"; ladder: number[] };
  };
  expected: {
    fragment: string;
    burn_fragment: string;
    lookup: string;
    lookup_key: string;
    burn_key: string;
    pass_key: string | null;
    kek: string;
    wrapped_ek: string;
    manifest: string;
    payload_len: number;
    payload_sha256: string;
    bucket: number;
    chunk_count: number;
    blob_len: number;
    header: string;
    blob_base64: string;
  };
}

interface Doc {
  version: number;
  vectors: Vector[];
  reject: { name: string; base: string; expect: string; blob_base64: string }[];
  reject_fragments: { name: string; fragment: string; as: Kind; expect: string }[];
}

const doc: Doc = JSON.parse(readFileSync(new URL("../../vectors/v1.json", import.meta.url), "utf8"));
const wasmPath = new URL("../../target/wasm32-unknown-unknown/wasm/shhnote_argon2_wasm.wasm", import.meta.url);
let wasmBytes: Uint8Array;
try {
  wasmBytes = new Uint8Array(readFileSync(wasmPath));
} catch {
  throw new Error("Argon2 module not built: run scripts/build-wasm.sh first");
}
const argon2 = await Argon2.load(wasmBytes);

const b64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
const payloadOf = (v: Vector): Payload => ({
  text: v.inputs.text,
  files: v.inputs.files.map((f) => ({ name: f.name, type: f.type, bytes: b64(f.bytes_base64) })),
});
const policyOf = (v: Vector): PaddingPolicy => v.inputs.padding;
const byName = (name: string) => doc.vectors.find((v) => v.name === name)!;

async function sha256hex(bytes: Uint8Array): Promise<string> {
  return toHex(await credentialHash(bytes));
}

function assertPayloadEqual(actual: Payload, expected: Payload, name: string) {
  assert.equal(actual.text, expected.text, name);
  assert.equal(actual.files.length, expected.files.length, name);
  actual.files.forEach((f, i) => {
    assert.equal(f.name, expected.files[i]!.name, name);
    assert.equal(f.type, expected.files[i]!.type, name);
    assert.ok(equal(f.bytes, expected.files[i]!.bytes), `${name}: file ${i} bytes`);
  });
}

describe("conformance vectors", () => {
  it("file is for this protocol version", () => {
    assert.equal(doc.version, VERSION);
  });

  it("derivations match", async () => {
    for (const v of doc.vectors) {
      const seed = fromHex(v.inputs.seed);
      assert.equal(encodeFragment(seed, "share"), v.expected.fragment, v.name);
      assert.equal(encodeFragment(fromHex(v.inputs.burn_token), "burn"), v.expected.burn_fragment, v.name);
      assert.ok(equal(decodeFragment(v.expected.fragment, "share"), seed), v.name);
      assert.ok(equal(decodeFragment(v.expected.burn_fragment, "burn"), fromHex(v.inputs.burn_token)), v.name);
      // Each kind is refused where the other is expected (SPEC §2.2).
      assert.throws(() => decodeFragment(v.expected.burn_fragment, "share"), (e: unknown) => e instanceof ShhError && e.code === "wrong_kind", v.name);
      assert.throws(() => decodeFragment(v.expected.fragment, "burn"), (e: unknown) => e instanceof ShhError && e.code === "wrong_kind", v.name);

      const lk = await lookup(seed);
      assert.equal(toHex(lk), v.expected.lookup, v.name);
      assert.equal(await sha256hex(lk), v.expected.lookup_key, v.name);
      assert.equal(await sha256hex(fromHex(v.inputs.burn_token)), v.expected.burn_key, v.name);

      if (v.inputs.passphrase === null) {
        assert.equal(toHex(await hkdfBits(seed, INFO.kekDirect)), v.expected.kek, v.name);
      } else {
        const passKey = argon2.hash(v.inputs.passphrase, fromHex(v.inputs.salt), v.inputs.argon2);
        assert.equal(toHex(passKey), v.expected.pass_key, v.name);
        assert.equal(toHex(await hkdfBits(concat(seed, passKey), INFO.kekPass)), v.expected.kek, v.name);
      }
    }
  });

  it("payloads match", async () => {
    for (const v of doc.vectors) {
      const payload = payloadOf(v);
      assert.equal(manifestJson(payload), v.expected.manifest, v.name);
      const bytes = encodePayload(payload);
      assert.equal(bytes.length, v.expected.payload_len, v.name);
      assert.equal(await sha256hex(bytes), v.expected.payload_sha256, v.name);
      assertPayloadEqual(decodePayload(bytes), payload, v.name);
    }
  });

  it("encryption reproduces every blob byte for byte", async () => {
    for (const v of doc.vectors) {
      const out = await encrypt({
        randomness: {
          seed: fromHex(v.inputs.seed),
          burnToken: fromHex(v.inputs.burn_token),
          ek: await importEk(fromHex(v.inputs.ek)),
          salt: fromHex(v.inputs.salt),
          wrapIv: fromHex(v.inputs.wrap_iv),
          noncePrefix: fromHex(v.inputs.nonce_prefix),
        },
        payload: payloadOf(v),
        passphrase: v.inputs.passphrase,
        argon: v.inputs.argon2,
        policy: policyOf(v),
        argon2,
      });
      assert.equal(out.bucket, v.expected.bucket, v.name);
      assert.equal(out.blob.length, v.expected.blob_len, v.name);
      assert.equal(out.fragment, v.expected.fragment, v.name);
      assert.equal(out.burnFragment, v.expected.burn_fragment, v.name);
      assert.equal(toHex(out.lookupKey), v.expected.lookup_key, v.name);
      assert.equal(toHex(out.burnKey), v.expected.burn_key, v.name);
      const header = parseHeader(out.blob);
      assert.equal(toHex(serializeHeader(header)), v.expected.header, v.name);
      assert.equal(toHex(header.wrappedEk), v.expected.wrapped_ek, v.name);
      assert.equal(chunkCount(out.bucket), v.expected.chunk_count, v.name);
      assert.ok(equal(out.blob, b64(v.expected.blob_base64)), `${v.name}: full blob`);
      assert.ok(isValidPaddedSize(out.bucket, policyOf(v)), v.name);
      assert.equal(blobLen(out.bucket), out.blob.length, v.name);
    }
  });

  it("decryption recovers every payload", async () => {
    for (const v of doc.vectors) {
      const blob = b64(v.expected.blob_base64);
      const seed = fromHex(v.inputs.seed);
      assertPayloadEqual(await decrypt(blob, seed, v.inputs.passphrase, argon2), payloadOf(v), v.name);
      if (v.inputs.passphrase !== null) {
        await assert.rejects(decrypt(blob, seed, null, argon2), (e: ShhError) => e.code === "passphrase_required", v.name);
        await assert.rejects(decrypt(blob, seed, "wrong", argon2), (e: ShhError) => e.code === "wrong_passphrase", v.name);
      }
    }
  });

  it("direct and passphrase blobs are indistinguishable in shape", () => {
    const direct = byName("text-direct");
    const pass = byName("text-passphrase");
    assert.equal(direct.expected.blob_len, pass.expected.blob_len);
    assert.equal(direct.expected.bucket, pass.expected.bucket);
    assert.notEqual(direct.expected.header, pass.expected.header);
  });

  it("reject cases are rejected", async () => {
    for (const r of doc.reject) {
      const base = byName(r.base);
      const blob = b64(r.blob_base64);
      if (r.expect === "server") {
        // The server refuses this length; the client would never see it.
        assert.ok(!isValidPaddedSize(blob.length - 95 - 16, policyOf(base)), r.name);
        continue;
      }
      await assert.rejects(
        decrypt(blob, fromHex(base.inputs.seed), base.inputs.passphrase, argon2),
        (e: unknown) => e instanceof ShhError && e.code === r.expect,
        r.name,
      );
    }
  });

  it("reject fragments are refused", () => {
    for (const r of doc.reject_fragments) {
      assert.throws(() => decodeFragment(r.fragment, r.as), (e: unknown) => e instanceof ShhError && e.code === r.expect, r.name);
    }
  });
});

describe("padding", () => {
  it("padme matches the spec examples", () => {
    assert.equal(padme(65536), 65536);
    assert.equal(padme(65537), 67584);
    assert.equal(padme(4097), 4352);
    assert.equal(padme(2 ** 20 + 1), 2 ** 20 + 32 * 1024);
    assert.equal(padme(2 ** 36 + 1), 2 ** 36 + 2 ** 30);
  });
});
