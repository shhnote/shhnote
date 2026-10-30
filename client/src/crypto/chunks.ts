import { own, u32be } from "./bytes.ts";
import { ShhError } from "./error.ts";
import { CHUNK_SIZE, TAG_LEN } from "./padding.ts";

const subtle = globalThis.crypto.subtle;

// nonce = prefix(7) ‖ index(u32 BE) ‖ last(u8): chunks cannot be reordered, dropped or
// truncated without a tag failing (SPEC §2.7).
function nonce(prefix: Uint8Array, index: number, last: boolean): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(12);
  out.set(prefix, 0);
  out.set(u32be(index), 7);
  out[11] = last ? 1 : 0;
  return out;
}

export async function sealChunk(ek: CryptoKey, prefix: Uint8Array, index: number, last: boolean, chunk: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce(prefix, index, last), tagLength: 128 }, ek, own(chunk)));
}

export async function openChunk(ek: CryptoKey, prefix: Uint8Array, index: number, last: boolean, sealed: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce(prefix, index, last), tagLength: 128 }, ek, own(sealed)));
  } catch {
    throw new ShhError("corrupt", `chunk ${index} failed to authenticate`);
  }
}

export async function sealAll(ek: CryptoKey, prefix: Uint8Array, padded: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
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

// All chunks but the last are exactly 64 KiB + 16 bytes, so the body's length says where
// each one starts. The final chunk is opened with the last flag, so a body cut short fails there.
export async function openAll(ek: CryptoKey, prefix: Uint8Array, body: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
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
