import { concat, readU32be, u32be } from "./bytes.ts";
import { ShhError } from "./error.ts";
import { type Argon2Params, SALT_LEN, checkArgon2Bounds } from "./kdf.ts";
import { HEADER_LEN } from "./padding.ts";

export const WRAP_IV_LEN = 12;
export const WRAPPED_EK_LEN = 48;
export const NONCE_PREFIX_LEN = 7;

// The fixed 95-byte header in front of the ciphertext chunks (SPEC §2.8). Same shape for
// direct and passphrase blobs; there is no mode, version or flags field.
export interface Header {
  salt: Uint8Array;
  argon: Argon2Params;
  wrapIv: Uint8Array;
  wrappedEk: Uint8Array;
  noncePrefix: Uint8Array;
}

export function serializeHeader(h: Header): Uint8Array<ArrayBuffer> {
  if (h.salt.length !== SALT_LEN || h.wrapIv.length !== WRAP_IV_LEN || h.wrappedEk.length !== WRAPPED_EK_LEN || h.noncePrefix.length !== NONCE_PREFIX_LEN) {
    throw new RangeError("header field has the wrong length");
  }
  const out = concat(h.salt, u32be(h.argon.m), u32be(h.argon.t), u32be(h.argon.p), h.wrapIv, h.wrappedEk, h.noncePrefix);
  if (out.length !== HEADER_LEN) throw new RangeError("header is not 95 bytes");
  return out;
}

// Parses and bounds-checks the Argon2 parameters, so a hostile blob is refused before any KDF runs.
export function parseHeader(blob: Uint8Array): Header {
  if (blob.length < HEADER_LEN) throw new ShhError("invalid_blob_length");
  const argon = checkArgon2Bounds({ m: readU32be(blob, 16), t: readU32be(blob, 20), p: readU32be(blob, 24) });
  return {
    salt: blob.slice(0, 16),
    argon,
    wrapIv: blob.slice(28, 40),
    wrappedEk: blob.slice(40, 88),
    noncePrefix: blob.slice(88, 95),
  };
}
