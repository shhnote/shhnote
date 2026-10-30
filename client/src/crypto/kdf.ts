import { own } from "./bytes.ts";
import { ShhError } from "./error.ts";

const encoder = new TextEncoder();

// Frozen: changing any of these is a new fragment version (SPEC §2.3, §2.13).
export const INFO = {
  lookup: encoder.encode("shhnote/lookup/v1"),
  kekDirect: encoder.encode("shhnote/kek-direct/v1"),
  kekPass: encoder.encode("shhnote/kek-pass/v1"),
} as const;

export const SALT_LEN = 16;

// `m` is in KiB (SPEC §2.9).
export interface Argon2Params {
  m: number;
  t: number;
  p: number;
}

export const ARGON2_DEFAULT: Argon2Params = { m: 64 * 1024, t: 3, p: 1 };
export const ARGON2_MIN: Argon2Params = { m: 8 * 1024, t: 1, p: 1 };
export const ARGON2_MAX: Argon2Params = { m: 256 * 1024, t: 8, p: 4 };

// A blob can name any cost it likes, so this runs before the KDF ever does.
export function checkArgon2Bounds(params: Argon2Params): Argon2Params {
  const within = (v: number, lo: number, hi: number) => Number.isInteger(v) && v >= lo && v <= hi;
  if (
    !within(params.m, ARGON2_MIN.m, ARGON2_MAX.m) ||
    !within(params.t, ARGON2_MIN.t, ARGON2_MAX.t) ||
    !within(params.p, ARGON2_MIN.p, ARGON2_MAX.p)
  ) {
    throw new ShhError("argon2_out_of_bounds");
  }
  return params;
}

const subtle = globalThis.crypto.subtle;

async function hkdfBase(ikm: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", own(ikm), "HKDF", false, ["deriveBits", "deriveKey"]);
}

// Empty salt: Web Crypto hands it to RFC 5869, which treats it as HashLen zero bytes.
function hkdfAlgorithm(info: Uint8Array): HkdfParams {
  return { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: own(info) };
}

export async function hkdfBits(ikm: Uint8Array, info: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const key = await hkdfBase(ikm);
  return new Uint8Array(await subtle.deriveBits(hkdfAlgorithm(info), key, 256));
}

// Derives a non-extractable AES-256-GCM key straight from HKDF, so the KEK never exists as bytes in JavaScript.
export async function hkdfAesKey(ikm: Uint8Array, info: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  const key = await hkdfBase(ikm);
  return subtle.deriveKey(hkdfAlgorithm(info), key, { name: "AES-GCM", length: 256 }, false, usages);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle.digest("SHA-256", own(bytes)));
}
