import { readU32be, u32be } from "./bytes.ts";
import { ShhError } from "./error.ts";

export const CHUNK_SIZE = 65536;
export const TAG_LEN = 16;
export const HEADER_LEN = 95;
export const LENGTH_PREFIX = 4;
export const DEFAULT_PADDING_MIN = 64 * 1024;

// How an instance rounds payloads up (SPEC §6.2); served by GET /config.
export type PaddingPolicy = { mode: "padme"; min: number } | { mode: "buckets"; ladder: number[] };

// Padmé (Nikitin et al., PURBs 2019): keeps the top few bits of the length. BigInt keeps the
// arithmetic exact above 2^31, where JavaScript's bitwise operators would break.
export function padme(len: number): number {
  if (len < 2) return len;
  const L = BigInt(len);
  const e = BigInt(L.toString(2).length - 1);
  const s = BigInt(e.toString(2).length);
  const mask = (1n << (e - s)) - 1n;
  return Number((L + mask) & ~mask);
}

export function paddedSize(len: number, policy: PaddingPolicy): number | null {
  if (policy.mode === "padme") return padme(Math.max(len, policy.min));
  return policy.ladder.find((b) => b >= len) ?? null;
}

export function isValidPaddedSize(size: number, policy: PaddingPolicy): boolean {
  if (policy.mode === "padme") return size >= policy.min && padme(size) === size;
  return policy.ladder.includes(size);
}

export function chunkCount(bucket: number): number {
  return Math.max(1, Math.ceil(bucket / CHUNK_SIZE));
}

export function blobLen(bucket: number): number {
  return HEADER_LEN + bucket + TAG_LEN * chunkCount(bucket);
}

// `[payload_len: u32 BE][payload][0x00 fill]`, sized by the policy.
export function pad(payload: Uint8Array, policy: PaddingPolicy): Uint8Array<ArrayBuffer> {
  if (payload.length > 0xffffffff) throw new ShhError("payload_too_large");
  const bucket = paddedSize(payload.length + LENGTH_PREFIX, policy);
  if (bucket === null) throw new ShhError("payload_too_large");
  // Written in place, so no other copy of the plaintext is left behind.
  const padded = new Uint8Array(bucket);
  padded.set(u32be(payload.length));
  padded.set(payload, LENGTH_PREFIX);
  return padded;
}

export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < LENGTH_PREFIX) throw new ShhError("corrupt", "padding too short");
  const len = readU32be(padded, 0);
  if (len > padded.length - LENGTH_PREFIX) throw new ShhError("corrupt", "length prefix exceeds the bucket");
  return padded.subarray(LENGTH_PREFIX, LENGTH_PREFIX + len);
}
