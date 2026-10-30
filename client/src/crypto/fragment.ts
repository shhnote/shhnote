import { concat, fromBase64Url, toBase64Url } from "./bytes.ts";
import { ShhError } from "./error.ts";

// The only suite defined so far (SPEC §2).
export const VERSION = 1;
export const FRAGMENT_CHARS = 44;

// What a share or burn link carries after `#`: a version byte and 32 bytes of random material.
export function encodeFragment(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new RangeError("fragment material must be 32 bytes");
  return toBase64Url(concat(new Uint8Array([VERSION]), bytes));
}

// Accepts only the exact shape; a fragment of any other length is not ours.
export function decodeFragment(text: string): Uint8Array<ArrayBuffer> {
  const body = text.startsWith("#") ? text.slice(1) : text;
  if (body.length !== FRAGMENT_CHARS) throw new ShhError("invalid_fragment");
  const raw = fromBase64Url(body);
  if (raw === null || raw.length !== 33) throw new ShhError("invalid_fragment");
  if (raw[0] !== VERSION) throw new ShhError("unsupported_version", `version ${raw[0]}`);
  return raw.slice(1);
}
