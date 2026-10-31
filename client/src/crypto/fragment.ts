import { concat, fromBase64Url, toBase64Url } from "./bytes.ts";
import { ShhError } from "./error.ts";

// The only suite defined so far (SPEC §2). The kind byte names the suite and the link's role.
export const VERSION = 1;
export const FRAGMENT_CHARS = 44;

// Which link a fragment belongs to. A burn fragment must be told apart from a share fragment
// before anything is derived or sent (D-2), so the two have different first bytes.
export type Kind = "share" | "burn";

const KIND_BYTES: Record<Kind, number> = { share: 0x01, burn: 0x02 };

function kindOf(byte: number): Kind | null {
  if (byte === KIND_BYTES.share) return "share";
  if (byte === KIND_BYTES.burn) return "burn";
  return null;
}

// What a share or burn link carries after `#`: a kind byte and 32 bytes of random material.
export function encodeFragment(bytes: Uint8Array, kind: Kind = "share"): string {
  if (bytes.length !== 32) throw new RangeError("fragment material must be 32 bytes");
  return toBase64Url(concat(new Uint8Array([KIND_BYTES[kind]]), bytes));
}

// Accepts only the exact shape and only the expected kind: a share link given to the burn
// page, or the other way round, is refused before anything is derived from it.
export function decodeFragment(text: string, kind: Kind = "share"): Uint8Array<ArrayBuffer> {
  const body = text.startsWith("#") ? text.slice(1) : text;
  if (body.length !== FRAGMENT_CHARS) throw new ShhError("invalid_fragment");
  const raw = fromBase64Url(body);
  if (raw === null || raw.length !== 33) throw new ShhError("invalid_fragment");
  const first = raw[0] ?? -1;
  const found = kindOf(first);
  if (found === null) throw new ShhError("unsupported_version", `version ${first}`);
  if (found !== kind) throw new ShhError("wrong_kind", `a ${found} link was given where a ${kind} link was expected`);
  return raw.slice(1);
}
