export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function u32be(value: number): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`not a u32: ${value}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function readU32be(bytes: Uint8Array, at: number): number {
  if (at + 4 > bytes.length) throw new RangeError("read past end");
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at, false);
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// Copies into a fresh ArrayBuffer-backed array; Web Crypto rejects shared or detached buffers.
export function own(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i]));

// base64url without padding (RFC 4648 §5), the encoding used in fragments and API bodies.
export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += B64URL[(triple >> 18) & 63]! + B64URL[(triple >> 12) & 63]!;
    out += i + 1 < bytes.length ? B64URL[(triple >> 6) & 63]! : "";
    out += i + 2 < bytes.length ? B64URL[triple & 63]! : "";
  }
  return out;
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (text.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let buffer = 0;
  let at = 0;
  for (const ch of text) {
    const value = B64URL_INDEX.get(ch);
    if (value === undefined) return null;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (buffer >> bits) & 0xff;
    }
  }
  // Leftover bits must be zero, otherwise two different strings would decode to the same bytes.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null;
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) throw new RangeError("bad hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}
