import { concat, readU32be, u32be } from "./bytes.ts";
import { ShhError } from "./error.ts";

export const MANIFEST_VERSION = 1;
export const MAX_MANIFEST_LEN = 1024 * 1024;

export interface PayloadFile {
  // Untrusted display data on the receiving side; never use it as a path.
  name: string;
  type: string;
  bytes: Uint8Array;
}

export interface Payload {
  text: string | null;
  files: PayloadFile[];
}

export interface Manifest {
  v: number;
  text: string | null;
  files: { name: string; type: string; size: number }[];
}

const encoder = new TextEncoder();
// `ignoreBOM` keeps a byte order mark in the text, where JSON.parse refuses it like Rust does.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// A lone surrogate half: JSON.parse accepts the escape, but it is not a Unicode string.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// JSON.parse keeps the last of two duplicate keys and reads `1.0` as `1`. Two conforming
// clients would then disagree on one manifest, so the raw text is scanned for both first.
function checkManifestSyntax(text: string): void {
  const containers: ("object" | "array")[] = [];
  const keys: Set<string>[] = [];
  let afterSeparator = false; // just inside `{` or after a `,` in an object: a key comes next
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      if (afterSeparator && containers[containers.length - 1] === "object") {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        const seen = keys[keys.length - 1]!;
        if (seen.has(key)) throw new ShhError("manifest", "duplicate key");
        seen.add(key);
      }
      afterSeparator = false;
      i = j + 1;
    } else if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < text.length && /[-+0-9.eE]/.test(text[j]!)) j++;
      if (/[.eE]/.test(text.slice(i, j))) throw new ShhError("manifest", "non-integer number");
      afterSeparator = false;
      i = j;
    } else {
      if (c === "{") {
        containers.push("object");
        keys.push(new Set());
        afterSeparator = true;
      } else if (c === "[") {
        containers.push("array");
        afterSeparator = false;
      } else if (c === "}" || c === "]") {
        if (containers.pop() === "object") keys.pop();
        afterSeparator = false;
      } else if (c === ",") {
        afterSeparator = true;
      } else {
        afterSeparator = afterSeparator && /\s/.test(c);
      }
      i++;
    }
  }
}

// Key order matters: it is what the conformance vectors pin.
export function manifestJson(payload: Payload): string {
  const manifest: Manifest = {
    v: MANIFEST_VERSION,
    text: payload.text,
    files: payload.files.map((f) => ({ name: f.name, type: f.type, size: f.bytes.length })),
  };
  return JSON.stringify(manifest);
}

// `[manifest_len: u32 BE][manifest JSON][file bytes in manifest order]`
export function encodePayload(payload: Payload): Uint8Array<ArrayBuffer> {
  if (payload.text === null && payload.files.length === 0) throw new ShhError("empty_payload");
  const manifest = encoder.encode(manifestJson(payload));
  try {
    if (manifest.length > MAX_MANIFEST_LEN) throw new ShhError("payload_too_large");
    return concat(u32be(manifest.length), manifest, ...payload.files.map((f) => f.bytes));
  } finally {
    // The manifest holds the note's text; the copy above is the one that goes on.
    manifest.fill(0);
  }
}

// The manifest bytes to a checked manifest: the same shape the Rust core accepts, no more.
export function parseManifest(bytes: Uint8Array): Manifest {
  let manifest: Manifest;
  try {
    const text = decoder.decode(bytes);
    checkManifestSyntax(text);
    manifest = JSON.parse(text);
  } catch (e) {
    if (e instanceof ShhError) throw e;
    throw new ShhError("manifest", String(e));
  }
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    manifest.v !== MANIFEST_VERSION ||
    !(manifest.text === null || typeof manifest.text === "string") ||
    !Array.isArray(manifest.files)
  ) {
    throw new ShhError("manifest", "unexpected manifest shape");
  }
  if (manifest.text !== null && LONE_SURROGATE.test(manifest.text)) throw new ShhError("manifest", "lone surrogate");
  for (const meta of manifest.files) {
    if (
      typeof meta !== "object" ||
      meta === null ||
      typeof meta.name !== "string" ||
      typeof meta.type !== "string" ||
      !Number.isInteger(meta.size) ||
      meta.size < 0 ||
      LONE_SURROGATE.test(meta.name) ||
      LONE_SURROGATE.test(meta.type)
    ) {
      throw new ShhError("manifest", "bad file entry");
    }
  }
  return manifest;
}

export function decodePayload(bytes: Uint8Array): Payload {
  if (bytes.length < 4) throw new ShhError("corrupt", "payload too short");
  const manifestLen = readU32be(bytes, 0);
  if (manifestLen > MAX_MANIFEST_LEN) throw new ShhError("corrupt", "manifest too large");
  if (4 + manifestLen > bytes.length) throw new ShhError("corrupt", "manifest length exceeds payload");
  const manifest = parseManifest(bytes.subarray(4, 4 + manifestLen));
  if (manifest.text === null && manifest.files.length === 0) throw new ShhError("empty_payload");

  let at = 4 + manifestLen;
  const files: PayloadFile[] = [];
  for (const meta of manifest.files) {
    if (at + meta.size > bytes.length) throw new ShhError("corrupt", "file sizes exceed payload");
    files.push({ name: meta.name, type: meta.type, bytes: bytes.slice(at, at + meta.size) });
    at += meta.size;
  }
  if (at !== bytes.length) throw new ShhError("corrupt", "trailing bytes after the last file");
  return { text: manifest.text, files };
}
