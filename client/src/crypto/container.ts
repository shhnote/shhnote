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

interface Manifest {
  v: number;
  text: string | null;
  files: { name: string; type: string; size: number }[];
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

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
  if (manifest.length > MAX_MANIFEST_LEN) throw new ShhError("payload_too_large");
  return concat(u32be(manifest.length), manifest, ...payload.files.map((f) => f.bytes));
}

export function decodePayload(bytes: Uint8Array): Payload {
  if (bytes.length < 4) throw new ShhError("corrupt", "payload too short");
  const manifestLen = readU32be(bytes, 0);
  if (manifestLen > MAX_MANIFEST_LEN) throw new ShhError("corrupt", "manifest too large");
  if (4 + manifestLen > bytes.length) throw new ShhError("corrupt", "manifest length exceeds payload");

  let manifest: Manifest;
  try {
    manifest = JSON.parse(decoder.decode(bytes.subarray(4, 4 + manifestLen)));
  } catch (e) {
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
  if (manifest.text === null && manifest.files.length === 0) throw new ShhError("empty_payload");

  let at = 4 + manifestLen;
  const files: PayloadFile[] = [];
  for (const meta of manifest.files) {
    if (typeof meta.name !== "string" || typeof meta.type !== "string" || !Number.isInteger(meta.size) || meta.size < 0) {
      throw new ShhError("manifest", "bad file entry");
    }
    if (at + meta.size > bytes.length) throw new ShhError("corrupt", "file sizes exceed payload");
    files.push({ name: meta.name, type: meta.type, bytes: bytes.slice(at, at + meta.size) });
    at += meta.size;
  }
  if (at !== bytes.length) throw new ShhError("corrupt", "trailing bytes after the last file");
  return { text: manifest.text, files };
}
