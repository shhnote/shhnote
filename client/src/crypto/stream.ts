import { type Header, parseHeader } from "./blob.ts";
import { concat, readU32be } from "./bytes.ts";
import { openChunk } from "./chunks.ts";
import { MAX_MANIFEST_LEN, type Manifest, type Payload, type PayloadFile, parseManifest } from "./container.ts";
import { ShhError } from "./error.ts";
import { CHUNK_SIZE, HEADER_LEN, TAG_LEN } from "./padding.ts";

// Decryption as a pipeline (SPEC §2.7, §10): sealed chunks are opened as they arrive and the
// payload is assembled piece by piece, so memory stays around the chunk size plus the files
// themselves, never the whole blob several times over.

// A `ReadableStream` as an async iterable, without relying on the stream being iterable
// itself (Safari's is not).
export async function* iterateStream(stream: ReadableStream<Uint8Array>): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

export function iterateBytes(bytes: Uint8Array): AsyncIterable<Uint8Array> {
  return (async function* () {
    yield bytes;
  })();
}

export async function collect(body: AsyncIterable<Uint8Array>): Promise<Uint8Array<ArrayBuffer>> {
  const parts: Uint8Array[] = [];
  for await (const piece of body) parts.push(piece);
  return concat(...parts);
}

// Takes the 95-byte header off the front of a body; the rest keeps streaming.
export async function readHeader(body: AsyncIterable<Uint8Array>): Promise<{ header: Header; rest: AsyncIterable<Uint8Array> }> {
  const source = body[Symbol.asyncIterator]();
  let buffered: Uint8Array = new Uint8Array(0);
  while (buffered.length < HEADER_LEN) {
    const { value, done } = await source.next();
    if (done) throw new ShhError("invalid_blob_length");
    buffered = buffered.length === 0 ? value : concat(buffered, value);
  }
  const header = parseHeader(buffered.subarray(0, HEADER_LEN));
  const leftover = buffered.subarray(HEADER_LEN);
  const rest = (async function* () {
    if (leftover.length > 0) yield leftover;
    for (;;) {
      const { value, done } = await source.next();
      if (done) return;
      yield value;
    }
  })();
  return { header, rest };
}

// Opens sealed chunks in order. One unit is always held back, so the final chunk is the one
// opened with the last flag: a body that ends mid-chunk, on a boundary without a last
// chunk, or with fewer bytes than a tag fails here (SPEC §2.7).
export async function* openStream(ek: CryptoKey, prefix: Uint8Array, body: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array<ArrayBuffer>> {
  const sealedLen = CHUNK_SIZE + TAG_LEN;
  let pending: Uint8Array = new Uint8Array(0);
  let index = 0;
  for await (const piece of body) {
    pending = pending.length === 0 ? piece : concat(pending, piece);
    while (pending.length > sealedLen) {
      const sealed = pending.subarray(0, sealedLen);
      yield await openChunk(ek, prefix, index++, false, sealed);
      pending = pending.subarray(sealedLen);
    }
  }
  if (pending.length < TAG_LEN) throw new ShhError("invalid_blob_length");
  yield await openChunk(ek, prefix, index, true, pending);
}

// Assembles the payload from padded plaintext as it arrives:
// `[payload_len][manifest_len][manifest][files…][zero fill]` (SPEC §2.5, §2.6).
export class PayloadDecoder {
  // The most payload the bucket can hold; a length prefix above it is a lie, and refusing it
  // here keeps a hostile manifest from reserving memory it never fills.
  private readonly maxPayload: number;
  private stage: "payload_len" | "manifest_len" | "manifest" | "files" | "done" = "payload_len";
  private buffered = new Uint8Array(0);
  private payloadLen = 0;
  private consumed = 0; // payload bytes seen, after the 4-byte length prefix
  private manifestLen = 0;
  private manifest: Manifest | null = null;
  private files: PayloadFile[] = [];
  private fileAt = 0;
  private fileOffset = 0;

  constructor(maxPayload = Infinity) {
    this.maxPayload = maxPayload;
  }

  push(chunk: Uint8Array): void {
    let at = 0;
    while (at < chunk.length && this.stage !== "done") {
      switch (this.stage) {
        case "payload_len": {
          at = this.fill(chunk, at, 4);
          if (this.buffered.length === 4) {
            this.payloadLen = readU32be(this.buffered, 0);
            this.buffered = new Uint8Array(0);
            if (this.payloadLen < 4) throw new ShhError("corrupt", "payload too short");
            if (this.payloadLen > this.maxPayload) throw new ShhError("corrupt", "length prefix exceeds the bucket");
            this.stage = "manifest_len";
          }
          break;
        }
        case "manifest_len": {
          at = this.fill(chunk, at, 4);
          if (this.buffered.length === 4) {
            this.manifestLen = readU32be(this.buffered, 0);
            this.buffered = new Uint8Array(0);
            this.consumed += 4;
            if (this.manifestLen > MAX_MANIFEST_LEN) throw new ShhError("corrupt", "manifest too large");
            if (4 + this.manifestLen > this.payloadLen) throw new ShhError("corrupt", "manifest length exceeds payload");
            this.stage = "manifest";
          }
          break;
        }
        case "manifest": {
          at = this.fill(chunk, at, this.manifestLen);
          if (this.buffered.length === this.manifestLen) {
            try {
              this.manifest = parseManifest(this.buffered);
            } finally {
              // The manifest holds the note's text; the parsed string is what goes on.
              this.buffered.fill(0);
              this.buffered = new Uint8Array(0);
            }
            this.consumed += this.manifestLen;
            const remaining = this.payloadLen - this.consumed;
            const total = this.manifest.files.reduce((n, f) => n + f.size, 0);
            if (total > remaining) throw new ShhError("corrupt", "file sizes exceed payload");
            if (total < remaining) throw new ShhError("corrupt", "trailing bytes after the last file");
            this.files = this.manifest.files.map((f) => ({ name: f.name, type: f.type, bytes: new Uint8Array(f.size) }));
            this.stage = this.files.length === 0 ? "done" : "files";
            this.skipEmptyFiles();
          }
          break;
        }
        case "files": {
          const file = this.files[this.fileAt]!;
          const take = Math.min(file.bytes.length - this.fileOffset, chunk.length - at);
          file.bytes.set(chunk.subarray(at, at + take), this.fileOffset);
          this.fileOffset += take;
          this.consumed += take;
          at += take;
          if (this.fileOffset === file.bytes.length) {
            this.fileAt++;
            this.fileOffset = 0;
            this.skipEmptyFiles();
          }
          break;
        }
      }
    }
    // Whatever follows the payload is zero fill, and nothing of it is kept.
  }

  // Empty files have no bytes to wait for; the decoder must not stall on them.
  private skipEmptyFiles(): void {
    while (this.fileAt < this.files.length && this.files[this.fileAt]!.bytes.length === 0) this.fileAt++;
    if (this.fileAt >= this.files.length) this.stage = "done";
  }

  private fill(chunk: Uint8Array, at: number, want: number): number {
    const take = Math.min(want - this.buffered.length, chunk.length - at);
    const next = this.buffered.length === 0 ? chunk.slice(at, at + take) : concat(this.buffered, chunk.subarray(at, at + take));
    // A field split across chunks is joined into a new buffer; the old partial copy goes.
    this.buffered.fill(0);
    this.buffered = next;
    return at + take;
  }

  finish(): Payload {
    if (this.stage !== "done" || this.manifest === null) {
      throw new ShhError("corrupt", this.stage === "payload_len" ? "padding too short" : "length prefix exceeds the bucket");
    }
    if (this.manifest.text === null && this.files.length === 0) throw new ShhError("empty_payload");
    return { text: this.manifest.text, files: this.files };
  }
}
