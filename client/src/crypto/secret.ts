import type { Argon2 } from "./argon2.ts";
import { type Header, NONCE_PREFIX_LEN, WRAP_IV_LEN, serializeHeader } from "./blob.ts";
import { concat, own } from "./bytes.ts";
import { sealAll } from "./chunks.ts";
import { type Payload, encodePayload } from "./container.ts";
import { ShhError } from "./error.ts";
import { encodeFragment } from "./fragment.ts";
import { ARGON2_DEFAULT, type Argon2Params, INFO, SALT_LEN, checkArgon2Bounds, hkdfAesKey, hkdfBits, sha256 } from "./kdf.ts";
import { HEADER_LEN, type PaddingPolicy, blobLen, pad } from "./padding.ts";
import { PayloadDecoder, iterateBytes, openStream, readHeader } from "./stream.ts";

const subtle = globalThis.crypto.subtle;

// Every random value a secret needs. Tests inject the conformance vectors' fixed values;
// real callers use `generateRandomness`.
export interface Randomness {
  seed: Uint8Array;
  burnToken: Uint8Array;
  ek: CryptoKey;
  salt: Uint8Array;
  wrapIv: Uint8Array;
  noncePrefix: Uint8Array;
}

function random(len: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(len));
}

// The content key must be extractable for `wrapKey` to accept it; nothing ever exports it.
export async function importEk(bytes: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", own(bytes), { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
}

export async function generateRandomness(): Promise<Randomness> {
  return {
    seed: random(32),
    burnToken: random(32),
    ek: await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]),
    salt: random(SALT_LEN),
    wrapIv: random(WRAP_IV_LEN),
    noncePrefix: random(NONCE_PREFIX_LEN),
  };
}

// What the creating client ends up with: the blob to upload, the values the server stores,
// and the material for the two links.
export interface Encrypted {
  blob: Uint8Array<ArrayBuffer>;
  bucket: number;
  fragment: string;
  burnFragment: string;
  lookupKey: Uint8Array<ArrayBuffer>;
  burnKey: Uint8Array<ArrayBuffer>;
}

// The value a client sends to find a secret; the server stores only `credentialHash` of it.
export function lookup(seed: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return hkdfBits(seed, INFO.lookup);
}

export const credentialHash = sha256;

function kekDirect(seed: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return hkdfAesKey(seed, INFO.kekDirect, usages);
}

function kekPass(seed: Uint8Array, passphrase: string, salt: Uint8Array, argon: Argon2Params, argon2: Argon2, usages: KeyUsage[]): Promise<CryptoKey> {
  const passKey = argon2.hash(passphrase, salt, argon);
  const ikm = concat(seed, passKey);
  passKey.fill(0);
  return hkdfAesKey(ikm, INFO.kekPass, usages).finally(() => ikm.fill(0));
}

export interface EncryptOptions {
  randomness: Randomness;
  payload: Payload;
  policy: PaddingPolicy;
  passphrase?: string | null;
  argon?: Argon2Params;
  // Required when a passphrase is set.
  argon2?: Argon2;
}

export async function encrypt(opts: EncryptOptions): Promise<Encrypted> {
  const { randomness: r } = opts;
  const argon = checkArgon2Bounds(opts.argon ?? ARGON2_DEFAULT);
  let kek: CryptoKey;
  // "" is never "no passphrase": omit the option to mean direct mode (SPEC §2.10).
  if (opts.passphrase === "") throw new ShhError("empty_passphrase");
  if (opts.passphrase) {
    if (!opts.argon2) throw new ShhError("argon2_unavailable", "a passphrase needs the Argon2 module");
    kek = await kekPass(r.seed, opts.passphrase, r.salt, argon, opts.argon2, ["wrapKey"]);
  } else {
    kek = await kekDirect(r.seed, ["wrapKey"]);
  }
  const header: Header = {
    salt: r.salt,
    // In direct mode these are filler; the layout stays identical to a passphrase blob.
    argon,
    wrapIv: r.wrapIv,
    wrappedEk: new Uint8Array(await subtle.wrapKey("raw", r.ek, kek, { name: "AES-GCM", iv: own(r.wrapIv) })),
    noncePrefix: r.noncePrefix,
  };

  const padded = pad(encodePayload(opts.payload), opts.policy);
  const body = await sealAll(r.ek, r.noncePrefix, padded);
  padded.fill(0);
  const blob = concat(serializeHeader(header), body);
  if (blob.length !== blobLen(padded.length)) throw new Error("blob length mismatch");

  return {
    blob,
    bucket: padded.length,
    fragment: encodeFragment(r.seed, "share"),
    burnFragment: encodeFragment(r.burnToken, "burn"),
    lookupKey: await credentialHash(await lookup(r.seed)),
    burnKey: await credentialHash(r.burnToken),
  };
}

async function unwrap(kek: CryptoKey, header: Header): Promise<CryptoKey | null> {
  try {
    return await subtle.unwrapKey("raw", own(header.wrappedEk), kek, { name: "AES-GCM", iv: own(header.wrapIv) }, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  } catch {
    return null;
  }
}

// SPEC §2.10 steps 3–4: the content key from the header alone. Tries direct mode first; a
// failed unwrap is the only signal that a passphrase is needed, and a wrong passphrase costs
// no server round trip, since only the header is needed to try again.
export async function unwrapEk(header: Header, seed: Uint8Array, passphrase?: string | null, argon2?: Argon2): Promise<CryptoKey> {
  if (passphrase === "") throw new ShhError("empty_passphrase");
  const direct = await unwrap(await kekDirect(seed, ["unwrapKey"]), header);
  if (direct !== null) return direct;
  if (!passphrase) throw new ShhError("passphrase_required");
  if (!argon2) throw new ShhError("argon2_unavailable", "a passphrase needs the Argon2 module");
  const ek = await unwrap(await kekPass(seed, passphrase, header.salt, header.argon, argon2, ["unwrapKey"]), header);
  if (ek === null) throw new ShhError("wrong_passphrase");
  return ek;
}

// SPEC §2.10 steps 5–6 over a stream: chunks are opened and the payload assembled as the
// bytes arrive; each plaintext chunk is wiped once consumed. `maxBlobBytes` is the most the
// blob may be (the instance's limit, or the Content-Length), and bounds what the payload
// may claim.
export async function decryptBody(ek: CryptoKey, header: Header, body: AsyncIterable<Uint8Array>, maxBlobBytes = Infinity): Promise<Payload> {
  const decoder = new PayloadDecoder(maxBlobBytes - HEADER_LEN);
  for await (const chunk of openStream(ek, header.noncePrefix, body)) {
    try {
      decoder.push(chunk);
    } finally {
      chunk.fill(0);
    }
  }
  return decoder.finish();
}

// The whole of SPEC §2.10 over a stream of blob bytes.
export async function decryptStream(body: AsyncIterable<Uint8Array>, seed: Uint8Array, passphrase?: string | null, argon2?: Argon2, maxBlobBytes = Infinity): Promise<Payload> {
  // Refused before anything is read, whatever mode the blob turns out to be in.
  if (passphrase === "") throw new ShhError("empty_passphrase");
  const { header, rest } = await readHeader(body);
  const ek = await unwrapEk(header, seed, passphrase, argon2);
  return decryptBody(ek, header, rest, maxBlobBytes);
}

// The same pipeline over a blob already in memory. No cap: the blob is already in memory,
// and a short one fails on its length, which says more than a refused prefix would.
export function decrypt(blob: Uint8Array, seed: Uint8Array, passphrase?: string | null, argon2?: Argon2): Promise<Payload> {
  return decryptStream(iterateBytes(blob), seed, passphrase, argon2);
}
