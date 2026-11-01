// `@shhnote/client/crypto`: the pure protocol (SPEC §2). No fetch, no DOM; what the
// conformance vectors test.
export { Argon2 } from "./argon2.ts";
export { type Header, parseHeader, serializeHeader } from "./blob.ts";
export { fromBase64Url, toBase64Url } from "./bytes.ts";
export { type Manifest, type Payload, type PayloadFile, decodePayload, encodePayload, parseManifest } from "./container.ts";
export { type ErrorCode, ShhError } from "./error.ts";
export { type Kind, VERSION, decodeFragment, encodeFragment } from "./fragment.ts";
export { ARGON2_DEFAULT, type Argon2Params, checkArgon2Bounds } from "./kdf.ts";
export { CHUNK_SIZE, HEADER_LEN, type PaddingPolicy, blobLen, isValidPaddedSize, pad, padme, unpad } from "./padding.ts";
export {
  type EncryptOptions,
  type Encrypted,
  type Randomness,
  credentialHash,
  decrypt,
  decryptBody,
  decryptStream,
  encrypt,
  generateRandomness,
  lookup,
  unwrapEk,
} from "./secret.ts";
export { PayloadDecoder, collect, iterateBytes, iterateStream, openStream, readHeader } from "./stream.ts";
