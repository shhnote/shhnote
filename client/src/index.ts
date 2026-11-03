// `@shhnote/client` (package root): the protocol plus the API client and the frontend-safety
// helpers. No DOM; runs in browsers, Node and workers alike.
export * from "./crypto/index.ts";
export {
  type ClientOptions,
  type CreateOptions,
  type Created,
  type ParsedFragment,
  type RevealOptions,
  type RevealedSecret,
  burnSecret,
  createSecret,
  parseFragment,
  revealSecret,
} from "./client.ts";
export { isUserActivation } from "./lib/activation.ts";
export {
  Api,
  ApiError,
  DEFAULT_MAX_BLOB_BYTES,
  type Fetch,
  type InstanceConfig,
  type Lifetime,
  type Region,
  type Revealed,
  getConfig,
} from "./lib/api.ts";
export { loadArgon2, prefetchArgon2 } from "./lib/argon2-loader.ts";
export { sanitiseFileName } from "./lib/filename.ts";
export { wipeBytes, wipePayload } from "./lib/wipe.ts";
