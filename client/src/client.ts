import type { Argon2 } from "./crypto/argon2.ts";
import type { Payload } from "./crypto/container.ts";
import { ShhError } from "./crypto/error.ts";
import { type Kind, decodeFragment } from "./crypto/fragment.ts";
import { decryptStream, encrypt, generateRandomness, lookup } from "./crypto/secret.ts";
import { Api, ApiError, type Fetch, type Lifetime } from "./ui/api.ts";

// The whole flow in four calls, for integrations outside the website: scripts, bots,
// password managers. Nothing here touches the DOM; pass your own fetch where needed.
export interface ClientOptions {
  // The instance's API base, e.g. "https://example.com/api" or "https://api.example.com".
  apiBase: string;
  fetch?: Fetch;
  // Needed only for passphrase-protected secrets: `await Argon2.load(wasmBytes)`.
  argon2?: Argon2;
}

export interface CreateOptions extends ClientOptions {
  payload: Payload;
  lifetime: Lifetime;
  ttlSeconds: number;
  // A non-empty string, or omitted/null for no passphrase; "" is an error.
  passphrase?: string | null;
}

export interface Created {
  // Append to "<site>/s#" and "<site>/burn#" to make the links.
  fragment: string;
  burnFragment: string;
}

export async function createSecret(opts: CreateOptions): Promise<Created> {
  if (opts.passphrase === "") throw new ShhError("empty_passphrase", "omit the passphrase to mean direct mode");
  if (opts.passphrase && !opts.argon2) throw new ShhError("argon2_unavailable", "a passphrase needs an Argon2 instance");
  const api = new Api(opts.apiBase, opts.fetch);
  const [config, randomness] = await Promise.all([api.config(), generateRandomness()]);
  const encrypted = await encrypt({
    randomness,
    payload: opts.payload,
    policy: config.padding,
    passphrase: opts.passphrase ?? null,
    ...(opts.argon2 ? { argon2: opts.argon2 } : {}),
  });
  if (encrypted.blob.length > config.max_blob_bytes) throw new ShhError("payload_too_large");
  await api.create(
    { lookupKey: encrypted.lookupKey, burnKey: encrypted.burnKey, lifetime: opts.lifetime, ttlSeconds: opts.ttlSeconds },
    encrypted.blob,
  );
  return { fragment: encrypted.fragment, burnFragment: encrypted.burnFragment };
}

export interface ParsedFragment {
  seed: Uint8Array;
}

// Accepts a full link, a bare fragment or "#fragment"; throws `invalid_fragment` otherwise, and
// `wrong_kind` when the fragment belongs to the other link (a burn link where a share link was
// expected, or the other way round).
export function parseFragment(linkOrFragment: string, kind: Kind = "share"): ParsedFragment {
  const hash = linkOrFragment.includes("#") ? linkOrFragment.slice(linkOrFragment.indexOf("#")) : linkOrFragment;
  return { seed: decodeFragment(hash, kind) };
}

export interface RevealOptions extends ClientOptions {
  passphrase?: string | null;
  // Set to false to keep a single-view secret downloadable until its claim window ends.
  confirm?: boolean;
  // A token from an earlier attempt (the `claimToken` on a result or on an error): the
  // secret is downloaded again with it instead of a fresh reveal, which a single-view
  // secret would refuse.
  claimToken?: string | null;
  // The most blob bytes to accept; the instance's `max_blob_bytes` from `/config`.
  maxBlobBytes?: number;
}

export interface RevealedSecret {
  payload: Payload;
  // True when this call consumed the secret. A TTL secret says nothing about how long it
  // stays readable; treat every secret as if this were the only read.
  singleView: boolean;
  // For a single-view secret that was not confirmed: lets the caller download it again
  // (`claimToken` in the options) or confirm later. Null otherwise.
  claimToken: string | null;
}

// Fetches and decrypts. A single-view secret is consumed by this call; by default the
// server is told to destroy it right away once decryption succeeded. Any failure after a
// single-view secret was claimed (a wrong passphrase, a dropped connection) carries the
// claim token, so a retry can pass it along rather than lose the secret.
export async function revealSecret(linkOrFragment: string, opts: RevealOptions): Promise<RevealedSecret> {
  if (opts.passphrase === "") throw new ShhError("empty_passphrase", "omit the passphrase to mean direct mode");
  if (opts.passphrase && !opts.argon2) throw new ShhError("argon2_unavailable", "a passphrase needs an Argon2 instance");
  const { seed } = parseFragment(linkOrFragment);
  const api = new Api(opts.apiBase, opts.fetch);
  const revealed = await api.reveal(await lookup(seed), opts.claimToken, opts.maxBlobBytes);
  const claimToken = revealed.claimToken ?? opts.claimToken ?? null;
  let payload: Payload;
  try {
    payload = await decryptStream(revealed.body, seed, opts.passphrase ?? null, opts.argon2, opts.maxBlobBytes ?? revealed.contentLength ?? undefined);
  } catch (e) {
    if (claimToken !== null && (e instanceof ShhError || e instanceof ApiError)) e.claimToken = claimToken;
    throw e;
  }
  if (claimToken !== null && opts.confirm !== false) {
    await api.confirm(await lookup(seed), claimToken);
    return { payload, singleView: true, claimToken: null };
  }
  return { payload, singleView: claimToken !== null, claimToken };
}

// Takes the burn link or its fragment; resolves on success, throws `ApiError` 404 otherwise.
// A share link is refused (`wrong_kind`) so the seed can never be sent as a burn token.
export async function burnSecret(linkOrBurnFragment: string, opts: ClientOptions): Promise<void> {
  const { seed: token } = parseFragment(linkOrBurnFragment, "burn");
  await new Api(opts.apiBase, opts.fetch).burn(token);
}
