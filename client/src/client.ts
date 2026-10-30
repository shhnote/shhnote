import type { Argon2 } from "./crypto/argon2.ts";
import type { Payload } from "./crypto/container.ts";
import { ShhError } from "./crypto/error.ts";
import { decodeFragment } from "./crypto/fragment.ts";
import { decrypt, encrypt, generateRandomness, lookup } from "./crypto/secret.ts";
import { Api, type Fetch, type Lifetime } from "./ui/api.ts";

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
  passphrase?: string | null;
}

export interface Created {
  // Append to "<site>/s#" and "<site>/burn#" to make the links.
  fragment: string;
  burnFragment: string;
}

export async function createSecret(opts: CreateOptions): Promise<Created> {
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

// Accepts a full link, a bare fragment or "#fragment"; throws `invalid_fragment` otherwise.
export function parseFragment(linkOrFragment: string): ParsedFragment {
  const hash = linkOrFragment.includes("#") ? linkOrFragment.slice(linkOrFragment.indexOf("#")) : linkOrFragment;
  return { seed: decodeFragment(hash) };
}

export interface RevealOptions extends ClientOptions {
  passphrase?: string | null;
  // Set to false to keep a single-view secret downloadable until its claim window ends.
  confirm?: boolean;
}

export interface RevealedSecret {
  payload: Payload;
  singleView: boolean;
  expiresInHours: number | null;
}

// Fetches and decrypts. A single-view secret is consumed by this call; by default the
// server is told to destroy it right away once decryption succeeded.
export async function revealSecret(linkOrFragment: string, opts: RevealOptions): Promise<RevealedSecret> {
  if (opts.passphrase && !opts.argon2) throw new ShhError("argon2_unavailable", "a passphrase needs an Argon2 instance");
  const { seed } = parseFragment(linkOrFragment);
  const api = new Api(opts.apiBase, opts.fetch);
  const revealed = await api.reveal(await lookup(seed));
  const payload = await decrypt(revealed.blob, seed, opts.passphrase ?? null, opts.argon2);
  if (revealed.claimToken !== null && opts.confirm !== false) {
    await api.confirm(await lookup(seed), revealed.claimToken);
  }
  return { payload, singleView: revealed.claimToken !== null, expiresInHours: revealed.expiresInHours };
}

// Takes the burn link or its fragment; resolves on success, throws `ApiError` 404 otherwise.
export async function burnSecret(linkOrBurnFragment: string, opts: ClientOptions): Promise<void> {
  const { seed: token } = parseFragment(linkOrBurnFragment);
  await new Api(opts.apiBase, opts.fetch).burn(token);
}
