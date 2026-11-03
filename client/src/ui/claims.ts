import { toBase64Url } from "../crypto/bytes.ts";
import { credentialHash } from "../crypto/secret.ts";

// The claim token of a single-view secret, kept so a reload of the reveal page can still
// download the secret it already claimed (SPEC §5.1). It lives in `sessionStorage`, so only
// this tab sees it and it ends with the tab, and only until the claim window closes. The key
// is `SHA-256(lookup)`, which is what the server stores anyway; the value is the token and
// its expiry. Nothing else about a secret is ever written to browser storage.

const PREFIX = "shh-claim:";

// The longest claim window an instance may set (SPEC §7.2), for when `/config` is unknown.
export const MAX_CLAIM_WINDOW_SECS = 86_400;

interface Entry {
  claimToken: string;
  expiresAt: number; // milliseconds since the epoch
}

function parse(text: string | null): Entry | null {
  if (text === null) return null;
  try {
    const value = JSON.parse(text) as Partial<Entry>;
    if (typeof value.claimToken === "string" && typeof value.expiresAt === "number") {
      return { claimToken: value.claimToken, expiresAt: value.expiresAt };
    }
  } catch {
    /* not ours */
  }
  return null;
}

// Privacy browsers may withhold storage or throw on any use of it; claims then simply do
// not survive a reload, as before.
function sessionStorageOrNull(): Storage | null {
  try {
    return globalThis.sessionStorage ?? null;
  } catch {
    return null;
  }
}

export class ClaimStore {
  private readonly storage: Storage | null;
  private readonly now: () => number;

  constructor(storage: Storage | null = sessionStorageOrNull(), now: () => number = Date.now) {
    this.storage = storage;
    this.now = now;
  }

  // The storage key for a secret, from its lookup value.
  static async keyFor(lookup: Uint8Array): Promise<string> {
    return PREFIX + toBase64Url(await credentialHash(lookup));
  }

  // The token, while its window is open; an expired or unreadable entry is removed.
  get(key: string): string | null {
    try {
      const entry = parse(this.storage?.getItem(key) ?? null);
      if (entry && entry.expiresAt > this.now()) return entry.claimToken;
      this.storage?.removeItem(key);
    } catch {
      /* storage unavailable */
    }
    return null;
  }

  set(key: string, claimToken: string, expiresAt: number): void {
    try {
      this.storage?.setItem(key, JSON.stringify({ claimToken, expiresAt } satisfies Entry));
    } catch {
      /* storage unavailable or full */
    }
  }

  delete(key: string): void {
    try {
      this.storage?.removeItem(key);
    } catch {
      /* storage unavailable */
    }
  }

  // Removes every claim whose window has closed, so nothing outlives it even if its page
  // never came back to confirm.
  prune(): void {
    try {
      const storage = this.storage;
      if (!storage) return;
      const keys: string[] = [];
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (key?.startsWith(PREFIX)) keys.push(key);
      }
      for (const key of keys) {
        const entry = parse(storage.getItem(key));
        if (!entry || entry.expiresAt <= this.now()) storage.removeItem(key);
      }
    } catch {
      /* storage unavailable */
    }
  }
}
