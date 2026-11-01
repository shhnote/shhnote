import { Argon2 } from "../crypto/argon2.ts";
import { ShhError } from "../crypto/error.ts";

// One instance per module URL, shared by every caller on the page.
const loading = new Map<string, Promise<Argon2>>();

// Fetched same-origin, once per page. Every create and reveal page fetches it, whether or
// not a passphrase is involved, so the fetch says nothing about passphrase use (D-22).
// `url` is where the instance serves the module (`/static/argon2.wasm?v=…`).
export function prefetchArgon2(url: string): void {
  loadArgon2(url).catch(() => {});
}

export function loadArgon2(url: string): Promise<Argon2> {
  // Tor Browser at "Safer" and some hardened profiles switch WebAssembly off; the pages say
  // so rather than reporting a corrupt secret (SPEC §10).
  if (typeof WebAssembly === "undefined") return Promise.reject(new ShhError("argon2_unavailable", "WebAssembly is not available"));
  let pending = loading.get(url);
  if (!pending) {
    pending = Argon2.fromResponse(fetch(url, { cache: "force-cache" })).catch((e) => {
      loading.delete(url);
      if (e instanceof WebAssembly.CompileError) throw new ShhError("argon2_unavailable", "WebAssembly is blocked");
      throw e;
    });
    loading.set(url, pending);
  }
  return pending;
}
