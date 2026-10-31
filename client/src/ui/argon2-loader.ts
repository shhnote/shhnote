import { Argon2 } from "../crypto/argon2.ts";
import { ShhError } from "../crypto/error.ts";

let loading: Promise<Argon2> | null = null;

// Fetched same-origin, once per page. Every create and reveal page fetches it, whether or
// not a passphrase is involved, so the fetch says nothing about passphrase use (D-22).
export function prefetchArgon2(): void {
  loadArgon2().catch(() => {});
}

export function loadArgon2(): Promise<Argon2> {
  // Tor Browser at "Safer" and some hardened profiles switch WebAssembly off; the pages say
  // so rather than reporting a corrupt secret (SPEC §10).
  if (typeof WebAssembly === "undefined") return Promise.reject(new ShhError("argon2_unavailable", "WebAssembly is not available"));
  const version = document.body.dataset["assetVersion"] ?? "";
  loading ??= Argon2.fromResponse(fetch(`/static/argon2.wasm?v=${version}`, { cache: "force-cache" })).catch((e) => {
    loading = null;
    if (e instanceof WebAssembly.CompileError) throw new ShhError("argon2_unavailable", "WebAssembly is blocked");
    throw e;
  });
  return loading;
}
