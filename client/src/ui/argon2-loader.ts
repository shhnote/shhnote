import { Argon2 } from "../crypto/argon2.ts";

let loading: Promise<Argon2> | null = null;

// Fetched same-origin only when a passphrase is actually involved, and only once per page.
export function loadArgon2(): Promise<Argon2> {
  const version = document.body.dataset["assetVersion"] ?? "";
  loading ??= Argon2.fromResponse(fetch(`/static/argon2.wasm?v=${version}`, { cache: "force-cache" })).catch((e) => {
    loading = null;
    throw e;
  });
  return loading;
}
