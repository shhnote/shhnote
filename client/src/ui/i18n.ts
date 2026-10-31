// Translations the server rendered into `<script type="application/json" data-i18n>`.
// Keep the key list in step with `UI_KEYS` in the server's web.rs.
export type UiKey =
  | "form-files-remove"
  | "result-copied"
  | "result-destroyed"
  | "result-chip-single"
  | "result-chip-multi"
  | "result-chip-expires"
  | "create-encrypting"
  | "create-uploading"
  | "create-error-empty"
  | "create-error-too-large"
  | "create-error-network"
  | "create-error-failed"
  | "create-error-wasm"
  | "reveal-fetching"
  | "reveal-decrypting"
  | "reveal-wrong-passphrase"
  | "reveal-single-view"
  | "reveal-expires-one"
  | "reveal-expires-many"
  | "reveal-download"
  | "reveal-error-network"
  | "reveal-error-corrupt"
  | "reveal-error-wasm"
  | "burn-working"
  | "report-working"
  | "report-error-invalid";

let strings: Partial<Record<UiKey, string>> | null = null;

export function t(key: UiKey, vars: Record<string, string | number> = {}): string {
  if (strings === null) {
    const block = document.querySelector<HTMLScriptElement>("script[data-i18n]");
    try {
      strings = block ? (JSON.parse(block.textContent ?? "{}") as Record<UiKey, string>) : {};
    } catch {
      strings = {};
    }
  }
  let text = strings[key] ?? key;
  for (const [name, value] of Object.entries(vars)) {
    text = text.replaceAll(`{${name}}`, String(value));
  }
  return text;
}
