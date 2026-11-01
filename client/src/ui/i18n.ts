// Translations the server rendered into `<script type="application/json" data-shh-i18n>`.
// Keep the key list in step with `UI_KEYS` in the server's web.rs. Controllers never read
// this directly: they take a `Translate` so another frontend can supply its own strings.
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
  | "reveal-download"
  | "reveal-error-network"
  | "reveal-error-corrupt"
  | "reveal-error-wasm"
  | "burn-working"
  | "report-working"
  | "report-error-invalid";

export type Translate = (key: UiKey, vars?: Record<string, string | number>) => string;

// What every controller takes besides its root element.
export interface Strings {
  t: Translate;
}

let strings: Partial<Record<UiKey, string>> | null = null;

export const t: Translate = (key, vars = {}) => {
  if (strings === null) {
    const block = document.querySelector<HTMLScriptElement>("script[data-shh-i18n]");
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
};
