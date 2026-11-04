// Translations the server rendered into `<script type="application/json" data-shh-i18n>`.
// Keep the key list in step with `UI_KEYS` in the server's web.rs. Controllers never read
// this directly: they take a `Translate` so another frontend can supply its own strings,
// or use `createT` to read a block the frontend renders the same way.
export type UiKey =
  | "form-files-remove"
  | "result-destroyed"
  | "result-chip-single"
  | "result-chip-multi"
  | "result-chip-expires"
  | "create-encrypting"
  | "create-uploading"
  | "create-error-empty"
  | "create-error-too-large"
  | "create-error-text-too-long"
  | "create-error-network"
  | "create-error-failed"
  | "create-error-wasm"
  | "reveal-fetching"
  | "reveal-decrypting"
  | "reveal-wrong-passphrase"
  | "reveal-single-view"
  | "reveal-single-view-destroyed"
  | "reveal-download"
  | "reveal-error-network"
  | "reveal-error-busy"
  | "reveal-error-too-large"
  | "reveal-error-corrupt"
  | "reveal-error-wasm"
  | "burn-working"
  | "report-working"
  | "report-error-invalid"
  | "error-unsupported-protocol";

export type Translate = (key: UiKey, vars?: Record<string, string | number>) => string;

// What every controller takes besides its root element.
export interface Strings {
  t: Translate;
}

// A `Translate` over the strings block a server rendered into the page:
// `<script type="application/json" data-shh-i18n>{"key": "text", …}</script>`, looked up
// inside `root` first, then in the document. The block is read on first use, so the
// translator can be made before the page has finished loading. A missing block, invalid
// JSON or a missing key all fall back to the key itself, so a gap shows as a key, never as
// an empty label. `{name}` in a string is replaced by `vars.name`.
export function createT(root?: ParentNode): Translate {
  let strings: Partial<Record<UiKey, string>> | null = null;
  return (key, vars = {}) => {
    if (strings === null) {
      const selector = "script[data-shh-i18n]";
      const block =
        root?.querySelector<HTMLScriptElement>(selector) ??
        (typeof document === "undefined" ? null : document.querySelector<HTMLScriptElement>(selector));
      try {
        const parsed: unknown = block ? JSON.parse(block.textContent ?? "{}") : {};
        // `null` or an array parse fine but hold no strings; keys fall back like any gap.
        strings = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<UiKey, string>) : {};
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
}

// The built-in pages' translator (`main.ts`).
export const t: Translate = createT();
