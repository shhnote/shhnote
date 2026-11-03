import { Api, DEFAULT_MAX_BLOB_BYTES } from "../lib/api.ts";
import type { Strings } from "./i18n.ts";

// Small helpers so the flow code reads as what it does, not as DOM plumbing. Controllers
// find what they need by `data-shh-*` attributes, inside the root they are given; the
// instance facts (API base, limits, asset version) come from the nearest element that
// declares them, the `<body>` on the built-in pages.

export function $<T extends Element = HTMLElement>(selector: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`missing element: ${selector}`);
  return el;
}

export function $$<T extends Element = HTMLElement>(selector: string, root: ParentNode = document): T[] {
  return [...root.querySelectorAll<T>(selector)];
}

export function show(el: HTMLElement): void {
  el.hidden = false;
}

export function hide(el: HTMLElement): void {
  el.hidden = true;
}

// Switches the visible `[data-shh-state]` section inside a page root.
export function setState(root: ParentNode, state: string): void {
  for (const section of $$<HTMLElement>("[data-shh-state]", root)) {
    section.hidden = section.dataset["shhState"] !== state;
  }
}

// The value of a `data-shh-<name>` attribute on the root, an ancestor, or the body.
export function instanceValue(root: Element, name: string): string | undefined {
  const attr = `data-shh-${name}`;
  const own = root.closest<HTMLElement>(`[${attr}]`)?.getAttribute(attr);
  if (own != null) return own;
  if (typeof document === "undefined") return undefined;
  return document.body?.getAttribute(attr) ?? undefined;
}

// What `wireCreate` and `wireReveal` take besides their root. Anything given here wins over
// the page's `data-shh-*` attributes, so a frontend can configure the controllers in code.
export interface PageOptions extends Strings {
  // The instance's versioned API base (`data-shh-api`).
  apiBase?: string;
  // Where the Argon2 module is served from this page's origin.
  argon2Url?: string;
  // The most blob bytes to accept (`data-shh-max-blob-bytes`).
  maxBlobBytes?: number;
}

export interface PageSettings {
  apiBase: string;
  argon2Url: string;
  // Undefined when neither the options nor the page say; each controller picks its own fallback.
  maxBlobBytes: number | undefined;
}

// Options first, then the page's attributes. The Argon2 module defaults to the instance's
// versioned asset when the page names an asset version (the built-in pages), and otherwise
// to `/argon2.wasm` at the page origin, where a frontend serves the package asset.
export function pageSettings(root: Element, options: Omit<PageOptions, "t"> = {}): PageSettings {
  const apiBase = options.apiBase ?? instanceValue(root, "api");
  if (!apiBase) throw new Error("no apiBase option and no data-shh-api attribute on the page");
  const fromPage = Number(instanceValue(root, "max-blob-bytes"));
  return {
    apiBase,
    argon2Url: options.argon2Url ?? argon2Url(root),
    maxBlobBytes: options.maxBlobBytes ?? (fromPage > 0 ? fromPage : undefined),
  };
}

export function apiBaseFrom(root: Element): string {
  return pageSettings(root).apiBase;
}

export function apiFrom(root: Element): Api {
  return new Api(apiBaseFrom(root));
}

// The instance's blob limit: a body past it is refused before it can fill memory.
export function maxBlobBytesFrom(root: Element): number {
  return Number(instanceValue(root, "max-blob-bytes")) || DEFAULT_MAX_BLOB_BYTES;
}

export function setStatus(el: HTMLElement, text: string): void {
  el.textContent = text;
}

// How long a copy button says it worked.
export const COPIED_MS = 1500;

// Copies, then marks the button `data-shh-copied="true"` for a moment so the page's own CSS
// can show that it worked (swap a label, change a colour). The button's content is never
// touched, so its icon and markup survive. Falls back silently where the clipboard API is
// unavailable (some privacy browsers), leaving the text selectable. `_copiedLabel` is no
// longer used (0.3.1) and stays only so older callers keep compiling.
export function wireCopy(button: HTMLButtonElement, getText: () => string, _copiedLabel?: string): void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
    } catch {
      return; /* clipboard unavailable */
    }
    button.dataset["shhCopied"] = "true";
    clearTimeout(timer);
    timer = setTimeout(() => delete button.dataset["shhCopied"], COPIED_MS);
  });
}

// A page's own markup for something a controller renders: the first element inside a
// `<template data-shh-template="<name>">`, looked up inside `root` first, then in the
// document. Null when the page has none, so the controller uses its built-in markup.
export function fromTemplate(root: ParentNode, name: string): HTMLElement | null {
  const selector = `template[data-shh-template="${name}"]`;
  const template = root.querySelector<HTMLTemplateElement>(selector) ?? document.querySelector<HTMLTemplateElement>(selector);
  const first = template?.content.firstElementChild;
  return first ? (first.cloneNode(true) as HTMLElement) : null;
}

// A small element with `data-shh-*` hooks only: the built-in markup carries no classes.
export function hook(tag: string, attribute: string, text = ""): HTMLElement {
  const el = document.createElement(tag);
  el.setAttribute(attribute, "");
  el.textContent = text;
  return el;
}

// The instance's Argon2 module, versioned like every other asset; `/argon2.wasm` when the page
// names no asset version.
export function argon2Url(root: Element): string {
  const version = instanceValue(root, "asset-version");
  return version === undefined ? "/argon2.wasm" : `/static/argon2.wasm?v=${version}`;
}

// A lifetime in its largest whole unit, worded by the browser in the page's language:
// 900 → "15 minutes", 86400 → "1 day", 259200 → "3 days". Any number of seconds works, so an
// operator's own presets need no translations.
export function formatDuration(seconds: number, locale?: string): string {
  const units = [
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
  ] as const;
  const [unit, size] = units.find(([, size]) => seconds % size === 0) ?? (["second", 1] as const);
  return new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "long" }).format(seconds / size);
}

// The page's language for formatting, when there is a page.
export function pageLocale(): string | undefined {
  if (typeof document === "undefined") return undefined;
  return document.documentElement.lang || undefined;
}

export function formatSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const number = new Intl.NumberFormat(document.documentElement.lang || "en", {
    maximumFractionDigits: unit === 0 ? 0 : 1,
  }).format(size);
  return `${number} ${units[unit]}`;
}
