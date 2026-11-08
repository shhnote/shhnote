import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import { encodeFragment } from "../src/crypto/fragment.ts";
import { wireReveal } from "../src/ui/reveal.ts";

// Just enough of the DOM for `wireReveal` to wire a page: elements found by selector, and
// the listeners registered on them.
class FakeElement {
  hidden = true;
  value = "";
  textContent = "";
  dataset: Record<string, string> = {};
  listeners = new Map<string, (event: unknown) => void>();
  found: Record<string, unknown>;

  constructor(found: Record<string, unknown> = {}) {
    this.found = found;
  }
  querySelector(selector: string): unknown {
    return this.found[selector] ?? null;
  }
  querySelectorAll(): unknown[] {
    return [];
  }
  addEventListener(type: string, listener: (event: unknown) => void): void {
    this.listeners.set(type, listener);
  }
  closest(): null {
    return null;
  }
  getAttribute(): null {
    return null;
  }
  replaceChildren(): void {}
}

// A `<template data-shh-template="file-card">` whose card has, or lacks, the download link.
function fileCardTemplate(withDownload: boolean): unknown {
  const card = new FakeElement(withDownload ? { "a[data-shh-file-download]": new FakeElement() } : {});
  return { content: { firstElementChild: { cloneNode: () => card } } };
}

function revealPage(template?: unknown): FakeElement {
  const armed = new FakeElement({ "[data-shh-status]": new FakeElement(), button: new FakeElement() });
  const passForm = new FakeElement({
    "input[name=passphrase]": new FakeElement(),
    "[data-shh-status]": new FakeElement(),
  });
  return new FakeElement({
    "[data-shh-form=reveal]": armed,
    "[data-shh-form=passphrase]": passForm,
    'template[data-shh-template="file-card"]': template,
  });
}

const globals = globalThis as Record<string, unknown>;
let windowListeners: Map<string, (event: unknown) => void>;
let reloads: number;

// The page is wired with a valid share link in the fragment; the Argon2 module URL is on
// another origin, so the prefetch is refused at once and nothing is fetched.
function wire(page: FakeElement): void {
  wireReveal(page as unknown as HTMLElement, {
    t: (key) => key,
    apiBase: "https://site.test/api/v1",
    argon2Url: "https://elsewhere.test/argon2.wasm",
  });
}

beforeEach(() => {
  windowListeners = new Map();
  reloads = 0;
  globals["window"] = {
    addEventListener: (type: string, listener: (event: unknown) => void) => windowListeners.set(type, listener),
  };
  globals["document"] = { querySelector: () => null };
  globals["location"] = {
    hash: `#${encodeFragment(new Uint8Array(32).fill(7))}`,
    href: "https://site.test/s",
    origin: "https://site.test",
    reload: () => reloads++,
  };
});

afterEach(() => {
  for (const name of ["window", "document", "location"]) delete globals[name];
});

describe("reveal page wiring", () => {
  // Found out only when a file is shown, a broken template would leave a single-view secret
  // consumed with nothing on screen, so it is refused before anything can be revealed.
  it("refuses a file-card template without a download link when wired", () => {
    assert.throws(() => wire(revealPage(fileCardTemplate(false))), /a\[data-shh-file-download\]/);
  });

  it("accepts a file-card template with a download link, or none", () => {
    wire(revealPage(fileCardTemplate(true)));
    wire(revealPage());
  });

  // Restored from the back-forward cache, the page would come back with its seed wiped and
  // its forms dead; it reloads instead, starting over from the fragment (SPEC §10).
  it("reloads when restored from the back-forward cache, and only then", () => {
    wire(revealPage());
    const pageshow = windowListeners.get("pageshow");
    assert.ok(pageshow, "no pageshow listener");
    pageshow({ persisted: false });
    assert.equal(reloads, 0);
    pageshow({ persisted: true });
    assert.equal(reloads, 1);
  });

  it("registers the handler that wipes the page when it is left", () => {
    wire(revealPage());
    assert.ok(windowListeners.has("pagehide"), "no pagehide listener");
  });
});
