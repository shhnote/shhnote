// Small helpers so the flow code reads as what it does, not as DOM plumbing.

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

// Switches the visible `[data-state]` section inside a page root.
export function setState(root: ParentNode, state: string): void {
  for (const section of $$<HTMLElement>("[data-state]", root)) {
    section.hidden = section.dataset["state"] !== state;
  }
}

export function setStatus(el: HTMLElement, text: string): void {
  el.textContent = text;
}

// Copies with a short "copied" confirmation on the button. Falls back silently where the
// clipboard API is unavailable (some privacy browsers), leaving the text selectable.
export function wireCopy(button: HTMLButtonElement, getText: () => string, copiedLabel: string): void {
  const original = button.textContent ?? "";
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      button.textContent = copiedLabel;
      setTimeout(() => (button.textContent = original), 1500);
    } catch {
      /* clipboard unavailable */
    }
  });
}

// The instance's Argon2 module, versioned like every other asset.
export function argon2Url(): string {
  const version = document.body.dataset["assetVersion"] ?? "";
  return `/static/argon2.wasm?v=${version}`;
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
