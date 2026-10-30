import { $$ } from "./dom.ts";

// Disclosure menus: native <details>, so they open without the script. The script only
// closes them when the pointer or focus leaves, and on Escape.
export function wireMenus(): void {
  const menus = $$<HTMLDetailsElement>("details[data-menu]");
  document.addEventListener("click", (event) => {
    for (const menu of menus) {
      if (menu.open && !menu.contains(event.target as Node)) menu.open = false;
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    for (const menu of menus) {
      if (menu.open) {
        menu.open = false;
        menu.querySelector("summary")?.focus();
      }
    }
  });
  for (const menu of menus) {
    menu.addEventListener("focusout", (event) => {
      if (!menu.contains(event.relatedTarget as Node | null)) menu.open = false;
    });
  }
}

const THEMES = new Set(["light", "dark", "light-hc", "dark-hc"]);
const THEME_KEY = "shhnote-theme";

// Four themes plus "match system" (no attribute: the stylesheet follows the OS). The choice
// is kept in localStorage when the browser allows it; privacy browsers that don't simply
// reset to "match system" on the next visit.
export function wireTheme(): void {
  const apply = (choice: string) => {
    if (THEMES.has(choice)) document.documentElement.dataset["theme"] = choice;
    else delete document.documentElement.dataset["theme"];
    for (const button of $$<HTMLButtonElement>("[data-theme-choice]")) {
      button.setAttribute("aria-checked", String((button.dataset["themeChoice"] ?? "auto") === choice));
    }
  };

  let stored = "auto";
  try {
    stored = localStorage.getItem(THEME_KEY) ?? "auto";
  } catch {
    /* storage unavailable */
  }
  apply(stored);

  for (const button of $$<HTMLButtonElement>("[data-theme-choice]")) {
    button.addEventListener("click", () => {
      const choice = button.dataset["themeChoice"] ?? "auto";
      apply(choice);
      try {
        if (choice === "auto") localStorage.removeItem(THEME_KEY);
        else localStorage.setItem(THEME_KEY, choice);
      } catch {
        /* storage unavailable */
      }
      button.closest("details")?.removeAttribute("open");
    });
  }
}

// Show/hide toggle for passphrase fields.
export function wirePasswordToggles(): void {
  for (const wrapper of $$("[data-pwd-input]")) {
    const input = wrapper.querySelector<HTMLInputElement>("input");
    const button = wrapper.querySelector<HTMLButtonElement>("[data-pwd-toggle]");
    if (!input || !button) continue;
    button.addEventListener("click", () => {
      const shown = input.type === "password";
      input.type = shown ? "text" : "password";
      wrapper.dataset["shown"] = String(shown);
      button.setAttribute("aria-pressed", String(shown));
      input.focus();
    });
  }
}
