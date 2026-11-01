import { wireBurn } from "./ui/burn.ts";
import { wireMenus, wirePasswordToggles, wireTheme } from "./ui/chrome.ts";
import { wireCreate } from "./ui/create.ts";
import { $$ } from "./ui/dom.ts";
import { t } from "./ui/i18n.ts";
import { wireReport } from "./ui/report.ts";
import { wireReveal } from "./ui/reveal.ts";
import { wireTabs } from "./ui/tabs.ts";

// The built-in pages: the controllers from `ui/`, bound to the `data-shh-page` roots the
// templates mark, with the strings the server rendered into the page.
wireTheme();
wireMenus();
wirePasswordToggles();
wireTabs();

// Language links keep the #fragment of secret links, otherwise switching language would lose it.
for (const link of $$<HTMLAnchorElement>("a[data-shh-keep-hash]")) {
  link.addEventListener("click", () => {
    if (location.hash) link.hash = location.hash;
  });
}

const strings = { t };
const pages = { create: wireCreate, reveal: wireReveal, burn: wireBurn, report: wireReport } as const;
for (const [name, wire] of Object.entries(pages)) {
  const root = document.querySelector<HTMLElement>(`[data-shh-page=${name}]`);
  if (root) wire(root, strings);
}
