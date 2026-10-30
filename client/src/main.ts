import { wireBurn } from "./ui/burn.ts";
import { wireMenus, wirePasswordToggles, wireTheme } from "./ui/chrome.ts";
import { wireCreate } from "./ui/create.ts";
import { $$ } from "./ui/dom.ts";
import { Dropzone } from "./ui/dropzone.ts";
import { wireReveal } from "./ui/reveal.ts";
import { wireTabs } from "./ui/tabs.ts";

wireTheme();
wireMenus();
wirePasswordToggles();

// Language links keep the #fragment of secret links, otherwise switching language would lose it.
for (const link of $$<HTMLAnchorElement>("a[data-keep-hash]")) {
  link.addEventListener("click", () => {
    if (location.hash) link.hash = location.hash;
  });
}

const dropzones = Dropzone.wireAll();
wireTabs();

const createForm = document.querySelector<HTMLFormElement>("[data-create-form]");
if (createForm) wireCreate(createForm, dropzones[0]);

const revealPage = document.querySelector<HTMLElement>("[data-reveal-page]");
if (revealPage) wireReveal(revealPage);

const burnPage = document.querySelector<HTMLElement>("[data-burn-page]");
if (burnPage) wireBurn(burnPage);
