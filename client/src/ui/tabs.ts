import { $$ } from "./dom.ts";

// Progressive enhancement for the how-it-works page: without the script both sections show.
export function wireTabs(): void {
  for (const container of $$("[data-tabs]")) {
    const tabList = container.querySelector<HTMLElement>("[role=tablist]");
    if (!tabList) continue;
    const tabs = $$<HTMLButtonElement>("[role=tab]", tabList);
    const panels = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls") ?? ""));

    const select = (index: number, focus: boolean) => {
      tabs.forEach((tab, i) => {
        const selected = i === index;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        const panel = panels[i];
        if (panel) panel.hidden = !selected;
      });
      if (focus) tabs[index]?.focus();
    };

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => {
        select(index, false);
        history.replaceState(null, "", `#${panels[index]?.id ?? ""}`);
      });
      // Arrow keys move between tabs, as screen reader users expect.
      tab.addEventListener("keydown", (event) => {
        const step = ({ ArrowRight: 1, ArrowLeft: -1 } as Record<string, number>)[event.key];
        if (step) select((index + step + tabs.length) % tabs.length, true);
      });
    });

    // In-page links (and footer links) may name a tab by its id.
    for (const link of $$<HTMLAnchorElement>("[data-tab-link]", container)) {
      link.addEventListener("click", (event) => {
        const index = tabs.findIndex((tab) => tab.id === link.dataset["tabLink"]);
        if (index < 0) return;
        event.preventDefault();
        select(index, true);
        history.replaceState(null, "", `#${panels[index]?.id ?? ""}`);
        container.scrollIntoView({ block: "start" });
      });
    }
    window.addEventListener("hashchange", () => {
      const index = panels.findIndex((panel) => panel && `#${panel.id}` === location.hash);
      if (index >= 0) select(index, false);
    });

    const fromHash = panels.findIndex((panel) => panel && `#${panel.id}` === location.hash);
    select(Math.max(fromHash, 0), false);
    tabList.hidden = false;
    container.classList.add("is-ready");
  }
}
