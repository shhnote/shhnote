import { $$ } from "./dom.ts";

// Progressive enhancement for tabbed sections (the admin settings page): without the script
// every section shows. Once wired, the container gets `data-shh-ready="true"`, so the page's
// CSS can hide what only makes sense without tabs, such as the section titles.
export function wireTabs(root: ParentNode = document): void {
  for (const container of $$("[data-shh-tabs]", root)) {
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
    for (const link of $$<HTMLAnchorElement>("[data-shh-tab-link]", container)) {
      link.addEventListener("click", (event) => {
        const index = tabs.findIndex((tab) => tab.id === link.dataset["shhTabLink"]);
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
    container.setAttribute("data-shh-ready", "true");
  }
}
