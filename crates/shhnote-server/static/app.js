"use strict";

// Forms that need JavaScript start hidden, so people without it see the <noscript> message instead.
for (const form of document.querySelectorAll("[data-create-form], [data-reveal-form]")) {
  form.hidden = false;
}

// Language links keep the #key part of secret links, otherwise switching language would lose it.
for (const link of document.querySelectorAll("a[data-keep-hash]")) {
  link.addEventListener("click", () => {
    if (location.hash) {
      link.hash = location.hash;
    }
  });
}

setUpDropzones();
setUpForms();
setUpTabs();

function setUpDropzones() {
  for (const zone of document.querySelectorAll("[data-dropzone]")) {
    const input = zone.querySelector("input[type=file]");
    const list = zone.parentElement.querySelector("[data-file-list]");
    // The browser's file list can't be edited directly, so we keep our own and copy it back into the input.
    let files = [];

    const sync = () => {
      const transfer = new DataTransfer();
      for (const file of files) {
        transfer.items.add(file);
      }
      input.files = transfer.files;
      renderFileList(list, files, (index) => {
        files.splice(index, 1);
        sync();
      });
    };

    input.addEventListener("change", () => {
      files = files.concat(Array.from(input.files));
      sync();
    });

    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("is-dragging"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("is-dragging");
      files = files.concat(Array.from(event.dataTransfer.files));
      sync();
    });
  }
}

function renderFileList(list, files, onRemove) {
  list.replaceChildren();
  files.forEach((file, index) => {
    const item = document.createElement("li");
    const name = document.createElement("span");
    // textContent, never innerHTML, so a file name can't inject HTML into the page.
    name.textContent = `${file.name} (${formatSize(file.size)})`;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = list.dataset.removeLabel;
    remove.addEventListener("click", () => onRemove(index));
    item.append(name, remove);
    list.append(item);
  });
}

function formatSize(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const number = new Intl.NumberFormat(document.documentElement.lang, {
    maximumFractionDigits: unit === 0 ? 0 : 1,
  }).format(size);
  return `${number} ${units[unit]}`;
}

// Creating and viewing secrets isn't built yet, so for now the forms just say so.
function setUpForms() {
  for (const form of document.querySelectorAll("[data-create-form], [data-reveal-form]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      form.querySelector("[data-form-status]").textContent = form.dataset.notReady;
    });
  }
}

function setUpTabs() {
  for (const container of document.querySelectorAll("[data-tabs]")) {
    const tabList = container.querySelector("[role=tablist]");
    const tabs = Array.from(tabList.querySelectorAll("[role=tab]"));
    const panels = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls")));

    const select = (index, focus) => {
      tabs.forEach((tab, i) => {
        const selected = i === index;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        panels[i].hidden = !selected;
      });
      if (focus) {
        tabs[index].focus();
      }
    };

    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => {
        select(index, false);
        history.replaceState(null, "", `#${panels[index].id}`);
      });
      // Arrow keys move between tabs, as screen reader users expect.
      tab.addEventListener("keydown", (event) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
        if (step) {
          select((index + step + tabs.length) % tabs.length, true);
        }
      });
    });

    const fromHash = panels.findIndex((panel) => `#${panel.id}` === location.hash);
    select(Math.max(fromHash, 0), false);
    tabList.hidden = false;
    container.classList.add("is-ready");
  }
}
