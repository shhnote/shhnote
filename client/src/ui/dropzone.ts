import { $, formatSize, fromTemplate, hook } from "./dom.ts";
import type { Strings, Translate } from "./i18n.ts";

// Drag-and-drop file picker. The browser's FileList can't be edited, so the chosen files are
// kept here and read back by the create flow. The list it renders into is the
// `[data-shh-file-list]` next to the zone; each item is the page's
// `<template data-shh-template="dropzone-item">` when it has one (looked up in `root`, the
// create controller's root, then in the document), else a plain `<li>`, with
// `[data-shh-file-name]`, `[data-shh-file-meta]` (the size) and
// `button[data-shh-file-remove]` filled in. While files are dragged over the zone it carries
// `data-shh-dragging="true"`.
export class Dropzone {
  readonly files: File[] = [];
  private readonly zone: HTMLElement;
  private readonly root: ParentNode;
  private readonly list: HTMLUListElement;
  private readonly t: Translate;

  constructor(zone: HTMLElement, t: Translate, root: ParentNode = zone.parentElement ?? zone) {
    this.zone = zone;
    this.root = root;
    this.t = t;
    const input = $<HTMLInputElement>("input[type=file]", zone);
    this.list = $<HTMLUListElement>("[data-shh-file-list]", zone.parentElement ?? document);

    input.addEventListener("change", () => {
      this.add(input.files);
      input.value = "";
    });
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.dataset["shhDragging"] = "true";
    });
    zone.addEventListener("dragleave", () => delete zone.dataset["shhDragging"]);
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      delete zone.dataset["shhDragging"];
      this.add(event.dataTransfer?.files ?? null);
    });
  }

  hide(): void {
    this.reset();
    this.zone.hidden = true;
  }

  private add(files: FileList | null): void {
    if (files) this.files.push(...files);
    this.render();
  }

  private render(): void {
    this.list.replaceChildren();
    this.files.forEach((file, index) => {
      const item = fromTemplate(this.root, "dropzone-item") ?? this.builtInItem();
      // textContent, never innerHTML, so a file name can't inject HTML into the page.
      const name = item.querySelector("[data-shh-file-name]");
      if (name) name.textContent = file.name;
      const meta = item.querySelector("[data-shh-file-meta]");
      if (meta) meta.textContent = formatSize(file.size);
      const remove = item.querySelector<HTMLButtonElement>("button[data-shh-file-remove]");
      if (remove) {
        remove.type = "button";
        if (!remove.textContent?.trim()) remove.textContent = this.t("form-files-remove");
        remove.addEventListener("click", () => {
          this.files.splice(index, 1);
          this.render();
        });
      }
      this.list.append(item);
    });
  }

  reset(): void {
    this.files.length = 0;
    this.render();
    delete this.zone.dataset["shhDragging"];
  }

  private builtInItem(): HTMLElement {
    const item = document.createElement("li");
    item.append(hook("span", "data-shh-file-name"), " ", hook("span", "data-shh-file-meta"), " ", hook("button", "data-shh-file-remove"));
    return item;
  }
}

// `root` is where the `dropzone-item` template is looked up (then the document); the zone's
// parent when none is given. `wireCreate` passes its own root, so two create forms on one
// page each find their own template.
export function wireDropzone(zone: HTMLElement, { t }: Strings, root?: ParentNode): Dropzone {
  return new Dropzone(zone, t, root);
}
