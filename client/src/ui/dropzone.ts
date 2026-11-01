import { $, formatSize } from "./dom.ts";
import type { Strings, Translate } from "./i18n.ts";

// Drag-and-drop file picker. The browser's FileList can't be edited, so the chosen files are
// kept here and read back by the create flow. The list it renders into is the
// `[data-shh-file-list]` next to the zone.
export class Dropzone {
  readonly files: File[] = [];
  private readonly zone: HTMLElement;
  private readonly list: HTMLUListElement;
  private readonly t: Translate;

  constructor(zone: HTMLElement, t: Translate) {
    this.zone = zone;
    this.t = t;
    const input = $<HTMLInputElement>("input[type=file]", zone);
    this.list = $<HTMLUListElement>("[data-shh-file-list]", zone.parentElement ?? document);

    input.addEventListener("change", () => {
      this.add(input.files);
      input.value = "";
    });
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("is-dragging"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("is-dragging");
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
      const item = document.createElement("li");
      const name = document.createElement("span");
      // textContent, never innerHTML, so a file name can't inject HTML into the page.
      name.textContent = `${file.name} (${formatSize(file.size)})`;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = this.t("form-files-remove");
      remove.addEventListener("click", () => {
        this.files.splice(index, 1);
        this.render();
      });
      item.append(name, remove);
      this.list.append(item);
    });
  }

  reset(): void {
    this.files.length = 0;
    this.render();
    this.zone.classList.remove("is-dragging");
  }
}

export function wireDropzone(zone: HTMLElement, { t }: Strings): Dropzone {
  return new Dropzone(zone, t);
}
