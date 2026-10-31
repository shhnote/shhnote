import { $, $$, formatSize } from "./dom.ts";
import { t } from "./i18n.ts";

// Drag-and-drop file picker. The browser's FileList can't be edited, so the chosen files are
// kept here and read back by the create flow.
export class Dropzone {
  readonly files: File[] = [];
  private readonly zone: HTMLElement;
  private readonly list: HTMLUListElement;

  constructor(zone: HTMLElement) {
    this.zone = zone;
    const input = $<HTMLInputElement>("input[type=file]", zone);
    this.list = $<HTMLUListElement>("[data-file-list]", zone.parentElement ?? document);

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

  static wireAll(): Dropzone[] {
    return $$("[data-dropzone]").map((zone) => new Dropzone(zone));
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
      remove.textContent = t("form-files-remove");
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
