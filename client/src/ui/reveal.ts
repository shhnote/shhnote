import type { Payload } from "../crypto/container.ts";
import { ShhError } from "../crypto/error.ts";
import { decodeFragment } from "../crypto/fragment.ts";
import { decrypt, lookup } from "../crypto/secret.ts";
import { Api, ApiError } from "./api.ts";
import { loadArgon2 } from "./argon2-loader.ts";
import { $, formatSize, setState, setStatus, show, wireCopy } from "./dom.ts";
import { t } from "./i18n.ts";

// `/s#…`: nothing is fetched until the button is pressed, so link previews and scanners
// can't consume a single-view secret (SPEC §5).
export function wireReveal(page: HTMLElement): void {
  const api = Api.fromPage();
  const armed = $<HTMLFormElement>("[data-reveal-form]", page);
  const armedStatus = $("[data-form-status]", armed);
  const passForm = $<HTMLFormElement>("[data-passphrase-form]", page);
  const passInput = $<HTMLInputElement>("input[name=passphrase]", passForm);
  const passStatus = $("[data-form-status]", passForm);

  let seed: Uint8Array;
  try {
    seed = decodeFragment(location.hash, "share");
  } catch {
    setState(page, "notfound");
    return;
  }
  show(armed);

  let blob: Uint8Array | null = null;
  let claimToken: string | null = null;
  let expiresInHours: number | null = null;
  let shown: Payload | null = null;
  const objectUrls: string[] = [];

  // Best effort (SPEC §10): overwrite what we can once the page is left. Strings cannot be
  // wiped in JavaScript; file bytes and the DOM can.
  window.addEventListener("pagehide", () => {
    blob?.fill(0);
    blob = null;
    for (const file of shown?.files ?? []) file.bytes.fill(0);
    shown = null;
    for (const url of objectUrls) URL.revokeObjectURL(url);
    const pre = page.querySelector("[data-text]");
    if (pre) pre.textContent = "";
    page.querySelector("[data-files]")?.replaceChildren();
  });

  armed.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    const button = $<HTMLButtonElement>("button", armed);
    const working = $("[data-working-status]", page);
    button.disabled = true;
    try {
      setState(page, "working");
      setStatus(working, t("reveal-fetching"));
      const revealed = await api.reveal(await lookup(seed));
      blob = revealed.blob;
      claimToken = revealed.claimToken;
      expiresInHours = revealed.expiresInHours;
      setStatus(working, t("reveal-decrypting"));
      await tryDecrypt(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setState(page, "notfound");
      } else {
        setState(page, "armed");
        setStatus(armedStatus, e instanceof ApiError ? t("reveal-error-network") : t("reveal-error-corrupt"));
        button.disabled = false;
      }
    }
  });

  passForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $<HTMLButtonElement>("button", passForm);
    button.disabled = true;
    try {
      setStatus(passStatus, t("reveal-decrypting"));
      await tryDecrypt(passInput.value);
    } catch (e) {
      console.error(e);
      setStatus(passStatus, t("reveal-error-corrupt"));
    } finally {
      button.disabled = false;
    }
  });

  // Wrong passphrases are retried against the blob already in memory: no server round trip.
  async function tryDecrypt(passphrase: string | null): Promise<void> {
    if (!blob) return;
    try {
      const argon2 = passphrase ? await loadArgon2() : undefined;
      const payload = await decrypt(blob, seed, passphrase, argon2);
      await display(payload);
    } catch (e) {
      if (e instanceof ShhError && e.code === "passphrase_required") {
        setState(page, "passphrase");
        passInput.focus();
        return;
      }
      if (e instanceof ShhError && e.code === "wrong_passphrase") {
        setStatus(passStatus, t("reveal-wrong-passphrase"));
        passInput.select();
        return;
      }
      throw e;
    }
  }

  async function display(payload: Payload): Promise<void> {
    blob = null;
    shown = payload;
    // The fragment has done its job; keep the seed out of history and autocomplete.
    history.replaceState(null, "", location.pathname);

    const revealed = $("[data-state=revealed]", page);
    const lifetime = $("[data-lifetime]", revealed);
    const lifetimeText = $("[data-lifetime-text]", lifetime);
    if (claimToken !== null) {
      lifetimeText.textContent = t("reveal-single-view");
    } else if (expiresInHours !== null) {
      lifetime.classList.remove("badge--danger");
      lifetimeText.textContent = expiresInHours <= 1 ? t("reveal-expires-one") : t("reveal-expires-many", { hours: expiresInHours });
    }

    if (payload.text !== null) {
      const block = $("[data-text-block]", revealed);
      const pre = $("[data-text]", block);
      pre.textContent = payload.text;
      wireCopy($<HTMLButtonElement>("[data-copy=text]", block), () => payload.text ?? "", t("result-copied"));
      show(block);
    }

    const list = $<HTMLUListElement>("[data-files]", revealed);
    for (const file of payload.files) {
      const item = document.createElement("li");
      item.className = "file-card";
      const icon = document.createElement("span");
      icon.className = "file-card__icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = "▣";
      const meta = document.createElement("div");
      meta.className = "file-card__meta";
      const name = document.createElement("div");
      name.className = "file-card__name";
      // textContent, never innerHTML: the file name came from the sender.
      name.textContent = file.name;
      const sub = document.createElement("div");
      sub.className = "file-card__sub";
      sub.textContent = `${file.type || "application/octet-stream"} · ${formatSize(file.bytes.length)}`;
      meta.append(name, sub);
      const link = document.createElement("a");
      link.className = "btn btn--ghost btn--sm";
      link.href = URL.createObjectURL(new Blob([file.bytes as BlobPart], { type: file.type || "application/octet-stream" }));
      objectUrls.push(link.href);
      // Keep the sender's name, but never let it carry a path.
      link.download = file.name.replaceAll(/[/\\]/g, "_") || "file";
      link.textContent = t("reveal-download");
      item.append(icon, meta, link);
      list.append(item);
    }
    setState(page, "revealed");

    // Destroy now rather than when the claim window lapses. Best effort: the secret is
    // consumed either way (SPEC §5.1).
    if (claimToken !== null) {
      const token = claimToken;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await api.confirm(await lookup(seed), token);
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
      }
    }
  }
}
