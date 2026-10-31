import type { Header } from "../crypto/blob.ts";
import type { Payload } from "../crypto/container.ts";
import { ShhError } from "../crypto/error.ts";
import { decodeFragment } from "../crypto/fragment.ts";
import { HEADER_LEN } from "../crypto/padding.ts";
import { decryptBody, lookup, unwrapEk } from "../crypto/secret.ts";
import { collect, iterateBytes, readHeader } from "../crypto/stream.ts";
import { Api, ApiError, DEFAULT_MAX_BLOB_BYTES } from "./api.ts";
import { loadArgon2 } from "./argon2-loader.ts";
import { $, formatSize, setState, setStatus, show, wireCopy } from "./dom.ts";
import { t } from "./i18n.ts";

// `/s#…`: nothing is fetched until the button is pressed, so link previews and scanners
// can't consume a single-view secret (SPEC §5).
export function wireReveal(page: HTMLElement): void {
  const api = Api.fromPage();
  // The instance's limit: a body past it is refused before it can fill memory.
  const maxBlobBytes = Number(document.body.dataset["maxBlobBytes"]) || DEFAULT_MAX_BLOB_BYTES;
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

  // Kept only for a passphrase-protected secret: the header to retry the passphrase against
  // and the ciphertext body, so every retry stays in the browser (SPEC §2.10).
  let locked: { header: Header; body: Promise<Uint8Array> } | null = null;
  let bodyBytes: Uint8Array | null = null;
  // Set once a single-view secret is claimed, and kept through failures: the next press
  // downloads again with it rather than finding the secret gone (SPEC §5.1).
  let claimToken: string | null = null;
  let expiresInHours: number | null = null;
  let shown: Payload | null = null;
  const objectUrls: string[] = [];

  // Best effort (SPEC §10): overwrite what we can once the page is left. Strings cannot be
  // wiped in JavaScript; file bytes and the DOM can.
  window.addEventListener("pagehide", () => {
    bodyBytes?.fill(0);
    bodyBytes = null;
    locked = null;
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
      const revealed = await api.reveal(await lookup(seed), claimToken, maxBlobBytes);
      claimToken = revealed.claimToken ?? claimToken;
      expiresInHours = revealed.expiresInHours;
      // The header is enough to know whether a passphrase is needed; the rest of the body
      // is decrypted as it arrives, so the ciphertext is never held whole.
      const { header, rest } = await readHeader(revealed.body);
      setStatus(working, t("reveal-decrypting"));
      let ek: CryptoKey;
      try {
        ek = await unwrapEk(header, seed);
      } catch (e) {
        if (!(e instanceof ShhError && e.code === "passphrase_required")) throw e;
        // Keep downloading while the passphrase is typed, so the retry loop needs no server.
        const body = collect(rest).then((bytes) => (bodyBytes = bytes));
        body.catch(() => {});
        locked = { header, body };
        setState(page, "passphrase");
        passInput.focus();
        return;
      }
      await display(await decryptBody(ek, header, rest, maxBlobBytes));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setState(page, "notfound");
      } else {
        setState(page, "armed");
        setStatus(armedStatus, e instanceof ApiError && e.code === "network" ? t("reveal-error-network") : t("reveal-error-corrupt"));
        button.disabled = false;
      }
    }
  });

  // Wrong passphrases are retried against the header already in memory: no server round trip.
  passForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!locked) return;
    const button = $<HTMLButtonElement>("button", passForm);
    button.disabled = true;
    try {
      setStatus(passStatus, t("reveal-decrypting"));
      const ek = await unwrapEk(locked.header, seed, passInput.value, await loadArgon2());
      const bytes = await locked.body;
      await display(await decryptBody(ek, locked.header, iterateBytes(bytes), bytes.length + HEADER_LEN));
    } catch (e) {
      if (e instanceof ShhError && e.code === "wrong_passphrase") {
        setStatus(passStatus, t("reveal-wrong-passphrase"));
        passInput.select();
      } else if (e instanceof ApiError && e.code === "network") {
        // The download behind the prompt failed; the next press fetches again with the token.
        locked = null;
        setState(page, "armed");
        setStatus(armedStatus, t("reveal-error-network"));
        $<HTMLButtonElement>("button", armed).disabled = false;
      } else {
        setStatus(passStatus, t("reveal-error-corrupt"));
      }
    } finally {
      button.disabled = false;
    }
  });

  async function display(payload: Payload): Promise<void> {
    bodyBytes?.fill(0);
    bodyBytes = null;
    locked = null;
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
