import type { Header } from "../crypto/blob.ts";
import type { Payload } from "../crypto/container.ts";
import { ShhError } from "../crypto/error.ts";
import { decodeFragment } from "../crypto/fragment.ts";
import { HEADER_LEN } from "../crypto/padding.ts";
import { decryptBody, lookup, unwrapEk } from "../crypto/secret.ts";
import { collect, iterateBytes, readHeader } from "../crypto/stream.ts";
import { isUserActivation } from "../lib/activation.ts";
import { ApiError } from "../lib/api.ts";
import { loadArgon2, prefetchArgon2 } from "../lib/argon2-loader.ts";
import { sanitiseFileName } from "../lib/filename.ts";
import { wipeBytes, wipePayload } from "../lib/wipe.ts";
import { $, apiFrom, argon2Url, formatSize, hide, maxBlobBytesFrom, setState, setStatus, show, wireCopy } from "./dom.ts";
import type { Strings } from "./i18n.ts";

// `/s#…`: nothing is fetched until the button is pressed, so link previews and scanners
// can't consume a single-view secret (SPEC §5).
export function wireReveal(page: HTMLElement, { t }: Strings): void {
  const api = apiFrom(page);
  const maxBlobBytes = maxBlobBytesFrom(page);
  const armed = $<HTMLFormElement>("[data-shh-form=reveal]", page);
  const armedStatus = $("[data-shh-status]", armed);
  const passForm = $<HTMLFormElement>("[data-shh-form=passphrase]", page);
  const passInput = $<HTMLInputElement>("input[name=passphrase]", passForm);
  const passStatus = $("[data-shh-status]", passForm);

  let seed: Uint8Array;
  try {
    seed = decodeFragment(location.hash, "share");
  } catch {
    setState(page, "notfound");
    return;
  }
  show(armed);
  prefetchArgon2(argon2Url(page));

  // Kept only for a passphrase-protected secret: the header to retry the passphrase against
  // and the ciphertext body, so every retry stays in the browser (SPEC §2.10).
  let locked: { header: Header; body: Promise<Uint8Array> } | null = null;
  let bodyBytes: Uint8Array | null = null;
  // Set once a single-view secret is claimed, and kept through failures: the next press
  // downloads again with it rather than finding the secret gone (SPEC §5.1).
  let claimToken: string | null = null;
  let shown: Payload | null = null;
  const objectUrls: string[] = [];

  // Best effort (SPEC §10): overwrite what we can once the page is left. Strings cannot be
  // wiped in JavaScript; the seed, file bytes and the DOM can.
  window.addEventListener("pagehide", () => {
    wipeBytes(seed, bodyBytes);
    bodyBytes = null;
    locked = null;
    passInput.value = "";
    wipePayload(shown);
    shown = null;
    for (const url of objectUrls) URL.revokeObjectURL(url);
    const pre = page.querySelector("[data-shh-text]");
    if (pre) pre.textContent = "";
    page.querySelector("[data-shh-files]")?.replaceChildren();
  });

  // Only a real press reveals (SPEC §5, `isUserActivation`); the form itself never submits.
  const button = $<HTMLButtonElement>("button", armed);
  armed.addEventListener("submit", (event) => event.preventDefault());
  button.addEventListener("click", (event) => {
    if (isUserActivation(event)) void reveal();
  });
  button.addEventListener("keydown", (event) => {
    if (isUserActivation(event)) {
      event.preventDefault();
      void reveal();
    }
  });

  async function reveal(): Promise<void> {
    if (button.disabled) return;
    const working = $("[data-shh-status=working]", page);
    button.disabled = true;
    try {
      setState(page, "working");
      setStatus(working, t("reveal-fetching"));
      const revealed = await api.reveal(await lookup(seed), claimToken, maxBlobBytes);
      claimToken = revealed.claimToken ?? claimToken;
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
  }

  // Wrong passphrases are retried against the header already in memory: no server round trip.
  passForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!locked) return;
    // A blank field is "nothing entered", not a passphrase; the library would refuse "".
    if (passInput.value === "") {
      passInput.focus();
      return;
    }
    const button = $<HTMLButtonElement>("button", passForm);
    button.disabled = true;
    try {
      setStatus(passStatus, t("reveal-decrypting"));
      const ek = await unwrapEk(locked.header, seed, passInput.value, await loadArgon2(argon2Url(page)));
      const bytes = await locked.body;
      await display(await decryptBody(ek, locked.header, iterateBytes(bytes), bytes.length + HEADER_LEN));
    } catch (e) {
      if (e instanceof ShhError && e.code === "wrong_passphrase") {
        setStatus(passStatus, t("reveal-wrong-passphrase"));
        passInput.select();
      } else if (e instanceof ShhError && e.code === "argon2_unavailable") {
        setStatus(passStatus, t("reveal-error-wasm"));
      } else if (e instanceof ApiError && e.code === "network") {
        // The download behind the prompt failed; the next press fetches again with the token.
        locked = null;
        setState(page, "armed");
        setStatus(armedStatus, t("reveal-error-network"));
        button.disabled = false;
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
    passInput.value = "";
    shown = payload;
    // The fragment has done its job; keep the seed out of history and autocomplete.
    history.replaceState(null, "", location.pathname);

    // Only a single-view secret announces its fate. A TTL secret says nothing about whether
    // or how long it stays readable, so every recipient learns to keep what they were sent.
    const revealed = $("[data-shh-state=revealed]", page);
    const lifetime = $("[data-shh-lifetime]", revealed);
    if (claimToken !== null) {
      $("[data-shh-lifetime-text]", lifetime).textContent = t("reveal-single-view");
    } else {
      hide(lifetime);
    }

    if (payload.text !== null) {
      const block = $("[data-shh-text-block]", revealed);
      const pre = $("[data-shh-text]", block);
      pre.textContent = payload.text;
      wireCopy($<HTMLButtonElement>("[data-shh-copy=text]", block), () => payload.text ?? "", t("result-copied"));
      show(block);
    }

    const list = $<HTMLUListElement>("[data-shh-files]", revealed);
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
      // The cleaned name, as text inside <bdi>: the sender's name can neither inject markup
      // nor reorder the text around it.
      const safeName = sanitiseFileName(file.name);
      const bdi = document.createElement("bdi");
      bdi.textContent = safeName;
      name.append(bdi);
      const sub = document.createElement("div");
      sub.className = "file-card__sub";
      sub.textContent = `${file.type || "application/octet-stream"} · ${formatSize(file.bytes.length)}`;
      meta.append(name, sub);
      const link = document.createElement("a");
      link.className = "btn btn--ghost btn--sm";
      // Always octet-stream: a sender-chosen text/html would render under this origin if the
      // blob URL were opened in a tab.
      link.href = URL.createObjectURL(new Blob([file.bytes as BlobPart], { type: "application/octet-stream" }));
      objectUrls.push(link.href);
      link.download = safeName;
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
