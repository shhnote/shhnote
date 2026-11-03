import type { Header } from "../crypto/blob.ts";
import type { Payload } from "../crypto/container.ts";
import { ShhError } from "../crypto/error.ts";
import { decodeFragment } from "../crypto/fragment.ts";
import { HEADER_LEN } from "../crypto/padding.ts";
import { decryptBody, lookup, unwrapEk } from "../crypto/secret.ts";
import { collect, iterateBytes, readHeader } from "../crypto/stream.ts";
import { isUserActivation } from "../lib/activation.ts";
import { Api, ApiError, DEFAULT_MAX_BLOB_BYTES, getConfig } from "../lib/api.ts";
import { loadArgon2, prefetchArgon2 } from "../lib/argon2-loader.ts";
import { sanitiseFileName } from "../lib/filename.ts";
import { wipeBytes, wipePayload } from "../lib/wipe.ts";
import { $, type PageOptions, formatSize, fromTemplate, hide, hook, pageSettings, setState, setStatus, show, wireCopy } from "./dom.ts";
import { ClaimStore, MAX_CLAIM_WINDOW_SECS } from "./claims.ts";
import type { Translate } from "./i18n.ts";

// `/s#…`: nothing is fetched until the button is pressed, so link previews and scanners
// can't consume a single-view secret (SPEC §5). `options` may name the API base, the Argon2
// module URL and the blob limit; otherwise they come from the page's `data-shh-*` attributes.
export function wireReveal(page: HTMLElement, options: PageOptions): void {
  const { t } = options;
  const settings = pageSettings(page, options);
  const api = new Api(settings.apiBase);
  // The option or the page's attribute; otherwise `/config`, read after the press.
  const pageMaxBlobBytes = settings.maxBlobBytes;
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
  prefetchArgon2(settings.argon2Url);

  // Kept only for a passphrase-protected secret: the header to retry the passphrase against
  // and the ciphertext body, so every retry stays in the browser (SPEC §2.10).
  let locked: { header: Header; body: Promise<Uint8Array> } | null = null;
  let bodyBytes: Uint8Array | null = null;
  // Set once a single-view secret is claimed, and kept through failures: the next press
  // downloads again with it rather than finding the secret gone (SPEC §5.1). Also kept in
  // this tab's sessionStorage for the claim window, so a reload does not lose it.
  let claimToken: string | null = null;
  let claimKey: string | null = null;
  // Derived at the press and kept for the confirm, which may still be retrying after the
  // page is left and the seed has been overwritten.
  let lookupValue: Uint8Array | null = null;
  const claims = new ClaimStore();
  claims.prune();
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

  // Stored at once with the longest possible window, so a reload right away still finds it,
  // then shortened to this instance's window. `/config` is fetched only now, after the
  // press, so the page still sends nothing before a real activation.
  function remember(key: string, token: string): void {
    const claimedAt = Date.now();
    claims.set(key, token, claimedAt + MAX_CLAIM_WINDOW_SECS * 1000);
    void getConfig(settings.apiBase).then(
      (config) => {
        if (claims.get(key) === token) claims.set(key, token, claimedAt + config.claim_window_secs * 1000);
      },
      () => {},
    );
  }

  async function reveal(): Promise<void> {
    if (button.disabled) return;
    const working = $("[data-shh-status=working]", page);
    button.disabled = true;
    try {
      setState(page, "working");
      setStatus(working, t("reveal-fetching"));
      lookupValue ??= await lookup(seed);
      claimKey ??= await ClaimStore.keyFor(lookupValue);
      claimToken ??= claims.get(claimKey);
      const maxBlobBytes = pageMaxBlobBytes ?? (await getConfig(settings.apiBase).then((c) => c.max_blob_bytes, () => DEFAULT_MAX_BLOB_BYTES));
      const revealed = await api.reveal(lookupValue, claimToken, maxBlobBytes);
      if (revealed.claimToken) {
        claimToken = revealed.claimToken;
        remember(claimKey, claimToken);
      }
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
        // Gone, or the window closed: a stored token has nothing left to fetch, and the
        // fragment has nothing left to open, so it leaves the URL and history too.
        if (claimKey) claims.delete(claimKey);
        history.replaceState(null, "", location.pathname);
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
      const ek = await unwrapEk(locked.header, seed, passInput.value, await loadArgon2(settings.argon2Url));
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
      wireCopy($<HTMLButtonElement>("[data-shh-copy=text]", block), () => payload.text ?? "");
      show(block);
    }

    const list = $<HTMLUListElement>("[data-shh-files]", revealed);
    for (const file of payload.files) {
      // Always octet-stream: a sender-chosen text/html would render under this origin if the
      // blob URL were opened in a tab.
      const url = URL.createObjectURL(new Blob([file.bytes as BlobPart], { type: "application/octet-stream" }));
      objectUrls.push(url);
      list.append(fileCard(page, t, file.name, `${file.type || "application/octet-stream"} · ${formatSize(file.bytes.length)}`, url));
    }
    setState(page, "revealed");

    // Destroy now rather than when the claim window lapses. Best effort: the secret is
    // consumed either way (SPEC §5.1).
    if (claimToken !== null) {
      const token = claimToken;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await api.confirm(lookupValue ?? (await lookup(seed)), token);
          // Destroyed: nothing left to download again.
          if (claimKey) claims.delete(claimKey);
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
      }
    }
  }
}

// One downloadable file: the page's `<template data-shh-template="file-card">` when it has
// one, else a plain `<li>`. Hooks filled in: `[data-shh-file-name]` (the cleaned name, as
// text inside a `<bdi>`, so the sender's name can neither inject markup nor reorder the text
// around it), `[data-shh-file-meta]` (type and size) and `a[data-shh-file-download]`, which
// keeps its own label or gets "reveal-download".
function fileCard(page: HTMLElement, t: Translate, rawName: string, meta: string, url: string): HTMLElement {
  const card = fromTemplate(page, "file-card") ?? builtInFileCard();
  const link = card.querySelector<HTMLAnchorElement>("a[data-shh-file-download]");
  if (!link) throw new Error('a file-card template needs an a[data-shh-file-download]');
  const safeName = sanitiseFileName(rawName);
  const bdi = document.createElement("bdi");
  bdi.textContent = safeName;
  card.querySelector("[data-shh-file-name]")?.replaceChildren(bdi);
  const metaSlot = card.querySelector("[data-shh-file-meta]");
  if (metaSlot) metaSlot.textContent = meta;
  link.href = url;
  link.download = safeName;
  if (!link.textContent?.trim()) link.textContent = t("reveal-download");
  return card;
}

function builtInFileCard(): HTMLElement {
  const item = document.createElement("li");
  item.append(hook("span", "data-shh-file-name"), " ", hook("span", "data-shh-file-meta"), " ", hook("a", "data-shh-file-download"));
  return item;
}
