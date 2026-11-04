import { checkProtocol } from "../client.ts";
import { decodeFragment } from "../crypto/fragment.ts";
import { ShhError } from "../crypto/error.ts";
import { type Encrypted, encrypt, generateRandomness } from "../crypto/secret.ts";
import { wipeBytes } from "../lib/wipe.ts";
import { Api, ApiError, type InstanceConfig, type Lifetime, getConfig } from "../lib/api.ts";
import { loadArgon2, prefetchArgon2 } from "../lib/argon2-loader.ts";
import { $, type PageOptions, formatDuration, hide, pageLocale, pageSettings, setStatus, show, wireCopy } from "./dom.ts";
import { type Dropzone, wireDropzone } from "./dropzone.ts";
import type { Translate } from "./i18n.ts";

// The lifetimes to offer, from the instance's policy: its presets plus its default, within
// its bounds, shortest first. The default is preselected.
export function ttlChoices(
  config: Pick<InstanceConfig, "ttl_presets" | "default_ttl_secs" | "min_ttl_secs" | "max_ttl_secs">,
): { seconds: number[]; selected: number } {
  const inRange = (s: number) => s >= config.min_ttl_secs && s <= config.max_ttl_secs;
  const offered = new Set(config.ttl_presets.filter(inRange));
  if (inRange(config.default_ttl_secs)) offered.add(config.default_ttl_secs);
  const seconds = [...offered].sort((a, b) => a - b);
  const selected = offered.has(config.default_ttl_secs) ? config.default_ttl_secs : (seconds[0] ?? config.default_ttl_secs);
  return { seconds, selected };
}

// Replaces the select's options with the instance's lifetimes. The default is also the
// `defaultSelected` one, so `form.reset()` goes back to it.
export function fillTtl(select: HTMLSelectElement, config: InstanceConfig, locale = pageLocale()): void {
  const { seconds, selected } = ttlChoices(config);
  select.replaceChildren(...seconds.map((s) => new Option(formatDuration(s, locale), String(s), s === selected, s === selected)));
}

// The create page: encrypt in the browser, upload, then swap the form for the two links.
// `root` holds the form (`[data-shh-form=create]`), its wrapper and the result panel.
// `options` may name the API base, the Argon2 module URL and the blob limit; otherwise they
// come from the page's `data-shh-*` attributes (and the limit from the instance's `/config`).
export function wireCreate(root: HTMLElement, options: PageOptions): void {
  const { t } = options;
  const page = pageSettings(root, options);
  const apiBase = page.apiBase;
  const api = new Api(apiBase);
  const form = $<HTMLFormElement>("[data-shh-form=create]", root);
  const status = $("[data-shh-status]", form);
  const submit = $<HTMLButtonElement>("button[type=submit]", form);
  const result = $("[data-shh-create-result]", root);
  const wrapper = $("[data-shh-create-wrapper]", root);
  const zone = form.querySelector<HTMLElement>("[data-shh-dropzone]");
  // Filled from `/config` when present; a frontend may instead offer its own `expiry` field.
  const ttlSelect = form.querySelector<HTMLSelectElement>("select[data-shh-ttl]");
  const dropzone: Dropzone | undefined = zone ? wireDropzone(zone, { t }) : undefined;
  show(wrapper);
  prefetchArgon2(page.argon2Url);

  // Raw material of the secret being made (seed, burn token, file bytes). Overwritten once it
  // has done its job: file bytes as soon as the blob is built, the rest when the links are
  // shown or the attempt fails, and anything still here when the page is left (SPEC §10,
  // best effort: the note and the links are strings, which JavaScript cannot overwrite).
  const inFlight = new Set<Uint8Array>();
  window.addEventListener("pagehide", () => {
    wipeBytes(...inFlight);
    inFlight.clear();
    const passphrase = form.querySelector<HTMLInputElement>("input[name=passphrase]");
    if (passphrase) passphrase.value = "";
    for (const selector of ["[data-shh-share-link]", "[data-shh-burn-link]"]) {
      const el = result.querySelector(selector);
      if (el) el.textContent = "";
    }
    result.querySelector("[data-shh-open-link]")?.removeAttribute("href");
  });

  // Instance policy: with files switched off the drop zone goes away and the API would refuse
  // anything file-sized anyway.
  let filesEnabled = true;
  void getConfig(apiBase).then((config) => {
    filesEnabled = config.files_enabled;
    if (!filesEnabled) dropzone?.hide();
    if (ttlSelect) fillTtl(ttlSelect, config);
  }, () => {});

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const text = String(data.get("note") ?? "").replace(/\r\n/g, "\n");
    const passphrase = String(data.get("passphrase") ?? "");
    const lifetime: Lifetime = data.get("burn") ? "single_view" : "ttl";
    const files = filesEnabled ? (dropzone?.files ?? []) : [];

    if (text.length === 0 && files.length === 0) {
      setStatus(status, t("create-error-empty"));
      return;
    }

    submit.disabled = true;
    try {
      setStatus(status, t("create-encrypting"));
      // Cached since the page loaded; fetched again here if that first attempt failed, and
      // then the lifetimes are filled in before one is read.
      const config = await getConfig(apiBase);
      // Links in a format the instance doesn't speak would be useless to their recipients.
      checkProtocol(config);
      if (ttlSelect && ttlSelect.options.length === 0) fillTtl(ttlSelect, config);
      const ttlSeconds = ttlSelect ? Number(ttlSelect.value) : Number(data.get("expiry"));
      const [randomness, argon2, fileBytes] = await Promise.all([
        generateRandomness(),
        passphrase ? loadArgon2(page.argon2Url) : Promise.resolve(undefined),
        Promise.all(files.map(async (f) => ({ name: f.name, type: f.type || "application/octet-stream", bytes: new Uint8Array(await f.arrayBuffer()) }))),
      ]);
      for (const buffer of [randomness.seed, randomness.burnToken, ...fileBytes.map((f) => f.bytes)]) inFlight.add(buffer);
      let encrypted: Encrypted;
      try {
        encrypted = await encrypt({
          randomness,
          payload: { text: text.length > 0 ? text : null, files: fileBytes },
          policy: config.padding,
          passphrase: passphrase || null,
          ...(argon2 ? { argon2 } : {}),
        });
      } finally {
        // The blob holds them now, encrypted; the plaintext copies are done.
        wipeBytes(...fileBytes.map((f) => f.bytes));
      }
      if (encrypted.blob.length > (page.maxBlobBytes ?? config.max_blob_bytes)) {
        setStatus(status, t("create-error-too-large"));
        return;
      }

      setStatus(status, t("create-uploading"));
      await api.create(
        { lookupKey: encrypted.lookupKey, burnKey: encrypted.burnKey, lifetime, ttlSeconds },
        encrypted.blob,
      );

      const expiryLabel = ttlSelect?.selectedOptions[0]?.textContent ?? formatDuration(ttlSeconds, pageLocale());
      showResult(api, t, result, encrypted.fragment, encrypted.burnFragment, {
        hasPassphrase: passphrase.length > 0,
        singleView: lifetime === "single_view",
        expiryLabel,
      });
      form.reset();
      dropzone?.reset();
      hide(wrapper);
      setStatus(status, "");
    } catch (e) {
      setStatus(status, messageFor(t, e));
    } finally {
      // Shown or failed: the seed and burn token live on only as the links' text.
      wipeBytes(...inFlight);
      inFlight.clear();
      submit.disabled = false;
    }
  });
}

interface ResultInfo {
  hasPassphrase: boolean;
  singleView: boolean;
  expiryLabel: string;
}

function showResult(api: Api, t: Translate, result: HTMLElement, fragment: string, burnFragment: string, info: ResultInfo): void {
  // No locale in the links: the server redirects `/s` and `/burn` to the visitor's own language,
  // and browsers keep the fragment across that redirect.
  const shareLink = `${location.origin}/s#${fragment}`;
  const burnLink = `${location.origin}/burn#${burnFragment}`;
  $("[data-shh-share-link]", result).textContent = shareLink;
  $("[data-shh-burn-link]", result).textContent = burnLink;
  $<HTMLAnchorElement>("[data-shh-open-link]", result).href = shareLink;
  $("[data-shh-chip=lifetime]", result).textContent = t(info.singleView ? "result-chip-single" : "result-chip-multi");
  $("[data-shh-chip=expiry]", result).textContent = t("result-chip-expires", { period: info.expiryLabel });
  if (info.hasPassphrase) show($("[data-shh-passphrase-reminder]", result));
  wireCopy($<HTMLButtonElement>("[data-shh-copy=share]", result), () => shareLink);
  wireCopy($<HTMLButtonElement>("[data-shh-copy=burn]", result), () => burnLink);

  const destroy = $<HTMLButtonElement>("[data-shh-destroy]", result);
  const status = $("[data-shh-status]", result);
  destroy.addEventListener("click", async () => {
    destroy.disabled = true;
    const token = decodeFragment(burnFragment, "burn");
    try {
      await api.burn(token);
      setStatus(status, t("result-destroyed"));
    } catch (e) {
      setStatus(status, messageFor(t, e));
      destroy.disabled = false;
    } finally {
      wipeBytes(token);
    }
  });
  show(result);
  result.scrollIntoView({ block: "start" });
}

export function messageFor(t: Translate, e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 0) return t("create-error-network");
    if (e.status === 413) return t("create-error-too-large");
    return t("create-error-failed");
  }
  if (e instanceof ShhError && (e.code === "payload_too_large" || e.code === "empty_payload")) {
    return t(e.code === "empty_payload" ? "create-error-empty" : "create-error-too-large");
  }
  if (e instanceof ShhError && e.code === "argon2_unavailable") return t("create-error-wasm");
  if (e instanceof ShhError && e.code === "unsupported_protocol") return t("error-unsupported-protocol");
  console.error(e);
  return t("create-error-failed");
}
