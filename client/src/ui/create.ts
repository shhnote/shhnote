import { decodeFragment } from "../crypto/fragment.ts";
import { ShhError } from "../crypto/error.ts";
import { encrypt, generateRandomness } from "../crypto/secret.ts";
import { Api, ApiError, type Lifetime, getConfig } from "../lib/api.ts";
import { loadArgon2, prefetchArgon2 } from "../lib/argon2-loader.ts";
import { $, type PageOptions, hide, pageSettings, setStatus, show, wireCopy } from "./dom.ts";
import { type Dropzone, wireDropzone } from "./dropzone.ts";
import type { Translate } from "./i18n.ts";

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
  const dropzone: Dropzone | undefined = zone ? wireDropzone(zone, { t }) : undefined;
  show(wrapper);
  prefetchArgon2(page.argon2Url);

  // Instance policy: with files switched off the drop zone goes away and the API would refuse
  // anything file-sized anyway.
  let filesEnabled = true;
  void getConfig(apiBase).then((config) => {
    filesEnabled = config.files_enabled;
    if (!filesEnabled) dropzone?.hide();
  }, () => {});

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const text = String(data.get("note") ?? "").replace(/\r\n/g, "\n");
    const passphrase = String(data.get("passphrase") ?? "");
    const lifetime: Lifetime = data.get("burn") ? "single_view" : "ttl";
    const ttlSeconds = Number(data.get("expiry"));
    const files = filesEnabled ? (dropzone?.files ?? []) : [];

    if (text.length === 0 && files.length === 0) {
      setStatus(status, t("create-error-empty"));
      return;
    }

    submit.disabled = true;
    try {
      setStatus(status, t("create-encrypting"));
      const [config, randomness, argon2, fileBytes] = await Promise.all([
        getConfig(apiBase),
        generateRandomness(),
        passphrase ? loadArgon2(page.argon2Url) : Promise.resolve(undefined),
        Promise.all(files.map(async (f) => ({ name: f.name, type: f.type || "application/octet-stream", bytes: new Uint8Array(await f.arrayBuffer()) }))),
      ]);
      const encrypted = await encrypt({
        randomness,
        payload: { text: text.length > 0 ? text : null, files: fileBytes },
        policy: config.padding,
        passphrase: passphrase || null,
        ...(argon2 ? { argon2 } : {}),
      });
      if (encrypted.blob.length > (page.maxBlobBytes ?? config.max_blob_bytes)) {
        setStatus(status, t("create-error-too-large"));
        return;
      }

      setStatus(status, t("create-uploading"));
      await api.create(
        { lookupKey: encrypted.lookupKey, burnKey: encrypted.burnKey, lifetime, ttlSeconds },
        encrypted.blob,
      );

      const expiryLabel = $<HTMLSelectElement>("select[name=expiry]", form).selectedOptions[0]?.textContent ?? "";
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
  wireCopy($<HTMLButtonElement>("[data-shh-copy=share]", result), () => shareLink, t("result-copied"));
  wireCopy($<HTMLButtonElement>("[data-shh-copy=burn]", result), () => burnLink, t("result-copied"));

  const destroy = $<HTMLButtonElement>("[data-shh-destroy]", result);
  const status = $("[data-shh-status]", result);
  destroy.addEventListener("click", async () => {
    destroy.disabled = true;
    try {
      await api.burn(decodeFragment(burnFragment, "burn"));
      setStatus(status, t("result-destroyed"));
    } catch (e) {
      setStatus(status, messageFor(t, e));
      destroy.disabled = false;
    }
  });
  show(result);
  result.scrollIntoView({ block: "start" });
}

function messageFor(t: Translate, e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 0) return t("create-error-network");
    if (e.status === 413) return t("create-error-too-large");
    return t("create-error-failed");
  }
  if (e instanceof ShhError && (e.code === "payload_too_large" || e.code === "empty_payload")) {
    return t(e.code === "empty_payload" ? "create-error-empty" : "create-error-too-large");
  }
  if (e instanceof ShhError && e.code === "argon2_unavailable") return t("create-error-wasm");
  console.error(e);
  return t("create-error-failed");
}
