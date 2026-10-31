import { decodeFragment } from "../crypto/fragment.ts";
import { ShhError } from "../crypto/error.ts";
import { encrypt, generateRandomness } from "../crypto/secret.ts";
import { Api, ApiError, type Lifetime } from "./api.ts";
import { loadArgon2, prefetchArgon2 } from "./argon2-loader.ts";
import { $, $$, hide, setStatus, show, wireCopy } from "./dom.ts";
import type { Dropzone } from "./dropzone.ts";
import { t } from "./i18n.ts";

// Home page: encrypt in the browser, upload, then swap the form for the two links.
export function wireCreate(form: HTMLFormElement, dropzone: Dropzone | undefined): void {
  const api = Api.fromPage();
  const status = $("[data-form-status]", form);
  const submit = $<HTMLButtonElement>("button[type=submit]", form);
  const result = $("[data-create-result]");
  const wrapper = $("[data-create-wrapper]");
  show(wrapper);
  prefetchArgon2();

  // Instance policy: with files switched off the drop zone goes away and the API would refuse
  // anything file-sized anyway.
  let filesEnabled = true;
  void api.config().then((config) => {
    filesEnabled = config.files_enabled;
    if (!filesEnabled) {
      dropzone?.reset();
      for (const zone of $$("[data-dropzone]", form)) hide(zone);
    }
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
        api.config(),
        generateRandomness(),
        passphrase ? loadArgon2() : Promise.resolve(undefined),
        Promise.all(files.map(async (f) => ({ name: f.name, type: f.type || "application/octet-stream", bytes: new Uint8Array(await f.arrayBuffer()) }))),
      ]);
      const encrypted = await encrypt({
        randomness,
        payload: { text: text.length > 0 ? text : null, files: fileBytes },
        policy: config.padding,
        passphrase: passphrase || null,
        ...(argon2 ? { argon2 } : {}),
      });
      if (encrypted.blob.length > config.max_blob_bytes) {
        setStatus(status, t("create-error-too-large"));
        return;
      }

      setStatus(status, t("create-uploading"));
      await api.create(
        { lookupKey: encrypted.lookupKey, burnKey: encrypted.burnKey, lifetime, ttlSeconds },
        encrypted.blob,
      );

      const expiryLabel = $<HTMLSelectElement>("select[name=expiry]", form).selectedOptions[0]?.textContent ?? "";
      showResult(api, result, encrypted.fragment, encrypted.burnFragment, {
        hasPassphrase: passphrase.length > 0,
        singleView: lifetime === "single_view",
        expiryLabel,
      });
      form.reset();
      dropzone?.reset();
      hide(wrapper);
      setStatus(status, "");
    } catch (e) {
      setStatus(status, messageFor(e));
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

function showResult(api: Api, result: HTMLElement, fragment: string, burnFragment: string, info: ResultInfo): void {
  // No locale in the links: the server redirects `/s` and `/burn` to the visitor's own language,
  // and browsers keep the fragment across that redirect.
  const shareLink = `${location.origin}/s#${fragment}`;
  const burnLink = `${location.origin}/burn#${burnFragment}`;
  $("[data-share-link]", result).textContent = shareLink;
  $("[data-burn-link]", result).textContent = burnLink;
  $<HTMLAnchorElement>("[data-open-link]", result).href = shareLink;
  $("[data-chip-lifetime]", result).textContent = t(info.singleView ? "result-chip-single" : "result-chip-multi");
  $("[data-chip-expiry]", result).textContent = t("result-chip-expires", { period: info.expiryLabel });
  if (info.hasPassphrase) show($("[data-passphrase-reminder]", result));
  wireCopy($<HTMLButtonElement>("[data-copy=share]", result), () => shareLink, t("result-copied"));
  wireCopy($<HTMLButtonElement>("[data-copy=burn]", result), () => burnLink, t("result-copied"));

  const destroy = $<HTMLButtonElement>("[data-destroy]", result);
  const status = $("[data-result-status]", result);
  destroy.addEventListener("click", async () => {
    destroy.disabled = true;
    try {
      await api.burn(decodeFragment(burnFragment, "burn"));
      setStatus(status, t("result-destroyed"));
    } catch (e) {
      setStatus(status, messageFor(e));
      destroy.disabled = false;
    }
  });
  show(result);
  result.scrollIntoView({ block: "start" });
}

function messageFor(e: unknown): string {
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
