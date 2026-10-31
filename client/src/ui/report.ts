import { decodeFragment } from "../crypto/fragment.ts";
import { lookup } from "../crypto/secret.ts";
import { Api } from "./api.ts";
import { $, setState, setStatus, show } from "./dom.ts";
import { t } from "./i18n.ts";

// `/report`: paste a secret link; the server removes the secret if it is active and keeps a
// ledger row either way. The answer is the same whatever happened, so nothing is learned here.
export function wireReport(page: HTMLElement): void {
  const api = Api.fromPage();
  const form = $<HTMLFormElement>("[data-report-form]", page);
  const input = $<HTMLInputElement>("input[name=link]", form);
  const status = $("[data-form-status]", form);

  // Arriving at `/report#…` (for example from a share link whose path was edited) prefills the field.
  if (location.hash.length > 1) {
    input.value = `${location.origin}/s${location.hash}`;
    history.replaceState(null, "", location.pathname);
  }
  show(form);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    let seed: Uint8Array;
    try {
      const hash = input.value.trim().split("#")[1] ?? "";
      seed = decodeFragment(`#${hash}`, "share");
    } catch {
      setStatus(status, t("report-error-invalid"));
      return;
    }
    const button = $<HTMLButtonElement>("button", form);
    button.disabled = true;
    setStatus(status, t("report-working"));
    try {
      await api.report(await lookup(seed));
      input.value = "";
      setState(page, "done");
    } catch {
      setStatus(status, t("reveal-error-network"));
      button.disabled = false;
    }
  });
}
