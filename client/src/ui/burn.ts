import { decodeFragment } from "../crypto/fragment.ts";
import { Api, ApiError } from "../lib/api.ts";
import { $, setState, setStatus, show } from "./dom.ts";
import { t } from "./i18n.ts";

// `/burn#…`: static until confirmed, so a prefetched burn link destroys nothing.
export function wireBurn(page: HTMLElement): void {
  const api = Api.fromPage();
  const form = $<HTMLFormElement>("[data-burn-form]", page);
  const status = $("[data-form-status]", form);

  let token: Uint8Array;
  try {
    token = decodeFragment(location.hash, "burn");
  } catch {
    setState(page, "notfound");
    return;
  }
  show(form);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!event.isTrusted) return;
    const button = $<HTMLButtonElement>("button", form);
    button.disabled = true;
    setStatus(status, t("burn-working"));
    try {
      await api.burn(token);
      history.replaceState(null, "", location.pathname);
      setState(page, "done");
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        history.replaceState(null, "", location.pathname);
        setState(page, "notfound");
      } else {
        setStatus(status, t("reveal-error-network"));
        button.disabled = false;
      }
    }
  });
}
