import { decodeFragment } from "../crypto/fragment.ts";
import { Api, ApiError } from "../lib/api.ts";
import { $, type PageOptions, pageSettings, setState, setStatus, show } from "./dom.ts";

// `/burn#…`: static until confirmed, so a prefetched burn link destroys nothing. Only
// `apiBase` matters here (it wins over the page's `data-shh-api`), so the other page options
// are not accepted: passing them would suggest they do something.
export function wireBurn(page: HTMLElement, options: Pick<PageOptions, "t" | "apiBase">): void {
  const { t } = options;
  const api = new Api(pageSettings(page, options).apiBase);
  const form = $<HTMLFormElement>("[data-shh-form=burn]", page);
  const status = $("[data-shh-status]", form);

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
