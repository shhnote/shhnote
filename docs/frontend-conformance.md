# Frontend conformance checklist

What a frontend built on `@shhnote/client` must do so the properties in `SPEC.md` hold for
its users too (SPEC §10). The built-in website and `shhnote.com` meet every item. A frontend
that uses the `/ui` controllers (`wireCreate`, `wireReveal`, `wireBurn`, `wireReport`) meets
the per-page items marked **by construction**; the page-level and server-level items are the
frontend's own job whichever layer it uses.

Each line says what, why, and how to check it.

## The pages

1. **The reveal interstitial is static.** `/s` is the same document for every secret; the
   secret is named only by the URL fragment, which browsers never send. *Why:* a link that
   the server can tell apart from another is a lookup the server could log. *Check:* fetch
   `/s` with two different fragments from outside a browser and diff the bodies; they are
   byte-identical.
2. **Nothing is fetched before a trusted activation.** The reveal page makes no request to
   the API until the button receives a real pointer click (`detail > 0`) or key press, both
   trusted, while the browser reports user activation — never on `load`, never on a trusted
   `submit` or a scripted `click()`. **by construction** (`wireReveal`; `isUserActivation`
   from the package root for your own button). *Why:* a link scanner or a page script could
   otherwise consume a single-view secret. *Check:* open `/s#<valid>` with the network tab
   open: no request. In the console run `document.querySelector('[data-shh-form=reveal]')
   .requestSubmit()` and `document.querySelector('[data-shh-form=reveal] button').click()`:
   still no request. A real click fetches.
3. **The fragment is scrubbed after use.** After a reveal, after a reveal that finds nothing
   (the secret is gone) and after a burn, the page replaces its history entry so the seed is
   not left in the URL bar, history or autocomplete. **by construction**. *Check:* after
   revealing, and after opening a link that was already used, the URL has no `#…`; the back
   button does not restore it.
4. **Download names are sanitised.** File names come from the sender: normalise (NFC),
   strip control, bidi and path characters, cap the length, render inside `<bdi>`, and
   offer the file as `application/octet-stream` whatever the sender declared.
   **by construction** (`sanitiseFileName` from the package root for your own list).
   *Check:* send a file named `invoice‮fdp.exe` to yourself; the card shows a plain
   name and the download is not an executable name with a reversed extension.
5. **A wrong passphrase costs no round trip, and nothing is lost on failure.** Retries run
   against the header already in memory; the claim token of a single-view secret survives a
   wrong passphrase, a dropped connection and a reload of the page, and is sent again on the
   next attempt while the claim window is open (it is kept in `sessionStorage` for that
   window, item 7). **by construction**. *Check:* reveal a single-view passphrase secret,
   type a wrong passphrase twice, then the right one, with the network tab open: one
   `POST …/secrets/reveal` for all three attempts (besides it only `GET …/config` and,
   after decryption, `POST …/secrets/confirm`), then the secret. Reload between attempts:
   the next attempt sends `claim_token`.
6. **Bodies are capped.** The reveal refuses a body longer than the instance's
   `max_blob_bytes`, whether the server announces the length or not, before buffering it.
   The limit comes from the controller's `maxBlobBytes` option, else the
   `data-shh-max-blob-bytes` attribute, else `/config` read after the press; only when none
   of them can be had is the cap 4 GiB, the largest blob any instance can serve.
   `revealSecret` uses `/config`'s value unless given a smaller one. **by construction**.
   *Why:* D-4 promises bounded client memory whatever the server sends.
7. **Secret material is wiped when it is done and on leave.** On the reveal page, on
   `pagehide`, the seed, the buffered ciphertext and the decrypted file bytes are
   overwritten, the passphrase field, rendered text and file list are cleared, and blob URLs
   are revoked. On the create page the files' plaintext bytes are overwritten as soon as the
   blob is built and the seed and burn token once the links are shown (or the attempt
   fails); on `pagehide` anything still in flight is overwritten and the passphrase field and
   shown links are cleared. Best effort: strings (the note, the links as text) cannot be
   wiped in JavaScript, and the pages say so. **by construction** (`wipeBytes`, `wipePayload`
   for your own state). The one thing kept is the claim token in `sessionStorage` for the
   claim window (item 5).
8. **No expiry information is shown.** Neither the interstitial nor the revealed page says
   how long a TTL secret stays readable; a single-view secret says it is now destroyed.
   **by construction**. *Why:* SPEC §5.2 — every recipient learns to keep what they were
   sent on the first read.
9. **WebAssembly unavailable is a clear failure.** When `WebAssembly` is missing or blocked
   (Tor Browser at "Safer"), a passphrase secret shows a specific message, not "corrupt".
   **by construction** (`loadArgon2` rejects with `argon2_unavailable`). *Check:* Firefox
   with `javascript.options.wasm` set to `false`, or Tor Browser at Safer.
10. **`argon2.wasm` is fetched on every create and reveal page**, whether or not a
    passphrase is involved (D-22). **by construction** (`prefetchArgon2`). *Why:* fetching
    it only when needed tells the network which secrets have passphrases. *Check:* the
    network tab shows the module request on page load of `/` and `/s`.
11. **The empty passphrase is not a passphrase.** A blank field means "none" *before* the
    library is called; the library refuses `""` (`empty_passphrase`). **by construction**.

## The page and its origin

12. **Content Security Policy.** Every page carries at least
    `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self';
    img-src 'self' data: blob:; connect-src <self and the API origin>; form-action 'self';
    base-uri 'none'; frame-ancestors 'none'`, with no inline scripts or styles anywhere and
    no `on*=` attributes. *Check:* the response headers, and that a `<style>` or inline
    handler you add to a page is blocked by the browser.
13. **No external origins.** Fonts, scripts, styles, images and the Argon2 module come from
    the page's own origin; the only other origin a page talks to is the API (and only when
    the API is on its own host). No analytics, no CDN, no web fonts from elsewhere.
    *Check:* the network tab on every page shows the page origin and, at most, the API origin.
14. **`argon2.wasm` is served from your origin** with `Content-Type: application/wasm`
    (`WebAssembly.compileStreaming` requires it). The package ships it as
    `@shhnote/client/argon2.wasm`. Pass its URL to `loadArgon2`/`prefetchArgon2`, or to
    `wireCreate`/`wireReveal` as the `argon2Url` option; without it they use `/argon2.wasm`
    at the page's origin (or `/static/argon2.wasm?v=…` on a page that sets
    `data-shh-asset-version`, as the instance's own pages do).
15. **The frontend's origin is in the instance's `allowed_origins`** when the frontend is not
    on the instance's site origin (D-26), and the frontend never sends credentials with API
    requests.
16. **Security headers on every response** of the frontend host: HSTS, `X-Frame-Options:
    DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive
    `Permissions-Policy`. The instance sets them on everything it serves (HSTS only when
    `SHH_ENV=production`); a static host must be configured to.
17. **No caching of anything per-secret.** The interstitial may be cached (it is static).
    API responses must not be cached by the frontend's CDN or service worker, whatever
    headers they carry: secret blobs are sent with `Cache-Control: no-store`, and `/config`
    changes whenever the operator changes a setting. Do not register a service worker that
    caches API responses.
18. **Copy.** The pages refer to the instance as "this site", name the site and contact
    addresses from the instance's settings, say nothing about view counts, exact sizes or
    remaining time, and describe the lifecycle as SPEC §5 does ("revealed once, then gone").

## Verifying the whole

Run the instance locally (`cargo run -p shhnote-server`, or the image) with `SHH_WEB=api`
and `allowed_origins` set to your dev origin, point the frontend at it, and walk the
checklist once in Firefox and once in Chromium, plus Tor Browser at Safer for item 9. For
the protocol itself, the package's `/crypto` entry is pinned by `vectors/v1.json`; a
frontend does not re-implement it.
