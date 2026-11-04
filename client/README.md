# @shhnote/client

The client side of [shhnote](https://github.com/shhnote/shhnote): secrets are encrypted in
the browser, the server only ever sees ciphertext. This package is what the built-in website
and other frontends are made of.

Three entry points, take the layer you need:

- `@shhnote/client/crypto` — the protocol (SPEC §2): fragments, key derivation, the blob
  format, padding, chunked AES-GCM, the streaming decoder. No `fetch`, no DOM; pinned by the
  conformance vectors.
- `@shhnote/client` — the protocol plus the `Api` client, `getConfig`, `createSecret` /
  `revealSecret` / `burnSecret`, the protocol check (`checkProtocol`,
  `SUPPORTED_FRAGMENT_VERSIONS`), the Argon2 loader, `sanitiseFileName`, `isUserActivation`
  and the wipe helpers. No DOM; runs in browsers, Node and workers.
- `@shhnote/client/ui` — the reference page controllers (`wireCreate`, `wireReveal`,
  `wireBurn`, `wireReport`, …), `createT` and the helpers the reference pages use
  (`formatDuration`, `ttlChoices`, `fillTtl`, `COPIED_MS`). They bind to `data-shh-*` attributes inside a
  root element you give them and take their strings from you; they ship no CSS, and any
  markup they generate is either yours (a `<template>`) or plain elements with `data-shh-*`
  hooks only.

`@shhnote/client/argon2.wasm` is the Argon2id module (the same Rust crate the server uses),
to serve from your own origin; passphrase secrets need it. `@shhnote/client/package.json` is
exported too.

## Scripts, bots and other clients

```js
import { createSecret, revealSecret, Argon2 } from "@shhnote/client";

// The versioned API base: "/api/v1" on the site's host, or "/v1" on an `api.` host.
const api = { apiBase: "https://secrets.example.com/api/v1" };
const { fragment, burnFragment } = await createSecret({
  ...api,
  payload: { text: "the password is hunter2", files: [] },
  lifetime: "single_view",
  ttlSeconds: 86400,
});
// Links: `https://secrets.example.com/s#${fragment}` and `…/burn#${burnFragment}`.
const { payload } = await revealSecret(`#${fragment}`, api);
```

- **Passphrases** need the Argon2 module: `argon2: await Argon2.load(wasmBytes)` (in Node, the
  bytes of `@shhnote/client/argon2.wasm`). A passphrase is a non-empty string; `""` is
  refused (`empty_passphrase`), and omitting it is the only way to mean "none".
- **`/config` comes first.** `createSecret` and `revealSecret` read the instance's
  `GET /config` (once per API base and fetch implementation, through `getConfig`) and throw
  `ShhError("unsupported_protocol")` if its `fragment_version` is not one this package
  supports, before anything is uploaded or claimed. `revealSecret` does not reveal without
  it, and caps the body at the instance's `max_blob_bytes` unless you pass a smaller
  `maxBlobBytes`.
- **Single-view secrets** are consumed by `revealSecret`, and confirmed (destroyed) right away
  unless you pass `confirm: false`. Any failure after the claim (a wrong passphrase, a
  dropped connection, a failed confirm) carries a `claimToken`; pass it back as `claimToken`
  within the claim window and the secret is downloaded again instead of being lost. If only
  the confirm failed, the `ApiError` also carries the decrypted `payload`.
- **Errors** are `ShhError` (the protocol; `code` is stable) or `ApiError` (`status` and the
  server's `code`; status `0` with `network` or `too_large` when no complete answer arrived).
- **`getConfig(apiBase, fetch?)`** is exported: the same cached `/config` the functions use. A
  failed fetch is not kept. A successful one is kept for the life of the page or process, so
  a long-running process picks up a changed instance policy only after a restart (or with a
  fresh fetch implementation).

## The reference controllers (`/ui`)

```js
import { createT, wireReveal } from "@shhnote/client/ui";

wireReveal(document.querySelector("[data-shh-page=reveal]"), {
  t: createT(), // or your own (key, vars) => string
  apiBase: "https://api.secrets.example.com/v1",
  argon2Url: "/argon2.wasm",
});
```

**Strings.** Every controller takes `{ t }`, a function `(key, vars?) => string` over the keys
listed below (`UiKey`). `createT(root?)` builds one from a
`<script type="application/json" data-shh-i18n>{"key": "text", …}</script>` block (inside
`root`, else in the document), filling `{name}` from `vars` and falling back to the key.

**Options.** `wireCreate` and `wireReveal` also take `apiBase`, `argon2Url` and `maxBlobBytes`.
An option wins; otherwise the controller reads `data-shh-api`, `data-shh-asset-version` and
`data-shh-max-blob-bytes` from the root, an ancestor or `<body>` (`pageSettings` resolves
this, if you want to see the result):

- `apiBase`: required one way or the other.
- `argon2Url`: `/static/argon2.wasm?v=<version>` when the page names an asset version (the
  instance's own pages), otherwise `/argon2.wasm` at the page's origin. It must be on the
  page's own origin: `loadArgon2` refuses any other with `argon2_unavailable`, since a module
  from elsewhere could hand every passphrase secret a constant key (SPEC §10).
- `maxBlobBytes`: otherwise both pages use `/config`'s `max_blob_bytes`.

Both pages read `/config` (once, shared through `getConfig`) and check its `fragment_version`
with `checkProtocol`: the create page before it encrypts, the reveal page after the press and
before the reveal request, so a single-view secret is never used up by a page that cannot
open it. If `/config` cannot be read, the reveal page stays armed with
`reveal-error-network`; an unsupported version shows `error-unsupported-protocol`.

`wireBurn` and `wireReport` take the same options; only `apiBase` matters to them.

**States.** Inside a controller's root, every `[data-shh-state="<name>"]` element is hidden
except the one for the current state. Elements the markup below calls "shown" start with
`hidden` and are revealed by the controller once it has checked the page, so nothing works
before the script runs.

**Templates.** Where a controller renders a list item it uses your
`<template data-shh-template="<name>">` when the page has one (its first element is cloned,
looked up inside the root, then in the document), else a plain `<li>` with the same hooks.
Text is always set with `textContent`, never as HTML.

### `wireCreate(root, options)`

- `[data-shh-create-wrapper]`, shown on start, hidden after a create. Inside it
  `[data-shh-form=create]` with a `[data-shh-status]` and a `button[type=submit]`, and the
  fields `note` (text), `passphrase`, `burn` (a checkbox: checked means single view) and the
  lifetime: a `select[data-shh-ttl]`, which is filled from the instance's `ttl_presets` and
  `default_ttl_secs`, labelled by the browser in the page's language, or else any field named
  `expiry` holding seconds.
- Optional `[data-shh-dropzone]` around an `input[type=file]`, with a `[data-shh-file-list]`
  next to it (same parent); hidden when the instance has files off. Items: template
  `dropzone-item` with `[data-shh-file-name]`, `[data-shh-file-meta]` (the size) and
  `button[data-shh-file-remove]`. While files are dragged over it, the zone has
  `data-shh-dragging="true"`.
- `[data-shh-create-result]`, shown after a create, holding `[data-shh-share-link]`,
  `[data-shh-burn-link]` (the links as text), `a[data-shh-open-link]`,
  `[data-shh-chip=lifetime]`, `[data-shh-chip=expiry]`, `[data-shh-passphrase-reminder]`
  (shown when a passphrase was set), `[data-shh-copy=share]`, `[data-shh-copy=burn]`,
  `[data-shh-destroy]` and a `[data-shh-status]`.
- The links are `<page origin>/s#…` and `<page origin>/burn#…`: the frontend must serve
  those paths (see `docs/deploy/own-frontend.md`).
- Strings: `create-encrypting`, `create-uploading`, `create-error-empty`,
  `create-error-too-large`, `create-error-network`, `create-error-failed`,
  `create-error-wasm`, `error-unsupported-protocol`, `result-chip-single`,
  `result-chip-multi`, `result-chip-expires` (`{period}`), `result-destroyed`,
  `form-files-remove`.

### `wireReveal(root, options)`

- States `armed` (the initial one), `working`, `passphrase`, `revealed`, `notfound`.
- `[data-shh-form=reveal]`, shown once the fragment is valid, with its button and a
  `[data-shh-status]`. No API request is sent until that button gets a real click or key
  press (`isUserActivation`); scripted clicks and submits do nothing. The Argon2 module is
  fetched on load either way, so its request says nothing about passphrases.
- `[data-shh-status=working]` for progress.
- `[data-shh-form=passphrase]` with `input[name=passphrase]`, a button and a
  `[data-shh-status]`.
- Inside `[data-shh-state=revealed]`: `[data-shh-lifetime]` with `[data-shh-lifetime-text]`
  (says "destroyed" for a single-view secret, hidden otherwise),
  `[data-shh-text-block]` (shown when there is text) with `[data-shh-text]` and
  `[data-shh-copy=text]`, and the list `[data-shh-files]`. Items: template `file-card` with
  `[data-shh-file-name]` (the sanitised name, in a `<bdi>`), `[data-shh-file-meta]` (type and
  size) and the required `a[data-shh-file-download]` (an `application/octet-stream` blob URL;
  keeps its own label or gets `reveal-download`).
- Strings: `reveal-fetching`, `reveal-decrypting`, `reveal-wrong-passphrase`,
  `reveal-single-view`, `reveal-download`, `reveal-error-network`, `reveal-error-corrupt`,
  `reveal-error-wasm`, `error-unsupported-protocol`.

### `wireBurn(root, options)` and `wireReport(root, options)`

- Burn: states `armed`, `done`, `notfound`; `[data-shh-form=burn]`, shown once the fragment
  is a burn fragment, with its button and a `[data-shh-status]`. Only a trusted submit burns.
  Strings: `burn-working`, `reveal-error-network`.
- Report: state `done`; `[data-shh-form=report]`, shown on start, with `input[name=link]`, a
  button and a `[data-shh-status]`; a `/report#…` URL pre-fills the field. Strings:
  `report-working`, `report-error-invalid`, `reveal-error-network`.

### Smaller pieces

- `wireCopy(button, getText)`: copies, then sets `data-shh-copied="true"` on the button for
  1.5 seconds. The button's content is never touched; show "copied" with your own
  CSS. (A third argument is accepted and ignored, for 0.3.0 callers.)
- `wireDropzone(zone, { t })` returns a `Dropzone` (`files`, `hide()`, `reset()`).
- `wirePasswordToggles(root?)`: `[data-shh-pwd-input]` wrapping an `input` and a
  `[data-shh-pwd-toggle]` button; sets `aria-pressed` and `data-shown`.
- `wireTheme(root?)`: buttons `[data-shh-theme-choice=light|dark|light-hc|dark-hc|auto]` set
  `data-theme` on `<html>` and `aria-checked`, remembered in `localStorage`
  (`shhnote-theme`) when the browser allows.
- `wireMenus(root?)`: closes `details[data-shh-menu]` on outside click, focus loss or Escape.
- `wireTabs(root?)`: `[data-shh-tabs]` with a `[role=tablist]` of `[role=tab][aria-controls]`
  and optional `[data-shh-tab-link]` links. Shows the tab list and sets
  `data-shh-ready="true"` on the container once wired, so your CSS can hide what only makes
  sense without tabs.
- `formatDuration(seconds, locale?)`: a lifetime in its largest whole unit, worded by the
  browser (`Intl`), e.g. "15 minutes", "3 days". `ttlChoices(config)` gives the lifetimes
  `wireCreate` offers (`{ seconds, selected }`), and `fillTtl(select, config, locale?)` fills
  a `<select>` with them. `COPIED_MS` is how long `wireCopy` keeps `data-shh-copied`.

## What is stored and what is wiped

The reveal controller keeps one thing in browser storage: the claim token of a single-view
secret, in `sessionStorage` under `SHA-256(lookup)`, until the claim window closes, the
secret is confirmed or a reveal finds nothing. A reload within the window then downloads the
claimed secret again rather than finding it gone. The theme choice is the only other value,
in `localStorage`.

Secret bytes are overwritten when they are done with and when the page is left (SPEC §10
lists exactly what). For your own state use `wipeBytes(...buffers)` and
`wipePayload(payload)`; the latter overwrites file bytes but cannot touch `payload.text`:
JavaScript strings cannot be overwritten.

## Served bundles, conformance, versions

Every instance also serves the root and `/ui` entries as `/static/shh.js` and
`/static/shh-ui.js`, with `/static/argon2.wasm`, for frontends without a build step on the
same origin as the instance (module scripts load with CORS, which `/static/*` does not send).

A frontend built on this package should meet the frontend conformance checklist in the
repository (`docs/frontend-conformance.md`).

The package is versioned in lockstep with the server: `@shhnote/client` x.y.z is released
together with shhnote x.y.z. Compatibility with an instance is by `fragment_version` in
`GET /config`, which the package checks itself. AGPL-3.0-only.
