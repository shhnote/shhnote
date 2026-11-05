# Changelog

What changed for a consumer of `@shhnote/client`, newest first. The package is versioned in
lockstep with the shhnote server; the server's own changes are in the repository's
`CHANGELOG.md`. Every release lists the `UiKey`s (the strings the `/ui` controllers ask `t`
for) it added and removed, so a frontend can update its strings block from this file alone.

## 0.4.1 — 2026-11-04

### Changed
- `wireBurn` and `wireReport` take `Pick<PageOptions, "t" | "apiBase">`: passing `argon2Url`
  or `maxBlobBytes` to them is a type error, since neither did anything there.

### Fixed
- The `dropzone-item` template is looked up in the `wireCreate` root first, then in the
  document, as the README's "Templates" section says. It was looked up next to the zone, so a
  template placed elsewhere in the root was found only through the document, and two create
  forms on one page could pick the wrong one. `wireDropzone(zone, { t }, root?)` takes the
  root; without it the zone's parent is used, as before.
- README: the create page fetches the Argon2 module at `argon2Url` as soon as it is wired,
  passphrase or not (D-22); a page's own `<link rel="prefetch">` for it is harmless and not
  needed. This was only documented for the reveal page.

### UiKeys
- Added: none.
- Removed: none.

## 0.4.0 — 2026-11-04

### Added
- `getConfig(apiBase, fetch?)` and `invalidateConfig(apiBase, fetch?)`: `GET /config`, fetched
  once per API base and shared by `createSecret`, `revealSecret` and the controllers; a failed
  fetch is not kept. `createSecret` and the create page invalidate it once when the instance
  refuses a blob's size (`isStalePolicyError` is exported) and pad again.
- `checkProtocol` and `SUPPORTED_FRAGMENT_VERSIONS`: an instance whose `fragment_version` the
  package does not support is refused (`ShhError("unsupported_protocol")`) before anything is
  encrypted, uploaded or claimed. `InstanceConfig` gains `regions`, `server_version` and
  `web_mode`.
- `/ui`: `createT(root?)`, `formatDuration`, `ttlChoices`, `fillTtl`, `COPIED_MS` and
  `revealErrorKey`. `@shhnote/client/package.json` is exported.
- The reveal page keeps a single-view secret's claim token in `sessionStorage` until the claim
  window closes, so a reload within the window downloads it again.

### Changed
- The `/ui` controllers take an options object: `wireCreate(root, options)`,
  `wireReveal(root, options)`, `wireBurn(root, options)` and `wireReport(root, options)` with
  `PageOptions` `{ t, apiBase?, argon2Url?, maxBlobBytes? }`. An option wins over the page's
  `data-shh-*` attribute; `{ t }` alone still works.
- `argon2Url` must be on the page's own origin: `loadArgon2` refuses any other with
  `argon2_unavailable`. It defaults to `/static/argon2.wasm?v=…` only when the page sets
  `data-shh-asset-version`, otherwise to `/argon2.wasm` at the page origin.
- `max_blob_bytes` in `/config` is a bucket, the largest padded size the instance accepts, not
  a blob byte count. `createSecret` compares the padded size with it; `revealSecret` caps the
  body at `blobLen(max_blob_bytes)` or a smaller `maxBlobBytes` (a byte count) and bounds the
  decoder by the announced length. The reveal page no longer uses `data-shh-max-blob-bytes`.
- `/config` is validated before use (`ApiError(0, "invalid_config")` otherwise, with
  `max_blob_bytes` clamped to 4 GiB); an instance without `server_version` or `web_mode` is
  refused the same way.
- Template hooks: the controllers set no classes and no built-in styling. File cards and
  drop-zone items come from `<template data-shh-template="file-card">` and `"dropzone-item"`
  when the page has them, otherwise plain elements with `data-shh-*` hooks only. A `file-card`
  without its download anchor is refused when `wireReveal` is called. The drop zone gets
  `data-shh-dragging="true"` and a wired `wireTabs` container `data-shh-ready="true"` instead
  of classes.
- `wireCopy(button, getText)` sets `data-shh-copied="true"` on the button for `COPIED_MS`
  instead of replacing its text; the third argument is accepted and ignored.
- `wireCreate` fills a `select[data-shh-ttl]` with the instance's `ttl_presets` and
  `default_ttl_secs`, labelled by the browser; the create page refuses a note over
  `text_max_bytes`.
- A failed confirm after a successful decrypt throws an `ApiError` carrying the claim token
  and the decrypted `payload`. Both pages wipe their secret material on leave and reload
  themselves when restored from the back-forward cache.
- `reveal-single-view` now reads "Revealed"; the destroyed wording moved to
  `reveal-single-view-destroyed`, shown once the confirm succeeded.

### UiKeys
- Added: `create-error-text-too-long` (`{max}`), `reveal-single-view-destroyed`,
  `reveal-error-busy`, `reveal-error-too-large`, `error-unsupported-protocol`.
- Removed: `result-copied`.

## 0.3.0 — 2026-11-02

The first release of the package, with three entry points: `/crypto` (the protocol, no
network, no DOM), the root (the API client, `createSecret` / `revealSecret` / `burnSecret`
with claim-token retry and a body cap, and the frontend-safety helpers) and `/ui` (the
reference page controllers, bound by `data-shh-*` attributes with injected strings).
`@shhnote/client/argon2.wasm` is the Argon2id module. An empty passphrase is refused
(`empty_passphrase`); omitting it is the only way to mean none.

### UiKeys
- The initial set: `form-files-remove`, `result-copied`, `result-destroyed`,
  `result-chip-single`, `result-chip-multi`, `result-chip-expires`, `create-encrypting`,
  `create-uploading`, `create-error-empty`, `create-error-too-large`, `create-error-network`,
  `create-error-failed`, `create-error-wasm`, `reveal-fetching`, `reveal-decrypting`,
  `reveal-wrong-passphrase`, `reveal-single-view`, `reveal-download`, `reveal-error-network`,
  `reveal-error-corrupt`, `reveal-error-wasm`, `burn-working`, `report-working`,
  `report-error-invalid`.
