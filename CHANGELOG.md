# Changelog

User-visible changes, newest first. The protocol is specified in `SPEC.md`; the security
review that preceded 0.3.0, with every finding and fix, has its own record in
`docs/security-review/CHANGELOG.md`.

## 0.4.0 — unreleased

The docs, the client package and the server now say the same thing. A frontend can configure
the `/ui` controllers in code and bring its own markup, and the reference pages honour the
instance's settings. Revision 3 (`docs/security-review/spec-revision-3.md`) has the plan;
`DISCREPANCIES.md` maps each finding to its commit.

### Added
- `getConfig(apiBase, fetch?)`: `GET /config`, fetched once per API base and shared by
  `createSecret`, `revealSecret` and the controllers; a failed fetch is not kept.
  `InstanceConfig` gains `regions`, `server_version` and `web_mode`.
- `checkProtocol` and `SUPPORTED_FRAGMENT_VERSIONS`: `createSecret`, `revealSecret`,
  `wireCreate` and `wireReveal` refuse an instance whose `fragment_version` the package does
  not support (`ShhError("unsupported_protocol")`), before anything is encrypted, uploaded
  or claimed. New string `error-unsupported-protocol`.
- `/ui`: `createT(root?)` (the strings block reader the built-in pages use),
  `formatDuration`, `ttlChoices`, `fillTtl` and `COPIED_MS`. `@shhnote/client/package.json`
  is exported.
- The reveal page keeps a single-view secret's claim token in `sessionStorage`, under
  `SHA-256(lookup)`, until the claim window closes, the secret is confirmed or a reveal finds
  nothing, so a reload within the window downloads it again.
- Admin panel: lifetimes, the claim window and the salt rotation are chosen from durations in
  words; the lifetime presets are checkboxes. The admin API still takes seconds.

### Changed
- `/ui` controller signatures:
  - `wireCreate(root, options)`, `wireReveal(root, options)`, `wireBurn(root, options)` and
    `wireReport(root, options)` take `PageOptions`: `{ t, apiBase?, argon2Url?,
    maxBlobBytes? }`. An option wins over the page's `data-shh-*` attribute. `{ t }` alone
    still works.
  - The Argon2 module defaults to `/static/argon2.wasm?v=…` only when the page sets
    `data-shh-asset-version` (the instance's own pages), otherwise to `/argon2.wasm` at the
    page origin.
  - `wireCopy(button, getText)`: the third argument is accepted and ignored.
- `/ui` hooks: the controllers set no classes and no built-in styling any more.
  - File cards and drop-zone items come from `<template data-shh-template="file-card">` and
    `"dropzone-item"` when the page has them, otherwise plain elements with `data-shh-*`
    hooks only (no `file-card*` or `btn` classes, no icon).
  - Copy buttons get `data-shh-copied="true"` for `COPIED_MS` (1.5 s) instead of having
    their text replaced; `result-copied` is no longer one of the controllers' strings.
  - The drop zone gets `data-shh-dragging="true"` instead of the `is-dragging` class.
  - `wireTabs` sets `data-shh-ready="true"` on its container instead of the `is-ready`
    class.
  - `wireCreate` fills a `select[data-shh-ttl]` with the instance's `ttl_presets` and
    `default_ttl_secs`, labelled by the browser; the reference create page no longer
    hard-codes its lifetimes (the `expiry-*` strings are gone).
- `revealSecret` caps the body at the instance's `max_blob_bytes` unless given a smaller
  `maxBlobBytes`; the reveal page reads `/config` after the press and reveals nothing
  without it (no 4 GiB fallback).
- A failed confirm after a successful decrypt throws an `ApiError` that carries the claim
  token and the decrypted `payload`. The create page wipes the seed, the burn token and the
  file bytes after use and on leave; the reveal page scrubs the fragment on a 404 too.
- The client package is versioned in lockstep with the server (D-13 amended).
- Every API response, and the "shutting down" 503, carries `Cache-Control: no-store`; the
  admin API's and the panel login's 429s carry `Retry-After`.
- An existing spool or blob directory is set to `0700` at startup (with a warning), or the
  server refuses to start.
- `shhnote init --env` writes through a temp file and a rename; the Docker quick start
  appends `init`'s output to `.env` (`docker run --rm ghcr.io/shhnote/shhnote init >> .env`).
- Website wording (`en`, `de`): how single-view secrets are consumed and destroyed, that TTL
  secrets go at expiry, what reports count, the expiry rounding, cookies (none for visitors,
  one sign-in cookie for the admin panel); the specification and security-policy links point
  at `SPEC.md` and `SECURITY.md` (`{{spec_url}}`, `{{security_policy_url}}`).

### Fixed
- The API docs page gave `lookup_key` and `burn_key` as the raw values; they are
  `SHA-256(lookup)` and `SHA-256(burn_token)`. Its client example used an API base without
  `/v1`.
- An upload whose declared length cannot be a valid padded size is refused before any of it
  is spooled.
- A stray file in the blob area (`.DS_Store`, say) no longer stops startup: the orphan sweep
  deletes only unreferenced objects of its own name shape and counts the rest.
- Settings: a padding ladder above the largest blob the instance stores is refused (and
  ignored with a warning at startup); `padding_min` and `padding_ladder` are kept while the
  other mode is in use; an empty region URL is refused.
- Deploy guides: the Fly and bare-metal guides include the setup step; `operations.md`
  (`SHH_ENV` default, token behaviour, `shhnote health` under subdomain routing, the start
  log line), `docker.md` (`COMPOSE_PROFILES=caddy,postgres`) and `own-frontend.md` (root
  paths and locale redirect in `api` mode, same-origin bundles) are corrected; the README's
  development steps are in build order.
- `static/app.js` is no longer tracked.

## 0.3.0 — 2026-11-02

The built-in website becomes a minimal reference frontend, the client becomes a package, and
an instance says who runs it before it serves anything.

### Added
- `@shhnote/client` on npm, with three entry points: `/crypto` (the protocol, no network, no
  DOM), the root (adds the API client, `createSecret`/`revealSecret`/`burnSecret` with
  claim-token retry and a body cap, and the frontend-safety helpers) and `/ui` (the reference
  page controllers, bound by `data-shh-*` attributes with injected strings). Every instance
  also serves the root and `/ui` entries as `/static/shh.js` and `/static/shh-ui.js`.
- `SHH_WEB=api`: serve the API, the admin panel and `/static/*` only, for operators who run
  their own frontend (`docs/deploy/own-frontend.md`, `docs/frontend-conformance.md`).
- `SHH_ADMIN_ROUTING=subdomain`: the admin panel on `admin.<host>/<locale>/` instead of
  `/<locale>/admin`, with a host-only session cookie.
- `allowed_origins` setting: other origins whose frontends may call the API from a browser;
  CORS is sent on both routing modes for the site origin plus the list.
- The server version on `GET /config` (`server_version`), `GET /health` (`version`), every
  page footer and the `{{version}}` content placeholder; `GET /config` also reports
  `web_mode`.
- First-run setup gate: until an admin key exists and the site has a name and a contact
  address, every public page and API call answers 503 with a setup page (or
  `not_configured` for the API); `/health` reports `configured`. The two settings cannot be
  cleared once set.
- `shhnote init`: generates `SHH_SECRET_KEY` and `SHH_ADMIN_TOKEN`, printed or written into
  an env file (`--env <path>`) without overwriting a set value. The deployment guides use it
  as the first command.
- `project_url` setting, shown in the footer and available to content pages as
  `{{project_url}}` (falling back to `source_url`); `{{site_name}}`, `{{contact_email}}`,
  `{{security_email}}` placeholders for the policy pages.
- Admin panel: "End sessions" on a key; `reset-admin` and a changed bootstrap token end
  earlier bootstrap sessions; settings save and key creation redirect, the new key is shown
  once.

### Changed
- The built-in website is a reference frontend: the create form, the reveal, burn and report
  pages, the policy pages, a short how-it-works and the public API docs. The marketing
  sections, the technical breakdown and the FAQs are gone; every page speaks of "this site"
  and takes the site name and contact addresses from settings. The admin API documentation
  moved to `docs/admin-api.md`.
- A neutral default theme ("Slate"): same four themes and token names (plus `--ring`,
  `--notice-text` and `--shadow`), zinc neutrals, self-hosted Geist and Geist Mono, a single
  720px column with titles above cards. A frontend with its own look builds on the client
  package.
- `site_name` has no default; `security_email` falls back to `contact_email`.
- An empty passphrase is refused by both libraries (`empty_passphrase`); omitting it is the
  only way to mean no passphrase.
- A TTL secret's reveal says nothing about its remaining time; single-view secrets keep
  their "destroyed" message.
- Dependencies trimmed (axum, tokio, sqlx features); crate metadata, `deny.toml`,
  `rust-toolchain.toml`; the release pipeline pins actions and images, builds reproducible
  archives and publishes provenance.

### Fixed
- Everything in the security review: see `docs/security-review/CHANGELOG.md`, where each
  finding is mapped to its commit.

## 0.1.0 — release candidates only (2026-10-29 to 2026-10-31)

The first version: end-to-end encrypted single-view or time-limited secrets, text and files,
optional passphrase, Padmé padding, uniform negatives, reports, rate limiting without stored
addresses, SQLite or Postgres, inline, local-disk or S3 blobs, an admin panel and admin API,
English and German. Tagged as `v0.1.0-rc.4` to `rc.6`; never released as `0.1.0`, since the
security review and this revision followed directly.
