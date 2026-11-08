# Changelog

User-visible changes, newest first. The protocol is specified in `SPEC.md`; the security
review that preceded 0.3.0, with every finding and fix, has its own record in
`docs/security-review/CHANGELOG.md`.

## 0.6.1 — unreleased

### Fixed
- The S3 tier starts with a bucket-scoped Cloudflare R2 token (Object Read & Write), the
  least-privilege credential. R2 has no bucket versioning, so the startup versioning check
  is skipped there; on other providers a `403` on that check is logged as a warning instead
  of refusing to start. Wrong credentials still fail the start, at the bucket listing,
  whose error now names the call. The operations guide lists the permissions per provider
  (#10).
- `shhnote --version` and `shhnote --help` work without any configuration, and an unknown
  command is refused before the configuration is read, instead of after connecting to the
  database and applying migrations (#4).
- Bare-metal guide (#4, #9): the environment file is `0600`, as `shhnote init` asks;
  the health endpoint is `/api/v1/health`, not `/health` (also in the Docker, Fly and
  operations guides); the local tier keeps blobs in `<SHH_LOCAL_PATH>/blobs/`; the
  archive check has a command. A new "Network access" section explains the unit's
  `IPAddressAllow` for a remote Postgres or object store, with `IPAddressAllow=any` for
  R2 and AWS S3, which have no fixed address; it also covers where `DynamicUser` keeps
  the state and how to run commands by hand as the service's user.

## 0.6.0 — 2026-11-06

Upgrading: replace `subdomain` with `domain` in `SHH_API_ROUTING` and `SHH_ADMIN_ROUTING`
before starting the new version.

### Changed
- `SHH_API_ROUTING` and `SHH_ADMIN_ROUTING` take `domain` instead of `subdomain` (the old
  value is refused with a hint). New `SHH_API_DOMAIN` and `SHH_ADMIN_DOMAIN` name the API
  and panel hosts under that routing, so an instance at `eu.example.com` can answer on
  `api-eu.example.com` instead of `api.eu.example.com`; the defaults are unchanged.
- The operations guide says what changing `SHH_URL` affects.

## 0.5.0 — 2026-11-06

Upgrading: add a unit to the size variables in `.env` before starting the new version.

### Changed
- Sizes in `.env` (`SHH_INLINE_MAX`, `SHH_EXTERNAL_MAX_OBJECT`, `SHH_LOCAL_MAX_TOTAL_BYTES`,
  `SHH_S3_MAX_TOTAL_BYTES`) and in the admin panel (`padding_min`, `padding_ladder`,
  `text_max_bytes`) are written with a unit: `100B`, `64K`, `10M`, `1G` (powers of 1024).
  A bare number is refused, so add a suffix to `.env` values before upgrading; stored
  settings are converted by a migration. The admin API takes these settings as strings
  with a unit. `/config` still reports bytes.

## 0.4.1 — 2026-11-04

Client package only (`client/CHANGELOG.md` has the consumer-facing entries, and now ships in
the package with every added or removed `UiKey` listed per release). The `dropzone-item`
template is looked up in the `wireCreate` root, as the README says, so two create forms on
one page each use their own; `wireBurn` and `wireReport` refuse the options they ignore at
the type level; the README says that the create page fetches the Argon2 module on wire.

## 0.4.0 — 2026-11-04

The docs, the client package and the server now say the same thing. A frontend can configure
the `/ui` controllers in code and bring its own markup, and the reference pages honour the
instance's settings. Revision 3 (`docs/security-review/spec-revision-3.md`) has the plan;
`DISCREPANCIES.md` maps each finding to its commit.

A second security review ran on 2026-11-04 (`docs/security-review/round-2/SUMMARY.md`: one
High, four Medium, twenty-four Low, and a claims audit of every document). Revision 4
(`docs/security-review/spec-revision-4.md`) applied the fixes; the summary's closing table
maps each finding to its commit or to the residual `SPEC.md` now records.

### Added
- `invalidateConfig(apiBase, fetch?)` drops the cached `/config`; `createSecret` and the create
  page use it once when the instance refuses a blob's size (`invalid_blob_length`,
  `files_disabled`: the padding policy changed since `/config` was read) and pad again
  (`isStalePolicyError` is exported). `revealErrorKey(e)` from `/ui` names the string a
  failed reveal shows.
- New strings: `reveal-error-busy` (a rate limit, a restart or an instance not yet set up),
  `reveal-error-too-large`, `reveal-single-view-destroyed` (shown once the confirm
  succeeded; `reveal-single-view` now reads "Revealed") and `create-error-text-too-long`
  (the create page refuses a note over the instance's `text_max_bytes`).
- `.github/dependabot.yml` (actions, images, crates and npm packages, weekly, grouped) and a
  weekly run of CI's `audit` job.
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
- `max_blob_bytes` in `/config` is the largest padded size (bucket) the instance accepts, on
  both sides now: the server's body limit is `blob_len(max_blob_bytes)` plus framing, so the
  largest advertised bucket is always accepted; the client compares the padded size when
  creating and caps a reveal at `blobLen(max_blob_bytes)` (or a smaller `maxBlobBytes`, a
  byte count), bounding the decoder by the announced length. The reveal page no longer uses
  the `data-shh-max-blob-bytes` attribute for its cap.
- `/config` is validated before use (shapes and ranges; `ApiError(0, "invalid_config")`
  otherwise, with `max_blob_bytes` clamped to 4 GiB); `loadArgon2` refuses a module URL on
  another origin; the manifest parser refuses a file size of `-0` and ignores duplicated
  unknown keys, as the Rust core does (new reject vector `file-size-negative-zero`).
- Uploads must keep 32 KiB/s overall after a 60 s grace (the deadline moves with every byte
  received), and an upload takes an `SHH_MAX_UPLOADS` slot only once 64 KiB of blob has
  arrived; `docs.md` asks clients to send `Content-Length`.
- One process owns an external tier: deploys stop before they start (guides updated), and the
  startup sweep and spool cleanup leave entries younger than the longest possible upload
  alone, re-checking the rows after listing. The sweep logs and continues past an object it
  cannot delete. The scrubber walks parked rows in key order from a cursor, so undeletable
  objects never hide the ones behind them.
- The setup gate opens exactly the panel's routes; an unconfigured `SHH_WEB=api` instance
  answers the JSON `not_configured` envelope on every non-admin path; a database error at
  the gate is a JSON 503 `degraded`, not the setup page; the negative state is cached until an
  admin write (or a second). In `api` mode a trailing-slash public path is a 404, not a 308.
  The setup page's login link is absolute to the admin host in subdomain mode.
- `shhnote init --env` reads lines the way the server does (`export`, spaces around `=`,
  quoted values): a set value is kept in any form, an empty one is filled, a key set twice or
  in a form it cannot judge is an error; it warns when the file's mode lets others read it.
  README, `docker.md` and `.env.example` create `.env` under `umask 077` / `chmod 600`.
- Deploy artefacts give stops 45 s (30 s drain plus 5 s to close connections); the bare-metal
  Caddyfile carries the commented `admin.` block; CLAUDE.md and the skills describe the four
  places a setting lives, the root-level migrations, the `data-shh-*` names and the ledger.
- `last_used_on` is read before it is written, so a keyed request no longer takes SQLite's
  write lock for a no-op; `touch_api_key` otherwise unchanged (D-23).
- Both reference pages reload themselves when restored from the back-forward cache; the
  reveal page wipes the lookup value and claim token on leave once no confirm is retrying, and
  checks a caller's `file-card` template when wired, before any secret is shown.
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
- A create whose client disconnected while the object store was acknowledging the write left
  an object the ceiling did not count until the next restart; the guard is now armed before
  the write and the reservation is released only once the object is confirmed gone (R-1).
- S3 bodies other than downloads (the versioning check, listings, error bodies, the put and
  delete acknowledgements) had no timeout; a store that stalls after its headers no longer
  hangs startup, the scrubber or an upload slot (R-3, completing S-12).
- Deleting the last admin key through the panel or the admin API revived a bootstrap session
  issued before that key; the deletion now records the cut-off as `reset-admin` does (R-7,
  reopening S-39).
- `{{site_name}}` and the other placeholders were substituted into the policy pages' rendered
  HTML unescaped; every value is HTML-escaped now (R-8).
- `files_enabled=false` with a bucket ladder too short for a text-only secret refused every
  create; the combination is refused on save and corrected at startup (R-16). A bad `?days=`
  on the admin stats endpoint answers the shared JSON error shape (R-17). `padding_min` above
  the largest blob the instance stores is refused.
- Website wording: the server never logs addresses (a proxy in front may); the reveal page
  "sends nothing about the secret" before the press; "Destroyed" is said only after the
  confirm; deploy guides name what stays open before setup; the proxy guide gives the body
  limit in padded-size terms and the login bucket's refill rate.
- The test suite leaked one SQLite file per test per run into the system temp directory;
  databases now live under `target/tmp/shhnote-tests`, named by the test and replaced on each
  run (`SHHNOTE_TEST_DB_DIR` moves them). The round-2 review tests are the `spec_r2_*` files.
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
