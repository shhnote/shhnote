# Revision 4 — round-2 review fixes

Status: draft for application. Follows the "Working procedure" in
`spec-revision.md`: one step at a time, stop, propose a commit message, wait
for "next". Source: `round-2/SUMMARY.md` (ids R-n, C-n, suspicions S-n),
tree `85f83a7` (0.4.0-rc.1). `de/` content is updated in the same step as
`en/`. The `review_r2_*` test files stay in the tree until step D3 converts
them.

Decisions taken (2026-11-04):
- **`max_blob_bytes` is a bucket** (R-6). The server's body limit is
  `blob_len(max_blob_bytes) + framing slack`; the client compares the
  padded size at create and caps the body at `blobLen(max_blob_bytes)` at
  reveal. SPEC §4 and §10 say so in one sentence each.
- **One process owns an external tier** (R-4). §6.1 states it; deploys are
  stop-before-start; the startup sweep and `clear_parts` additionally
  age-gate on object time (older than the upload deadline) and re-check the
  rows after listing. The age gate reads the timestamps §6.1 already lists
  as an accepted residual and writes nothing.
- **Duplicate-create timing is a recorded residual** (R-5), under D-21: the
  answer is identical, the work differs by one rollback vs one commit;
  exploiting it needs a dump, yields one sample per secret and is bounded
  by the create limit. The `/reports` row-size timing (suspicion 1) is
  recorded with it. No work-equalising writes.
- **`init --env` keeps the file's mode** (R-10); it warns when that mode
  grants group or other read, and the docs create `.env` under
  `umask 077`.
- **The CORS layer covers the public API only**; the admin API is
  same-origin (Bearer from a page script was never a supported path). §4
  says so.
- **An unconfigured `api`-mode instance answers the JSON 503** on every
  non-admin path, never the HTML setup page. D-29 says so.
- Release-environment reviewers (R-26) stay deferred with the npm staging
  decision; a `v*` tag ruleset is set on GitHub by hand (not in the tree).

## Part A — spec and decisions (text only)

| # | step | checks |
|---|---|---|
| A1 | SPEC: §4 `max_blob_bytes` is the largest padded size (bucket) accepted; §10 the client compares the padded size and caps the body at `blobLen(max_blob_bytes)`; §4 D-21 gains the timing residual (create and `/reports`); §4 CORS covers the public API only; D-29 api-mode 503 is JSON; §6.1 single-process ownership, stop-before-start, age-gated sweep; §7.1 the trailing-slash normaliser is skipped for public paths in `api` mode; §8 `init --env` warns on a permissive mode; §10 `sessionStorage` note (browsers persist it for session restore; the entry is the claim token and its expiry only, for the window). `docs/frontend-conformance.md` item 6 in bucket terms; items 5, 8, 10 with their qualifications (`argon2.wasm` and `/config` fetches; "destroyed" after confirm; prefetch only with a valid fragment). | none |
| A2 | Pass-0 public-page wording (en + de): `privacy.md` — the server never logs IPs; a reverse proxy or CDN in front may; `secret` interstitial — "cannot be opened again by anyone else" and, for TTL, "until it expires"; result page — "Destroyed" only after confirm succeeds (string change; the controller change is B13); `how-it-works.md` "fetches nothing" → "sends nothing about the secret" (the WASM prefetch is same-origin and carries no identifier); deploy guides — before setup, `/health`, `/static/*`, the admin panel and admin API are open; stop budgets note the 30 s drain + 5 s grace and recommend 45 s; `reverse-proxies.md` body limit in bucket terms and "one attempt per 180 s" for the login bucket; `site_name` help text (title and header). | `cargo test -p shhnote-server` (content tests) |
| A3 | Pass-0 internal wording: CLAUDE.md "a setting touches four places" (list them); i18n skill (content pages, `data-shh-*` names); web-page skill names; database skill (no reports table); file-uploads skill (ceiling via the ledger); api-endpoint skill (remove the pagination example); D-8 wording; `note_not_found` example. `deploy/caddy/Caddyfile` gains the commented `admin.` block, referenced from `bare-metal.md` (R-28). | read-through |

## Part B — server

| # | step | checks |
|---|---|---|
| B1 | **R-1.** Arm the `OrphanGuard` with the key before `put`; the reservation is released only after the guard's delete has completed on the drop path (or the row is written). Local and S3. | `review_r2_adversarial::…disconnect…` flipped to assert no uncounted object; `spec_disconnect_after_upload_leaves_no_uncounted_object` asserts the ceiling immediately, not after restart |
| B2 | **R-3.** Timeout on every `read_up_to` (versioning check, listing pages, error bodies, put/delete success check); reuse `get`'s per-frame idle adapter. | `review_r2_pass2` S3-headers-then-stall test passes; server starts when the store stalls after headers (fails fast with the error named) |
| B3 | **R-2.** Rolling minimum rate on uploads: deadline = start + received/32 KiB + grace, checked per chunk; `SHH_MAX_UPLOADS` permit taken after `meta` validates and the first blob chunk arrives; `docs.md` notes `Content-Length` for chunked clients. | `review_r2_adversarial` trickle test passes; 64 trickles do not block an ordinary create |
| B4 | **R-6.** Body limit `blob_len(max_blob_bytes) + slack`; `check_blob_limit` on the bucket; `/config` unchanged. `padding_min ≤ max_blob_bytes` enforced in settings (suspicion 4). | `review_r2_pass2` top-bucket test: `201` at the advertised maximum; `review_r2_pass0` flipped |
| B5 | **R-4.** Startup sweep and `clear_parts`: only entries older than the upload deadline, and `external_refs` re-checked after listing; `operations.md` and the Fly/bare-metal guides: one process per tier, stop-before-start, the window a rolling deploy would hit. | `review_r2_pass2` two-process test passes |
| B6 | **R-7.** `bootstrap_sessions_valid_after = now` inside `delete_api_key`'s transaction when the deleted key had `admin` scope. | `review_r2_pass4 finding_bootstrap…` passes; `spec_bootstrap_session_does_not_come_back` extended to the panel and API delete paths |
| B7 | **R-8.** Substitute placeholders into the Markdown source before rendering (text nodes), never into rendered HTML; same for `{{version}}`. | `review_r2_pass4 finding_site_name…` passes; a `site_name` of `<meta http-equiv=refresh …>` renders as text |
| B8 | **R-9.** `init --env`: parse lines the way dotenvy does (`export` prefix, whitespace around `=`, quoted values); a key present in a form `init` cannot judge, or more than once, is an error naming the line, never an append; `KEY=""` and `KEY= # c` count as empty and are filled. **R-10:** warn on stdout when the kept mode grants group/other read; README, `docker.md`, `.env.example`: `umask 077` before creating `.env` and `chmod 600 .env`. | `review_r2_adversarial` X tests pass; `spec_init_subcommand` extended |
| B9 | **R-11, R-12, R-13.** Gate matches the panel's exact routes (unknown `/admin/…` gets the 503 before setup); setup page's link is `Ctx::admin_url()` (absolute to the admin host in subdomain mode); trailing-slash 308 skipped for public paths in `api` mode; api-mode 503 is JSON on every non-admin path (D-29 decision). | `review_r2_adversarial` R/S tests pass; `spec_setup_gate`, `spec_api_mode_serves_no_pages` extended |
| B10 | **R-14, R-15, R-16, R-17.** Scrubber: `ORDER BY lookup_key`, cursor after the last key of the previous batch, wrap; failed keys logged once per tick. Gate: cache the negative admin-key count until an admin write (`create_api_key`, settings save) sets a dirty flag; acquire bounded like `ping`; never cache a positive. `text_only_bucket` falls back to the ladder's largest rung and `save_settings` refuses `files_enabled=false` with a ladder below the text-only size. Admin stats `?days=` rejection → shared JSON 400. Suspicion 7: `is_configured` distinguishes a database error from zero keys (503 `degraded` body, not the setup page). Suspicion 9: `collect_orphans` logs and continues on a delete error. Suspicion 8: skip `touch_api_key`'s `UPDATE` when `last_used_on` is today. | `review_r2_pass2` R-14/R-15 tests pass; new tests for R-16, R-17, suspicions 7–9 |

## Part C — `@shhnote/client`

| # | step | checks |
|---|---|---|
| C1 | **R-19, R-20, R-23.** `getConfig` validates `InstanceConfig` (`Number.isSafeInteger`, ranges, shapes) and throws `invalid_config`; `max_blob_bytes` clamped to the 4 GiB ceiling; malformed `Content-Length` treated as absent; on `400 invalid_blob_length`/`files_disabled` drop the cache and retry once with a fresh `/config`; export `invalidateConfig(apiBase)`; reveal uses `Math.min(options.maxBlobBytes ?? Infinity, config.max_blob_bytes)` and the attribute only as the create page's early hint. | `npm test`; `review_r2_pass5` F-5-2/3/6 flipped |
| C2 | **R-6 client side, R-18.** `createSecret` compares `encrypted.bucket` with `max_blob_bytes`; `revealSecret` and the reference page cap the body at `blobLen(max_blob_bytes)` and pass `Math.min(cap, contentLength)` to the decoder; the manifest's size sum is checked against `maxPayload − 4 − manifestLen` before allocating. | `npm test`; `review_r2_pass0` flipped; `review_r2_pass5` F-5-1 flipped |
| C3 | **R-21.** `loadArgon2` refuses a URL whose origin differs from `location.origin` when `location` exists; README option list says so. | `npm test` |
| C4 | **R-22.** TypeScript refuses `"size": -0`; duplicate-key rejection limited to known keys (matching serde); both as `reject[]` vectors; `v1.json` regenerated. | `cargo test -p shhnote-core`, `npm test` |
| C5 | **R-24, R-25, C-2.** `pwd.fill(0)` in `Argon2.hash`'s `finally`; wipe `lookupValue` and null `claimToken` on `pagehide` when no confirm is in flight; reveal page maps `429` and `503` to a "try again shortly" string and `too_large` to its own, keeps "corrupt" for `ShhError` only (new Fluent strings en + de); the create page enforces `text_max_bytes` from `/config` (counts bytes, shows the limit). Suspicion 11: `wireReveal` validates a caller file-card template at wire time (download anchor present) before anything is decrypted. Suspicion 12: `file.type` sanitised and `<bdi>`-isolated; `createT` tolerates a `null` block. Suspicion 10: `pageshow` with `event.persisted` reloads the reveal and create pages. | `npm test`; `review_r2_pass5` F-5-7/8 flipped |
| C6 | **R-5 client note / B13 "Destroyed".** The result state shows "Destroyed · this was the only view" only after `confirm` succeeds; before that, "Revealed". | `npm test`; conformance item 8 now exact |
| C7 | `client/README.md`: `invalidateConfig`, the same-origin `argon2Url` rule, the config validation, the bucket semantics of `max_blob_bytes`, template validation, the `sessionStorage` note. | read-through |

## Part D — pipeline, tests, release

| # | step | checks |
|---|---|---|
| D1 | **R-27.** Weekly `schedule:` for the `audit` job; `.github/dependabot.yml` for actions, docker, cargo and npm (grouped, weekly). **R-26 partial:** `release.yml` comment pointing at the `v*` tag ruleset; no environment yet. | `actionlint` |
| D2 | **R-29.** Test databases named by test, deleted by a drop guard, under `target/tmp`. | `cargo test` leaves nothing under `/tmp/shhnote-tests` |
| D3 | Convert `review_r2_*` tests: flip the ones asserting old behaviour, rename all to `spec_r2_*`, remove duplicates of existing `spec_*`, make `cargo clippy --all-targets` and `cargo fmt --check` green. | `cargo test --workspace`, `npm test`, clippy, fmt |
| D4 | Postgres run (suspicion 15): `SHH_TEST_PG_URL` set, the claim race, counter upserts, scrubber ordering and sweep tests once; fix anything engine-specific. | green on Postgres |
| D5 | `round-2/SUMMARY.md`: a closing table mapping every R-n and C-n to its commit or "accepted residual (§…)"; `CHANGELOG.md` 0.4.0 entries; `scripts/bump-version.sh release` → 0.4.0; tag. | `v0.4.0` |
