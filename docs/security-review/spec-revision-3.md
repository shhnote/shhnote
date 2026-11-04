# Revision 3 — discrepancy fixes (docs, `@shhnote/client` 0.4.0, server)

Status: draft for application. Follows the "Working procedure" in
`spec-revision.md`: one step at a time, stop, propose a commit message, wait
for "next". Sources: `DISCREPANCIES.md` in this repository (ids H*, C*, and
the Medium/Low lists) and the shhnote.com site's discrepancy review
(2026-11-03). Translations in `de/` are updated in the same step as `en/`
for content files; nothing else is translated here.

Decisions taken (2026-11-03):
- The client package is versioned in lockstep with the server; the docs say
  so (C2). This reverses revision 2 §10: amend D-13 ("the client package and
  the server share one version; compatibility is still by `fragment_version`").
- `/ui` controllers take their configuration as options with the
  `data-shh-*` attributes as fallback; markup they generate is replaceable
  by caller templates; the markup contract is documented per controller.
- The claim token is kept in `sessionStorage` for the claim window (C4).
- `shhnote init` already prints to stdout by default (revision 2, 12b); the
  remaining H2 fix is the `--env` write path and the quick-start wording.
- In `SHH_WEB=api` mode the frontend owns `/`, `/s`, `/burn`, `/report` and
  locale negotiation (SPEC §2.2 note; Caddy example in `own-frontend.md`).

## Part A — documentation that breaks third parties (first)

| # | step | checks |
|---|---|---|
| A1 | `content/{en,de}/docs.md`: `lookup_key` and `burn_key` are `SHA-256(lookup)` and `SHA-256(burn_token)`, base64url; the JS example uses `apiBase: "{{api_url}}/v1"`; the `/health` and `/config` examples include `version`, `configured`, `server_version`, `web_mode`, `regions`; error lists gain `invalid_multipart`, `too_busy`, `request_timeout`, `not_configured`. Add a content test that fails if `docs.md` mentions `lookup_key` without `SHA-256` in the same section. | `cargo test -p shhnote-server` |
| A2 | `README.md`: development steps reordered (`scripts/build-client.sh` before any `cargo run`); Docker quick start uses `shhnote init` printing to stdout (`docker run --rm ghcr.io/shhnote/shhnote init >> .env`); revisit after C5; "no cookies" → "no cookies for visitors; the admin panel uses one session cookie". | read-through |
| A3 | `docs/deploy/own-frontend.md`: shape 1 and 2 state that in `api` mode the server serves no `/`, `/s`, `/burn`, `/report` and no locale redirect, so the frontend must serve them at the root and negotiate locale; include the Caddy `Accept-Language` redirect block (with `Vary: Accept-Language`, cache-bypass note) and a sentence for non-Caddy setups; dev section: proxy `/api` in dev rather than cross-origin, or add the dev origin to `allowed_origins`; remove the `allowed_origins` = `SHH_URL` advice; the served `/static/shh*.js` bundles are same-origin only. SPEC §2.2: add "when the website is disabled (`SHH_WEB=api`) the frontend performs this redirect". | none |
| A4 | SPEC §8 and `docs/admin-api.md`: remove the admin `/reports` endpoint; `last_used_on`; timestamps are unix seconds; list `invalid_json`, `invalid_key`, `no_such_key`; name the base path; document `sessions_valid_after` ("end sessions") as API or note it is panel-only. | none |
| A5 | SPEC wording: §3 "one table per migration" → "forward-only migrations, one concern each" and mention `admin_state`; §4 "match a ladder entry exactly" → "be a valid padded size under the policy"; §4 `GET /` sits behind the setup gate and returns `{name, version}` (same fix in `content/*/docs.md`); §6.1 S3 versioning is an error; §6.1 spool-directory wording unchanged (C3 fixes the code); §6.1 orphan sweep: "deletes unreferenced objects with the 22-character name shape and ignores any other file, logging a count" (C2 implements); §8 `check`/`reset-admin` run migrations; §10 `createSecret` etc. live in `client/src/client.ts`; D-13 amended for lockstep (see Decisions); "active" counts include `claimed`. `client/README.md`: lockstep versioning; `fragment_version` check performed by the package (after B5). | `cargo test -p shhnote-server` (docs content test) |

## Part B — `@shhnote/client` 0.4.0

| # | step | checks |
|---|---|---|
| B1 | Export from `/ui`: the `t` implementation reading `data-shh-i18n` (`createT(root)`), and from the root: `getConfig(apiBase)` memoized per base, used by `createSecret`, `wireCreate` and available to callers. `./package.json` added to `exports`. `InstanceConfig` gains `regions`, `server_version`, `web_mode`. | `npm test`, `npm run typecheck` |
| B2 | Controller options: `wireCreate(root, { t, apiBase?, argon2Url?, maxBlobBytes? })` and the same for `wireReveal`; options win, `data-shh-*` attributes are the fallback; `argon2Url` default stays `/static/argon2.wasm?v=…` only when the attribute is present, otherwise `/argon2.wasm`. `wireCreate` reads `ttl_presets`, `default_ttl_secs`, `max_ttl_secs` and `max_blob_bytes` from `getConfig` and fills a `[data-shh-ttl]` select when present; the reference `home.html` drops its hard-coded options. | `npm test`; reference site offers the admin's presets |
| B3 | Replaceable markup: file cards in `wireReveal` and items in `wireDropzone` come from a `<template data-shh-template="file-card">` / `"dropzone-item"` in the page when present, else the built-in markup (now class-free: `data-shh-*` hooks only). `wireCopy` sets `data-shh-copied="true"` for the feedback window and restores it, never touching `textContent`. | `npm test`; reference templates updated to the template form |
| B4 | Claim token persistence (C4): `wireReveal` stores `{claimToken, expiresAt}` in `sessionStorage` keyed by the lookup hash, uses it on the next attempt while the window is open, deletes it on confirm, expiry or 404. Nothing else is stored. | `npm test` with a reload-between-attempts test; conformance item 5 wording "by construction" now true |
| B5 | `fragment_version` check (C3): `createSecret`/`revealSecret` compare `/config`'s `fragment_version` with the versions the package supports and throw `ShhError("unsupported_protocol")` otherwise. | `npm test` |
| B6 | Scrubbing (C7–C9): `wireCreate` wipes seed, burn token and file buffers on `pagehide` and after the result is shown; reveal scrubs the fragment on 404 as well as success; a failed `confirm` after decrypt throws with the claim token and keeps the payload available to the caller. Update SPEC §10 and the conformance checklist to match exactly what is wiped. | `npm test` |
| B7 | Body cap (C10): `revealSecret` without `maxBlobBytes` uses `getConfig().max_blob_bytes` before reading the body; the 4 GiB constant is only the ceiling for a missing config. | `npm test` |
| B8 | `client/README.md`: markup contract per controller (required attributes, optional templates, states toggled, strings used), the options, `getConfig`, `createT`, the `sessionStorage` note, lockstep versioning. `docs/frontend-conformance.md` items 5, 6, 14, 16, 17 reworded to what is true. | read-through |
| B9 | Version: `scripts/bump-version.sh minor` → 0.4.0 after the Part C server fixes (one release for both; controller signatures and hooks changed). | — |

## Part C — server

| # | step | checks |
|---|---|---|
| C1 | Padded-length validation before spooling: validate the declared length against the policy and `files_disabled` from `meta` before the first blob byte is written; the streaming cap is the declared length. | `cargo test` (`spec_resources`: a new case for an invalid declared length refused before any spool file exists) |
| C2 | Orphan sweep: delete unreferenced objects whose name matches the 22-character shape; ignore any other entry and log a count; never fail startup over a stray file. Matches the A5 wording. | `cargo test` with a stray file and an unreferenced valid-name object |
| C3 | Settings: ladder entries must be ≤ `SHH_EXTERNAL_MAX_OBJECT`; `padding_min` kept in buckets mode (validated, not reset); empty region URL rejected. Spool directory: an existing `SHH_SPOOL_PATH` is set to `0700` at startup (or startup fails naming it), so SPEC §6.1's guarantee holds for existing directories. | `cargo test` |
| C4 | `Cache-Control: no-store` on every API response (one layer on the API router); `Retry-After` on admin API and panel login 429s. | `cargo test` (`spec_headers`) |
| C5 | `shhnote init --env <path>`: write through a temp file + rename in the same directory; keep refusing to overwrite set values. README and deploy docs: the Docker quick start uses the stdout form (`docker run --rm ghcr.io/shhnote/shhnote init >> .env`), no bind mount, so the non-root image never needs write access to a host file. | `cargo test`; try the Docker quick start on Linux |
| C6 | `api.rs` comment on report (random bytes are counted), `report.ts` comment (daily counters, no ledger), `reveal.ts` comment (passphrase path collects the body). `.gitignore`/`build.rs` vs tracked `static/app.js`: untrack it (`git rm --cached`), add `shh-ui.js` and `.stamp` to `.dockerignore`. `release.yml` stale comments removed. `scripts/build-client.sh` header "three bundles". | `cargo build` from clean; `git status` clean after a build |
| C7 | Content wording (`en` and `de`): "deleted when opened" → consumed on open, destroyed on confirmation or within the claim window, never served to anyone else; TTL secrets are removed at expiry; reports: "we count reports and removals per day"; expiry rounding: "rounded to a 5-minute, hourly or daily grid"; burn-done: external blobs are removed within a minute; drop "the recipient then sees it was already opened" or say "sees the same not-found message"; drop "operator named on the contact page"; spec links point at `SPEC.md`; `SECURITY.md` placeholder filled, `/{locale}/security`. | `cargo test` (content tests); read-through |
| C8 | Deploy docs: Fly and bare-metal guides add the setup-gate step (site name, contact email); `operations.md` fixes (`SHH_ENV` default, token behaviour, `shhnote health` under subdomain routing, the log line at info level and its exact text); `docker.md` uses `COMPOSE_PROFILES=caddy,postgres`; compose pin `:0.3`; `CHANGELOG.md` 0.2.0 reference. | read-through |
| C9 | CLAUDE.md (`init` in Commands; "Blobs struct over a private Tier enum", no trait) and the four skills (`file-uploads`, `i18n`, `web-page`, `database`) corrected as listed in `DISCREPANCIES.md`. | read-through |
| C10 | `DISCREPANCIES.md`: mark every item resolved with its commit, or "accepted" with a reason; then B9 (bump to 0.4.0) and tag. `CHANGELOG.md`: `## 0.4.0 — unreleased` with the `/ui` signature and hook changes listed under "Changed". | `cargo test`, `npm test`; `v0.4.0-rc.1` first, then `v0.4.0` |
