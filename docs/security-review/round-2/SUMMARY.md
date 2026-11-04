# Security review, round 2 — synthesis (pass 8)

Date: 2026-11-04. Tree: `85f83a7` (0.4.0-rc.1), clean before the review. Inputs: `pass0-claims.md`, `pass1.md` … `pass7.md` in this directory. Nothing was fixed and nothing was committed; the working tree holds only the eight findings files and the `review_r2_*` test files listed at the end.

How to read the ids: `R-n` is a merged round-2 item; the "from" column lists every pass finding it absorbs. "Pass 7" says whether the adversarial pass, which saw only `SPEC.md`, `CHANGELOG.md` and the code, hit the same thing independently (**yes** = reproduced with a test in `review_r2_adversarial.rs`; *no* = in its property list but not found; – = outside its list). "Pass 0" marks items the claims audit also reached from the documentation side.

Baseline: the `spec_*` regression suites pass. `cargo test --workspace --no-fail-fast` is green on every binary (core 59 + 5 + 8, server 33 unit + `api` 23 + `spec_*` 81, store 15, one `#[ignore]` by design); `npm test` 64/64; `npm run typecheck` clean (scratchpad `baseline-tests.log`, three runs). Two environmental failures preceded the green run and are not findings against the server: the first `cargo test` stopped in `build.rs` because the embedded-asset stamp predated the 0.4.0-rc.1 version bump (S-53's designed refusal; `scripts/build-client.sh` fixed it), and the second run hit SQLite "database or disk is full" because `/tmp/shhnote-tests` holds 4.3 GB of databases the test helper never deletes (R-29). `SHH_TEST_PG_URL` was unset: everything below is SQLite; Postgres-specific behaviour (claim race, counter upserts, scrubber ordering) was not exercised this round.

## Round 1 regressions

| S-n | status | round-2 item | what happened |
|---|---|---|---|
| S-39 | **reopened** (one path) | R-7 | A bootstrap session issued before the first admin key is accepted again once the last admin key is deleted through the panel or `POST /api/v1/admin/keys/delete`; only `reset-admin` records `bootstrap_sessions_valid_after`. `spec_bootstrap_session_does_not_come_back` still passes because it tests the `reset-admin` path only. |
| S-12 | **incomplete** | R-3 | Connect, response-header and streamed-`get` timeouts exist; every other S3 body read (`read_up_to`) has none. A store that sends headers and stalls hangs startup, the scrubber task and an upload slot. `spec_hung_s3_does_not_hang_scheduler_reveal_or_create` covers a store that never answers, not one that answers headers only. |
| S-9 | **residual** | R-5 | The duplicate-create *answer* is identical (D-21 holds); the *work* differs by a rollback vs a write-and-commit, measurable in-process. |
| S-46 | **incomplete** | R-22 | Six parity cases are pinned by vectors and hold; two unpinned shapes (`"size": -0`, a duplicated unknown key) still decode differently in Rust and TypeScript. |
| S-20 | narrowed, not reverted | R-18, R-19 | The library streams and caps as promised; the reference page passes the instance maximum instead of the response length to the decoder, and nothing validates `/config` or `Content-Length` before they become the cap. |
| S-5 | by construction, one gap | R-1 | Spool bytes, pre-spool checks and startup orphan collection hold (`spec_spool_bytes_count_toward_the_ceiling`, `spec_invalid_declared_length_is_refused_before_spooling`, `spec_orphan_objects_are_collected_at_startup`). The gap pass 7 found is between `put` returning and the guard being armed; round 1's `spec_disconnect_after_upload_leaves_no_uncounted_object` observed zombies there and asserted only that a restart removes them. |

Every other S-n was re-verified by the pass that owns its area (each `pass<n>.md` has a "Round-1 regression check" subsection with the test name or `path:line`): S-1 to S-4, S-6 to S-8, S-10, S-11, S-13 to S-19, S-21 to S-38, S-40 to S-45, S-47 to S-58 hold. Pass 7 re-attacked properties A to Q blind and broke none of them.

## 1. Ranked findings

### High

| id | sev | one line | location | from | pass 7 |
|---|---|---|---|---|---|
| R-1 | High | A create whose client disconnects while the object store is acknowledging the `PUT` leaves an object nobody counts: the `OrphanGuard` is armed only after `put` returns, the dropped `Reservation` gives its bytes back, no row is written, and the tier grows past `SHH_LOCAL_MAX_TOTAL_BYTES` / `SHH_S3_MAX_TOTAL_BYTES` until the next restart's sweep (one object of up to `SHH_EXTERNAL_MAX_OBJECT` per aborted upload, bounded only by the create rate limit) | `api.rs:480-492`, `storage.rs:239-245, 439-444, 596-613` | F-7-1 (pass 2's "reservation released on disconnect" check covers the reservation, not the object) | **yes** (own finding) |

Severity note: pass 7 rated R-1 Medium because each hit costs an upload. It is kept High here because the rubric and the pass 2 prompt both call a way around a tier ceiling High (as S-5 was), the ceilings are the one limit Principle 7 calls absolute, and the attack is a client half-close after the last byte, which round 1's own disconnect test already produced without trying. For S3 the window is the store's commit-to-response latency on every upload; for local disk it is the rename.

### Medium

| id | sev | one line | location | from | pass 7 |
|---|---|---|---|---|---|
| R-2 | Medium | Trickling uploads (one byte per < 30 s) satisfy the per-chunk idle timeout and hold an `SHH_MAX_UPLOADS` permit, and their declared size against the ceiling, for the whole upload deadline: 34 min at the default 64 MiB cap, 36 h at 4 GiB; 64 such connections (three /64s under the 30/h create limit) answer every other create `503 too_busy`, and 16 of them keep an external tier at `507` | `api.rs:286-309, 318-323, 398-414, 757-764` | F-7-2, F-2-6 | **yes** |
| R-3 | Medium | S-12 incomplete: S3 bodies read by `read_up_to` (versioning check, listing pages, every error body, `put`/`delete` success check) have no timeout; a store that sends headers and stalls hangs `Blobs::open` (the server never starts), the scrubber for good, and an upload slot plus its reservation and spool (create has no request timeout) | `storage.rs:570, 612, 646, 667, 807-851`; `api.rs:482-485` | F-2-1 | – |
| R-4 | Medium | Two server processes on one external tier (a rolling or blue/green deploy with Postgres + S3, which nothing forbids) destroy each other's work: the new process's startup sweep deletes an object whose row the old one is about to write (creator got `201`, secret lost without a counter), and its `clear_parts` unlinks the old process's in-flight spools (uploads fail `500`) | `storage.rs:137-156, 425, 557`; `api.rs:482-497`; `main.rs:114-135` | F-2-2, pass 3 and pass 1 suspicions | – |
| R-5 | Medium | S-9 residual: `POST /secrets` answers a duplicate identically but does less work (unique-index failure and rollback vs row write, `created` upsert and commit); in-process on SQLite the medians differ by 27 % at 64 KiB and 19 % at 1 MiB, so a dump holder can tell from timing whether the victim's row still exists and plant their own row at the moment it goes (needs a hash, one transition sample per secret, bounded by the create limit) | `api.rs:463-471`; `secrets.rs:74-102` | F-1-1 | – (pass 7 measured the same class on `/reports`, see suspicions) |

### Low

| id | sev | one line | location | from | pass 7 | pass 0 |
|---|---|---|---|---|---|---|
| R-6 | Low | `max_blob_bytes` is a *bucket* on the server (`bucket > max` refused, body limit `max + 16 KiB`) and a *blob length* in the client (`blob.length > max`, `Content-Length > max`): the advertised top bucket is `413` on the default 64 MiB tier (its tags alone exceed the 16 KiB slack from 1019 chunks on), and below that the server stores and serves blobs the reference reveal page claims and then refuses with `too_large`, consuming a single-view secret unread; `reverse-proxies.md` repeats the unit slip | `api.rs:150-151, 340-359, 442-444, 666-677`; `client.ts:62`; `lib/api.ts:148`; `padding.rs:98-102` | F-3-1, F-2-5, C-27, C-49 | – | **yes** |
| R-7 | Low | S-39 reopened: a bootstrap cookie revives when the last admin key is deleted via the panel or admin API (`delete_api_key` never writes `bootstrap_sessions_valid_after`) | `admin.rs:179-183, 856-875`; `admin_api.rs:370-379`; `api_keys.rs:100-106, 140-152` | F-4-1 | no (M held for the paths it tried) | – |
| R-8 | Low | `{{site_name}}` (and the other placeholders) are string-replaced into the already-rendered HTML of the policy pages without escaping: an admin-set name injects markup, including a `<meta http-equiv="refresh">` redirect that CSP does not govern | `web.rs:630-647`; `settings.rs:168-171` | F-4-2 | – | – |
| R-9 | Low | `init --env` recognises only `KEY=` at line start; for `export KEY=…` or `KEY = …` (both read by dotenvy) it appends a second definition, and since `read_dotenv` collects into a `HashMap` the appended value wins: the operator's `SHH_SECRET_KEY`/`SHH_ADMIN_TOKEN` are silently replaced, and the new token is never printed; `KEY=""` / `KEY= # c` are reported "kept" although dotenvy reads them as empty | `init.rs:52-67`; `config.rs:658-666` | F-3-2, F-4-4, F-7-5 | **yes** | – |
| R-10 | Low | The Docker quick start creates `.env` under the user's umask (`curl -o`, `>>`), and `init --env` keeps an existing file's mode by design, so the session key, bootstrap token and any Postgres/S3 credentials end up world-readable with no warning; only a file `init` creates is `0600` | README.md:22-23; docs/deploy/docker.md:13-21; deploy/docker/.env.example:21-25; `init.rs:116-124` | F-6-1, F-7-6, pass 1 suspicion | **yes** | – |
| R-11 | Low | Before setup, `/{locale}/admin/<unknown>` (and `/{locale}/admin/../s`) passes the gate's prefix match, misses every panel route and renders the website's full 404 page with navigation and footer instead of the setup 503 | `app.rs:121-128`; `web.rs:219-244` | F-3-3, F-7-3 | **yes** | – |
| R-12 | Low | With `SHH_ADMIN_ROUTING=subdomain` the setup page's only call to action, "Open the admin panel", is the path-relative `/en/login` on the main host, which answers the setup page again (503) and a 404 once configured | `templates/setup.html:19`; `web.rs:128-131, 315-317`; `app.rs:140-145` | F-4-3, pass 1 suspicion | – | – |
| R-13 | Low | In `SHH_WEB=api` mode every trailing-slash path answers a `308` (`/en/` → `/en`) because the normaliser runs before routing on every host and mode; D-24 and §7.1 say every public route is `404` (pass 4's walk recorded the 308 and accepted it) | `app.rs:82, 179-199` | F-7-4 | **yes** (own finding) | – |
| R-14 | Low | The scrubber selects the same first 200 `pending_delete` rows every tick (no ordering, no skip), so 200 persistently undeletable objects block every later delete for ever and their bytes keep counting toward the ceiling (`507` with nothing live stored); a restart does not help | `secrets.rs:331-350`; `scheduler.rs:52-77` | F-2-3 | – | – |
| R-15 | Low | While `site_name` and `contact_email` are set but no admin key exists (reachable from a bootstrap session), the setup gate runs `SELECT COUNT(*) FROM api_keys WHERE scopes = 'admin'` (no index) for every unauthenticated request, outside every rate limit and the request timeout, with sqlx's 30 s acquire | `api.rs:78-87, 269-274`; `app.rs:86, 110`; `api_keys.rs:130-135` | F-2-4, pass 3 suspicion | – | – |
| R-16 | Low | `files_enabled = false` with a buckets ladder whose top rung is below `2 × text_max_bytes + 1 KiB` makes `text_only_bucket` return 0, so every create, text-only included, is refused `files_disabled`; the settings save accepts the combination | `api.rs:553-559, 341-345, 447-449`; `settings.rs:152-279` | F-3-4 | – | – |
| R-17 | Low | `GET /api/v1/admin/stats?days=abc` answers axum's `text/plain` 400 instead of the shared JSON error shape (authenticated admins only) | `admin_api.rs:139` | F-3-5 | – | – |
| R-18 | Low | The reference reveal page passes the instance maximum, not the response length, to the decoder, so a 64 KiB hostile blob whose manifest claims a `max_blob_bytes`-sized file makes every recipient allocate that much before the truncation is seen (`revealSecret` already uses `Math.min(cap, contentLength)`) | `ui/reveal.ts:130-131, 154`; `crypto/stream.ts:110, 142` | F-5-1 | – | – |
| R-19 | Low | Nothing validates `/config` or `Content-Length` before they become the body cap: a non-numeric `max_blob_bytes` or `Content-Length` turns every comparison into `NaN` and switches the cap off; a numeric value is not clamped to the 4 GiB ceiling | `lib/api.ts:98, 119-120, 146-150`; `client.ts:118, 125` | F-5-2 | – | – |
| R-20 | Low | `getConfig` caches a successful `/config` for the life of the page or process, so after the operator changes the padding policy every later create from an open page or a running bot fails `invalid_blob_length` until reload; the panel promises live application | `lib/api.ts:185-205`; `ui/create.ts:97-113, 192-204` | F-5-3 | – | – |
| R-21 | Low | `argon2Url` is not held to the page's origin in code (only the built-in CSP enforces it): a third-party frontend can load the KDF module cross-origin, and a hostile module silently reduces every passphrase secret to seed-only protection | `lib/argon2-loader.ts:20`; `ui/dom.ts:70` | F-5-4 | – | – |
| R-22 | Low | S-46 residual: `"size": -0` is a 0-byte file in TypeScript and a manifest error in Rust; a duplicated *unknown* key is a manifest error in TypeScript and ignored by serde; neither is a vector | `crypto/container.ts:44-48, 129-130`; `container.rs:10, 23, 28, 94` | F-5-5 | – | – |
| R-23 | Low | On the reveal page `data-shh-max-blob-bytes` (read at load) wins over the fresher `/config` value, so a tab left open across a raised limit claims a single-view secret and then refuses its body | `ui/reveal.ts:36, 130`; `ui/dom.ts:67-71` | F-5-6 | – | – |
| R-24 | Low | Scrubbing residuals outside §10's list: the encoded passphrase handed to WASM is never wiped on the JavaScript side; `lookupValue` and `claimToken` survive `pagehide` | `crypto/argon2.ts:45, 57-63`; `ui/reveal.ts:60-64, 72-83` | F-5-7 | – | – |
| R-25 | Low | The reveal page shows "couldn't be decrypted, the link may be incomplete" for `429`, the drain and setup `503`s and an over-cap body; a recipient asks for a new link and the sender's resend is the only way out of a single-view | `ui/reveal.ts:166-169, 202-203` | F-5-8 | – | – |
| R-26 | Low | A single `v*` tag push by any write-access account publishes `@shhnote/client` (OIDC trusted publishing), the `latest` image and the GitHub release with provenance attestations vouching for it: no `environment:` with required reviewers on `publish`/`release`/`manifest`, and whether a tag ruleset exists is not visible in the tree | `.github/workflows/release.yml:3-5, 81-144, 203-241` | F-6-2 | – | – |
| R-27 | Low | Advisory checks run only on push (no `schedule:`), and nothing bumps the action SHAs, image digests or lockfiles round 1 pinned; the `rust:1.99-alpine` digest is already one base-image rebuild behind its tag | `.github/workflows/ci.yml:3-8, 87-104`; `Dockerfile:10` | F-6-3 | – | – |
| R-28 | Low | The bare-metal Caddyfile has no `admin.` site block (with the `remote_ip` allow-list) although the Docker Caddyfile and `reverse-proxies.md` show and require it for `SHH_ADMIN_ROUTING=subdomain` | `deploy/caddy/Caddyfile:1-10` vs `deploy/docker/Caddyfile:14-19` | F-6-4 | – | – |
| R-29 | Low | The test helper `sqlite_path_for_tests` names databases by pid and never deletes them: 13 622 files / 4.3 GB under `/tmp/shhnote-tests` filled the 7.8 GB tmpfs and broke the baseline run (test harness, not product code) | `crates/shhnote-store/src/lib.rs:210-217` | F-7-7, noted by passes 0, 1, 2, 3 | **yes** | – |

Severity notes:
- R-2 merges pass 2's Low (the ceiling half, "a 4× cheaper variant of an accepted property") and pass 7's Medium (the permit half). Kept Medium: the permits are the server's own cap on its core function, the hold lasts hours on an external tier, and the cost to the attacker is a few bytes a minute from three addresses. Principle 7 makes it hardening in letter; in effect it is a cheap, long-lived denial of creates.
- R-5 is Medium as S-9 was: it needs a dump and yields one sample per secret. It should be decided together with pass 7's `/reports` timing suspicion (§5), which is the same class (same statement sequence, different work by row size).
- R-6 is the one item three passes reached from three sides (resources, Rust correctness, claims). No bytes over the cap are ever stored, so Low, but it is the first thing an integrator following `/config` and §6.1 literally will hit.

## 2. Duplicates merged

| merged into | came from | note |
|---|---|---|
| R-1 | F-7-1; pass 2's "OrphanGuard spawns its delete" suspicion (the shutdown variant of the same gap) | Pass 2 tested that the reservation is released on disconnect (`review_r2_pass2_reservation_is_released_on_duplicate_and_disconnect`); pass 7 showed that the release is the problem when the object already exists. |
| R-2 | F-7-2, F-2-6 | Same mechanism (idle timeout per chunk, far-off total deadline), two resources (permits, ceiling). |
| R-4 | F-2-2, pass 3 suspicion "orphan sweep across processes", pass 1 suspicion "two instances on one S3 bucket" | |
| R-6 | F-3-1, F-2-5, C-27, C-49 | Pass 2 found the 413 at the top bucket, pass 3 the unit mismatch and the unreadable stored secret, pass 0 the reference page refusing a legitimate blob (reproduced in `client/test/review_r2_pass0.test.ts`). |
| R-9 | F-3-2, F-4-4, F-7-5; pass 3 suspicion "key present twice" | Three passes, same two lines of `init.rs`; pass 3 adds the empty-value misreport. |
| R-10 | F-6-1, F-7-6, pass 1 suspicion | Pass 6 blames the quick start, pass 7 the silent keep-mode; both are true and the fix differs (docs vs a warning or a spec change). |
| R-11 | F-3-3, F-7-3 | |
| R-12 | F-4-3, pass 1 suspicion | |
| R-15 | F-2-4, pass 3 suspicion | |
| R-29 | F-7-7, environmental notes in passes 0, 1, 2, 3 | |

## 3. Proposed fixes checked against SPEC §12 and §13

Allowed = can be done in code without touching the spec. Needs spec revision = the fix is fine under the principles but changes something the spec states, or the spec is silent where it should not be. Rejected = the fix would violate a principle or re-propose a §13 item.

| id | proposed fix (short) | verdict |
|---|---|---|
| R-1 | Arm the `OrphanGuard` (holding the key) before `put`, keep the reservation alive until the guard's delete has run on the drop path; optionally run the orphan sweep periodically from the scheduler | Allowed (Principle 7 asks for it) |
| R-2 | Rolling minimum rate in `next_chunk` (deadline = start + received / 32 KiB + grace) or shrink the idle allowance as the upload stalls; take the permit after `meta` is validated and the first blob chunk arrives; mention `Content-Length` in `docs.md` for chunked clients | Allowed. §7.1 already claims "header, idle and request timeouts"; the rate is the missing piece. |
| R-3 | `tokio::time::timeout` around `read_up_to`'s `collect()` (or reuse `get`'s per-frame idle adapter) | Allowed. §6.1's "body timeouts" then becomes true. |
| R-4 | Age-gate the sweep and `clear_parts` (only objects/spools older than the upload deadline, re-check `external_refs` after listing), or state single-process ownership and stop-before-start in §6.1 and the deploy guides | **Needs spec revision** either way: §6.1 says "an object without a row is garbage" and "at startup the server … deletes unreferenced objects" without the single-process assumption. The age gate uses the object timestamps §6.1 already lists as an accepted residual, so it adds no new stored fact. |
| R-5 | Run the `+0` counter upsert and a commit on the duplicate path (removes the upsert-and-commit half of the gap), or record the timing residual under D-21 in §4 with the rate limit and one-sample bound as the reasons | **Needs spec decision**: the code matches §4's words today; either the words gain "after the same work" for create or the residual is recorded. Writing and discarding comparable bytes to match the row-write half is allowed but worth weighing against the threat. |
| R-6 | Decide what `max_blob_bytes` means (bucket is the least disruptive reading): body limit `blob_len(max) + FRAMING_SLACK`; client compares `encrypted.bucket` at create and caps the body at `blobLen(max)` at reveal; fix `reverse-proxies.md` | **Needs a one-line spec clarification** in §4/§10; then allowed. |
| R-7 | Write `bootstrap_sessions_valid_after = now` whenever an admin-scoped key is deleted (inside `delete_api_key`'s transaction) | Allowed. Keeps sessions stateless (§8); the timestamp is instance-level state the spec already has. |
| R-8 | HTML-escape every substituted setting before `.replace`, or substitute into the Markdown source before rendering so placeholders become text nodes | Allowed (web-page skill rule) |
| R-9 | Decide "set" the way dotenvy does (`export` prefix, whitespace around `=`, quoted-empty); refuse rather than append when a key appears in a form `init` cannot judge or more than once | Allowed |
| R-10 | Docs: `umask 077` / `chmod 600 .env` in README, docker.md and `.env.example`; code: print a warning when the kept mode grants group/other read | Warning and docs allowed. Tightening the mode to `0600` **needs a spec revision** of §8 ("keeping its permissions"). |
| R-11 | Give the admin routes nested into `pages()` a fallback like the admin-host variant, or match the gate to the panel's exact routes | Allowed |
| R-12 | In subdomain mode render the setup page's link as an absolute URL to the admin host (`Ctx::admin_url()`) | Allowed |
| R-13 | Skip the trailing-slash redirect for non-API, non-admin paths when `web == Api` | Allowed (D-24 asks for it). Alternative: say in §7.1 that the normaliser's 308 is exempt (wording). |
| R-14 | Rotating cursor (`ORDER BY lookup_key`, start after the last key of the previous batch, wrap) or skip keys that failed this tick; log once per tick | Allowed |
| R-15 | Cache the negative result briefly or re-derive only after an admin write (`create_api_key`, settings save) via a dirty flag; bound the acquire like `ping` | Allowed. D-29's "derived while unmet" does not require per-request. |
| R-16 | Fall back to the ladder's largest rung in `text_only_bucket`, or refuse the combination in `save_settings` with a message | Allowed (§7.2 "range-checked as a whole") |
| R-17 | `Result<Query<_>, QueryRejection>` → `error_response(400, "invalid_query")` | Allowed |
| R-18 | `decryptBody(…, Math.min(maxBlobBytes, revealed.contentLength ?? maxBlobBytes))`; cap the manifest's size sum at `maxPayload − 4 − manifestLen` before allocating | Allowed (D-4) |
| R-19 | Validate `InstanceConfig` in `getConfig` (`Number.isSafeInteger`, ranges, shapes) and throw `invalid_config`; `Math.min(configured, DEFAULT_MAX_BLOB_BYTES)`; treat a malformed `Content-Length` as absent | Allowed |
| R-20 | On `400 invalid_blob_length`/`files_disabled` drop the cached entry and retry once with a fresh `/config`; or a short TTL plus an exported `invalidateConfig(apiBase)` | Allowed |
| R-21 | In `loadArgon2`, refuse a URL whose origin differs from `location.origin` when `location` exists; say so in the README option list | Allowed (Principle 10, §10 "fetched same-origin") |
| R-22 | TypeScript: refuse `-0`, refuse duplicates only among known keys (or Rust: `deny_unknown_fields`); add both as `reject[]` vectors | Allowed; regenerating `v1.json` before the first deployed instance is what `vectors/README.md` permits |
| R-23 | On the reveal page use `Math.min(options.maxBlobBytes ?? Infinity, config.max_blob_bytes)`; keep the attribute for the create page's early hint only | Allowed |
| R-24 | `pwd.fill(0)` in `Argon2.hash`'s `finally`; wipe `lookupValue`/null `claimToken` on `pagehide` when no confirm is in flight | Allowed (§10 best effort; extends the list) |
| R-25 | Map `429`/`503` to a "try again in a moment" string and `too_large` to its own; keep "corrupt" for `ShhError` only | Allowed (new Fluent strings per the i18n skill) |
| R-26 | `environment: release` with required reviewers on `publish`/`release`/`manifest`, register it with npm's trusted publisher, add a `v*` tag ruleset | Allowed (GitHub/npm-side) |
| R-27 | Weekly `schedule:` for the `audit` job; `.github/dependabot.yml` for actions, docker, cargo, npm | Allowed |
| R-28 | Mirror the commented `admin.` block into `deploy/caddy/Caddyfile`, reference it from bare-metal.md | Allowed (docs/artefact) |
| R-29 | Name test databases by test name, delete in a drop guard, or use `target/tmp` | Allowed (tests only) |

**Rejected by principle:** none. Three things to watch while fixing: (a) R-4's age gate must read object timestamps, never write a per-secret time anywhere the spec does not already accept (§6.1 residual); (b) R-5 must not add a per-secret row or timestamp to equalise work (§13 "terminal-status tombstones"); (c) R-15's cache must never let the gate answer "configured" from stale state (D-29 "derived while unmet"): caching the *negative* only is safe.

**Decisions the spec should take even without a code change** (surfaced by passes 4 and 1, not findings):
- The CORS layer wraps the whole API router, admin API included, so a listed origin may call `/api/v1/admin/*` with a Bearer key. Credentials are never allowed and admin keys live nowhere a page script can read, so no reachable surface is added; §4 should say whether the admin API is meant to be cross-origin.
- An unconfigured `SHH_WEB=api` instance serves the HTML setup page on public paths (D-29 answers before D-24). Harmless; D-29 or §7.1 should say so, or api mode should answer the JSON 503.
- CORS preflights behind the setup gate get the 503 envelope with no `Access-Control-*` headers (the gate is outside the CORS layer), so a cross-origin frontend sees an opaque error instead of `not_configured`. Usability only.

## 4. Rediscovered accepted residuals

| rediscovered as | already recorded in | note |
|---|---|---|
| Pass 7 K: a `user` key and a secret correlate at day level on a one-secret day | D-23, §8 | The accepted resolution; nothing finer is stored (`review_r2_pass1_last_used_on_is_a_day_on_every_path`). |
| Pass 1: the admin `active` count moves on confirm, burn and expiry | §8 "live active count", CHANGELOG suspicion 12 | It no longer moves on the reveal itself (claimed rows are counted). |
| R-4's proposed age gate reads local `mtime` / S3 `LastModified` | §6.1 accepted residual (S-17) | The residual becomes load-bearing if that fix is taken. |
| Pass 5 F-5-7 (R-24) and the bfcache suspicion | §10 "best effort" | §10's list is otherwise exact; R-24 extends it rather than contradicting it. |
| Pass 5: a 256 MiB Argon2 blob holds memory until the page is left | §2.9 | Unchanged. |
| Pass 7 P: a browser driven with real input events reveals; `requestSubmit()`/`click()` do not | §5.1 accepted residual | Re-proved blind in `client/test/review_r2_adversarial.test.ts`. |
| Pass 1: `sessionStorage` is persisted to disk by browsers (session restore), so the claim token and lookup hash can sit in the recipient's profile for the window | §10 names `sessionStorage`; the on-disk consequence is not recorded | Candidate sentence for §10 and the privacy page ("no cookies" is true; the one storage entry is not mentioned there, pass 0 note). |
| Pass 2: a download in flight at SIGTERM is cut after about 5 s; the claimant re-downloads with the token after restart | D-1, §5.1 window semantics | The window keeps running while the server is down; worth a line in operations.md. |
| Pass 0 C-25: `argon2.wasm` is prefetched on `/s` only once a valid fragment decodes | D-22 | The D-22 property (passphrase vs direct indistinguishable) holds; the wording "on every reveal" should carry the qualification. |

## 5. Suspicions worth a follow-up

Each with the experiment that settles it. Deduplicated across passes.

1. **`/reports` work scales with the destroyed row** (pass 7). Same statement sequence, but a matched report deletes `blob_len(bucket)` bytes under `secure_delete`; 1 MiB inline rows measured 1.48 ms (existed) vs 0.62 ms (missing) in-process. Experiment: loopback HTTP at `SHH_INLINE_MAX = 64 MiB`, 200 samples each. If it survives the network it is a Low under §4 and belongs with R-5 (one decision: equalise, or record the residual). A constant-cost delete (park inline rows for the scrubber too) is a design change.
2. **SQLite write lock held across S3 `open` on the single-view claim** (pass 7): `begin_claim` has written when `open_blob` talks to S3 (up to 20 s of timeouts); other writers wait `busy_timeout` (5 s) and fail with a 500. Experiment: point the `fake_s3` hang harness at a claim and time a concurrent create. Needs a slow store; a fix would open the object inside a shorter window or retry the claim.
3. **One-chunk spool overshoot** (pass 7): the chunk is written before `written > cap` is checked, so a spool can exceed its reservation by one hyper read buffer (~400 KiB) before refusal. Bounded by `SHH_MAX_UPLOADS` × chunk. Experiment: a real socket sending the body in one write; check the cap first if confirmed.
4. **`padding_min` has a floor and no ceiling** (passes 5, 7; pass 4's crafted-form test did not include it). `PATCH {"padding_min": 4294967296}` is stored; `/config` advertises it; every create fails and the create page allocates `padme(padding_min)` before its size check. Experiment: the PATCH, then `/config` and a create. Fix: `padding_min ≤ max_blob_bytes` in `check_blob_limit`, and a client-side `paddedSize > max_blob_bytes` check before allocating.
5. **CORS `Max-Age: 86400` outlives an origin's removal** (pass 4): a browser with a cached preflight still sends the real `POST /secrets/reveal`, which claims the single-view secret although the page cannot read the answer. Needs a browser; a short `Max-Age` closes it.
6. **A forged `Host` reaches the admin router** (pass 4): host-based routing by design; the `remote_ip` allow-list must live in a proxy that also rejects unknown `Host` values, and the listener must not be reachable directly. `reverse-proxies.md` says half of this. Documentation.
7. **A database outage at startup reads as "not set up"** (pass 4): `is_configured` treats a failed `admin_key_count()` as zero, so a configured instance shows the setup page until the database returns. Experiment: start with the database down. Fix: distinguish `Err` from `Ok(0)`.
8. **Every keyed request takes the SQLite write lock** (pass 2): `touch_api_key`'s no-op `UPDATE` begins a write transaction; contends with sweeps and claims. Experiment: claim latency under 600/h keyed reveals during a 200-row sweep. Fix: read `last_used_on` with the key row and skip the `UPDATE` when it is today.
9. **An undeletable valid-shaped orphan fails startup** (pass 3): `collect_orphans` propagates the first `delete` error. Operator-controlled; `log_error!` and continue would match the "never fail startup over a stray" intent.
10. **bfcache restore after `pagehide`** (pass 5): the seed is zeroed, the passphrase form submits to nothing, the create page's copy buttons keep the links in closures. Experiment in Firefox and Chromium; a `pageshow` handler with `event.persisted` that reloads or re-arms.
11. **A caller file-card template without the download anchor** throws after the text is in the DOM and the fragment scrubbed, consuming a single-view secret without confirming (pass 5). Validate the template once at `wireReveal` time.
12. **`file.type` is neither sanitised nor bidi-isolated** in the reveal meta line (pass 5); `createT` on a literal `null` block throws (pass 5). Cosmetic and robustness.
13. **GitHub-side release gates** (pass 6): whether a `v*` tag ruleset and an npm trusted-publisher environment binding exist is not in the tree; confirm in the settings, which decides how much of R-26 remains.
14. **Caddy locale-redirect block and `//s`** (pass 6): `307 /en//s`, relative (not an open redirect) but the frontend must serve it. **`deny.toml` targets** omit the musl targets the release binary uses; same graph today.
15. **Postgres** was not exercised this round (`SHH_TEST_PG_URL` unset): the claim race, concurrent counter upserts, the scrubber's `LIMIT` without `ORDER BY` (R-14's order is engine-dependent) and `WITHOUT ROWID`-equivalent ordering deserve one run with the Postgres service CI already has.

## 6. Properties tested and holding

For the security page or threat model. Each was exercised by a review test this round on the current code; names are in the pass files.

- **Setup gate (D-29).** In all eight router modes (`full`/`api` × path/subdomain admin × host asked) and for every method, every public page and API path is `503` with `no-store`, the full §11 header set and a body that is byte-identical for a planted secret and a random one, never names the bootstrap token, and touches no row; exactly `/health`, `/static/*`, the admin panel on its host and the admin API stay open; configuring through the API flips `/health` to `configured: true`; `site_name`/`contact_email` cannot be cleared by form or API; the state is sticky in-process and re-derived at restart (1 376 responses walked by pass 4; `spec_setup_gate`; `r2_r_…`). Exceptions: R-11, R-15.
- **`SHH_WEB=api` (D-24).** No public page, no locale redirect, no `/`; `404` bodies are bare text with the full header set; `/static/*`, `/health`, the API and the panel work; `/config` says `web_mode: api`. Exception: R-13.
- **Admin subdomain (D-25).** Host matching is case-insensitive and ignores the port; prefixes, suffixes, trailing dots, an empty or missing Host, IPv6 literals and absolute-form targets never cross routers or panic; the path form is byte-identical to an ordinary 404 on the main host; the cookie has no `Domain` (host-only), is refused by the admin API, and presenting it on the main host hits no route; CSRF is bound to the session nonce; the admin host serves no API and no public page.
- **CORS (D-26).** `Access-Control-Allow-Origin` only for the literal site origin and `allowed_origins` entries, echoed exactly, case-insensitively; `null`, trailing slash, path, explicit default port, scheme change, look-alike hosts, subdomains of an allowed origin and empty origins get no CORS headers (only `Vary: Origin`); `Access-Control-Allow-Credentials` never appears and `cookie` is never an allowed header; preflights are `204`, `no-store`, do no database work, reach no rate limiter and never read the body (a 50 MB preflight body is answered at once); pages and `/static/*` carry no CORS headers; a PATCH with one bad origin changes nothing.
- **`shhnote init` (§8).** Values are 32 `getrandom` bytes (43 base64url characters); the no-argument form prints `KEY=value` to stdout only; `--env` writes through a `create_new` `0600` temp file in the target's directory, fsyncs, renames, copies mode and (best effort) owner, removes the temp file on every failure, leaves the old file intact when the directory is read-only, follows a live symlink, fills an empty `KEY=` in place, appends a missing key, never overwrites a plain set value, and prints no value with `--env`. Exceptions: R-9, R-10.
- **Version (D-27).** `CARGO_PKG_VERSION` only, in `/config`, `/health`, the footer and `{{version}}`; no git hash, build date, `Server` or `Date` header; nothing admin-controlled is adjacent and every rendered occurrence is escaped.
- **Expiry grid and claim rounding (D-18).** For every TTL in `[60 s, 14 d]` and every `now` from 0 to `i64::MAX`: `now + ttl ≤ expires_at < now + ttl + grid`, on the grid, boundaries exactly at 3600 and 259 200, no panic or wrap (`saturating_add`, `rem_euclid`); every creation second inside one step maps to the same stored value; `claim_expires_at` is a whole minute in `(now, now + window + 60]`; the sweep predicates are exact complements of the read predicates, so nothing is both servable and sweepable; no response or page carries remaining time; the admin `active` count does not move on a reveal.
- **Reports (D-19, S-16).** No reports table in any migration; `report` runs `reports +1`, destroy, `removed +N` in one transaction for every input, malformed and `null` bodies included; live, missing, claimed, burned, already-reported, malformed, non-JSON and no-Content-Type reports share status, headers and body; 50 concurrent reports count exactly 50; the dump holds no trace of a reported secret. Exception: the row-size timing suspicion (§5.1).
- **`last_used_on` (D-23).** 00:00 UTC of the day, written only when it differs, on all three call sites (keyed requests, panel login, admin API); idempotent within a day; a race across midnight writes two days, both days; the admin API and panel expose a date, never a time; the creating key's hash occurs in the dump exactly as often as an idle key's.
- **Orphan sweep (§6.1).** Only `blobs/` + exactly 22 base64url characters, unreferenced by any row (parked rows included), is deleted; directories, non-UTF-8 names, hidden files, short/long names and nested files are counted and left; symlinks of valid shape are removed as links; the S3 listing follows pages and stops on the continuation token; startup never fails over a stray entry; the log carries counts only; a live secret still reveals afterwards. Exception: R-4 (two processes).
- **Spool and ceiling (D-20, S-4, S-5).** Declared lengths of 0, 95, 96, one short of the smallest valid blob, far over the cap and `u64::MAX/2` are refused before any byte reaches disk; a plausible declared length with junk is spooled no further than reserved plus one chunk and the spool, `blobs/` and the reservation are all clean afterwards; 100 aborted uploads leave 0 spool files; 16 concurrent creates against room for 2 yield exactly 2 × `201`; 4 paused uploads on a full tier keep spool + stored ≤ ceiling; the reservation is released once on duplicate, disconnect and failed insert and never twice; the ledger's arithmetic cannot underflow or overflow. Exceptions: R-1, R-2.
- **Claim race and lifecycle (D-1).** 50 concurrent reveals of one single-view secret: one `200` with a token and a full body, 49 byte-identical `404`s, inline and local; 24 concurrent reveals + burns + reports over 6 rounds: exactly one winner per round; a sibling's token, the lookup hash, SHA-256 of the token, the stored `claim_key`, the burn token, a one-character variant, empty and malformed tokens all get the uniform `404` on reveal and confirm; after confirm nothing is served; the object is opened before the claim commits and a missing object is the uniform negative with the row untouched.
- **Uniform negatives and timing.** Never-existed, claimed-by-other, expired, malformed, wrong claim token and a TTL row with a bogus token are byte-identical `404`s with p50s within noise (510–522 µs); framework rejections (bad JSON, wrong types, missing Content-Type, 100 000-deep JSON, overflowing numbers, lone surrogates, BOM, 1 MB strings, 15 broken multipart shapes) never produce a 5xx or a hang and take the same path; wrong burns move no counter and leave the claimant's re-download working. Exception: R-5 (create), suspicion 1 (reports).
- **Dump.** After a checkpoint the SQLite file holds every hash and no raw credential (lookup, burn, claim, admin key, bootstrap token); each hash, base64url and hex, opens nothing as lookup, claim token, burn token, confirm token, Bearer or self-signed cookie.
- **Blob shape.** text/file × direct/passphrase × ttl/single-view: same length, same `argon_*` header fields, same create and reveal headers except the claim token (present iff single-view); bytes served as stored; the server cannot tell that a secret has a passphrase.
- **Rate limiting.** Ten addresses in one /64, an IPv4 peer also as `::ffff:`, rotating random Bearers, the admin key as Bearer, a 43-character garbage token, `X-Forwarded-For`/`Forwarded` from a non-proxy peer: exactly the anonymous quota per subject with `Retry-After: 60`; a real `user` key gets its own multiplied bucket and spends nothing of the IP's; the login bucket is consulted first and charged only on failure, shared by the panel and the admin API.
- **Logs.** 49 `log_*!` sites log static text, counts, sqlx/io/askama `Display` without bound values or paths, configured directories and the bind address; S3 errors are `status (Code)`; no `log`/`tracing` subscriber exists, so sqlx's statement logging has nowhere to go at any level; CLI subcommands are the only `println!`s; no panic reachable from a request formats request data.
- **Headers.** 1 376 responses across eight modes, configured and not, including 404s in api mode, 307/308 redirects, the setup 503s and the drain 503: CSP, HSTS (production), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` on every one; `no-store` on every API, admin, `/s`, `/burn`, 308 and 503 response; no inline script or style anywhere; the locale redirect never leaves the site (24 paths × 6 `Accept-Language` × 5 hosts, including `//evil.com`, `/\evil.com`, `%2F%2F`, `q=nan`).
- **Admin panel and sessions.** Session = `bootstrap ‖ key_hash ‖ issued_at ‖ expires ‖ nonce` under HMAC-SHA-256, MAC checked in constant time before any field is read; six forged variants, tampered expiry, flipped flag and foreign-key cookies are refused; every admin request re-checks the key; every POST (settings, key create, key delete, end sessions, logout) is 403 without or with a wrong CSRF token; "end sessions" kills the cookie while the key works on the API; the minted key is shown once to the minting session only; crafted duration/preset posts outside the allowed ranges are 422 and change nothing; `padding_min` survives a save in buckets mode and `padding_ladder` a save in padme mode; a `user` key cannot log in. Exception: R-7.
- **Settings PATCH.** 34 hostile patches (TTL over 14 d in every type, presets and defaults over the max, `padding_min` below the floor, ladders non-increasing/below floor/above the cap, buckets without a ladder, claim window and multiplier out of range, origins with path or wildcard, clearing the two required fields, unknown keys, `javascript:`/`ftp://` URLs) are all 422 and `/config` is byte-identical afterwards. Exception: R-16, suspicion 4.
- **Scheduler.** 450 expired rows swept by two concurrent sweepers count exactly 450; parked rows answer the uniform `404` to reveal, re-download, burn and report; two concurrent scrubbers delete each object once and leave the ledger with the whole ceiling free; ticks never overlap; the sweep works in 200-row transactions and truncates the WAL. Exception: R-14.
- **Client package.** `createSecret`/`revealSecret` and all four controllers check `fragment_version` before any request carrying derived material; every request goes to `apiBase` only, `credentials: "omit"`, `cache: "no-store"`; create sends only `SHA-256(lookup)` and `SHA-256(burn_token)`; `sessionStorage` holds exactly `{claimToken, expiresAt}` under `shh-claim:<base64url SHA-256(lookup)>`, deleted on confirm, 404 and expiry, tolerant of a throwing storage, never the seed or lookup; tampered entries are dropped; the fragment is scrubbed after display, after a 404 and after a burn; caller templates receive `textContent` and `<bdi>` only (`innerHTML` does not occur under `client/src`); `createT`'s block is server-rendered with `<` escaped and prototype-safe; only a trusted pointer `click` with `detail > 0` or a trusted Enter/Space, while `navigator.userActivation.isActive`, reveals: `button.click()`, synthetic events, `requestSubmit()`, keyup, Tab, pointer and touch events are refused; KEK via `deriveKey` non-extractable, EK extractable only for `wrapKey`, `exportKey` never called; both vector suites pass byte for byte (9 vectors, 38 reject cases); `erasableSyntaxOnly` on. Exceptions: R-18 to R-25.
- **Rust.** No `unsafe` outside the three audited WASM blocks and a test-only allocator; the whole suite passes under `-C overflow-checks=on`; 1 362 pedantic clippy hits triaged, none a finding on its own; host parsing, cookie decoding, `unhex`, `init` slicing and the ledger arithmetic cannot panic on request data; the Argon2 bounds are checked before `Params::new` and any allocation and the work memory is wiped.
- **Supply chain.** `cargo deny check` clean (advisories, bans, licenses, sources; the 9 sqlx/ring duplicates are the accepted S-35 set); `npm audit` 0; the lockfile is fully resolved with integrity hashes and only esbuild has an install script (never run); `npm pack` carries `dist/`, `argon2.wasm`, `LICENSE`, `README.md`, `package.json` and nothing else; the root Dockerfile builds (15.95 MB `scratch` image, user 65532, read-only and cap-dropped run verified, `init` works inside it); every action is SHA-pinned with `permissions: {}` and per-job grants; release depends on CI; tarballs are reproducible and attested; all 34 `KNOWN` variables are documented and no documented variable is unknown; the own-frontend Caddy snippets behave as documented against a real Caddy (XFF = `CF-Connecting-IP` only, `Vary` set, no header injection, no open redirect).

## 7. Claims (pass 0)

`pass0-claims.md` audited every behavioural statement in SPEC.md, README.md, CLAUDE.md, the five skills, client/README.md, docs/frontend-conformance.md, docs/deploy/*.md, docs/admin-api.md, content/en/*.md and locales/en/main.ftl against the code.

| status | count | what it means |
|---|---|---|
| WRONG | 5 | C-10 (CLAUDE.md "declared once": a setting touches four places), C-14 (i18n skill: content pages do not start with `##`), **C-27 (client caps a blob length against a bucket ceiling = R-6)**, C-37 (`site_name` help says footer; it is title and header), C-48 (reverse-proxies.md "locked out for an hour": the login bucket refills one attempt per 180 s) |
| UNBUILT | 2 | C-2 (`text_max_bytes` is advertised but enforced by nothing in the client), C-19 (api-endpoint skill's `limit`/`cursor` pagination exists nowhere) |
| OVERSTATED | 44 | True with a qualification the text omits. The ones on public pages matter most: C-36 (privacy.md implies the server may log IPs; it never does, a proxy would), C-39 (reveal interstitial "no way to retrieve it again": TTL secrets and in-window re-downloads exist), C-43 ("Destroyed · this was the only view" is shown before the confirm that destroys it), C-3/C-41 ("fetches nothing" before the gesture: it prefetches `argon2.wasm` per D-22), C-52 (three deploy guides say "nothing but the admin panel" before setup; `/static/*`, `/health` and the admin API are open), C-56 (the 35 s stop budgets equal the 30 s drain + 5 s close grace with no margin), C-49 (proxy body limit must exceed the bucket; = R-6's unit slip) |
| STALE | 6 | C-5 (D-8 "reports" panel), C-13 (database skill's reports table), C-15/C-17 (i18n and web-page skills' pre-`data-shh-*` names), C-20 (`note_not_found` example), C-22 (file-uploads skill's ceiling check via `external_bytes()`) |
| true | 375 | Grouped by source in the second table so the next reviewer can skip a file at a glance |

"By construction" items in docs/frontend-conformance.md: 10 of 10 are justified by a test or a code path (each named in the table). Item 6 (body cap) is justified in mechanism but wrong in unit (C-27/R-6); items 5, 8 and 10 carry a qualification (the `argon2.wasm` and `/config` fetches, "destroyed" before confirm, prefetch only with a valid fragment). No source is out of date as a whole; every DISCREPANCIES.md resolution that a claim touched was re-checked and is in the tree as its commit says.

## 8. Code or wording

| item | fix is | note |
|---|---|---|
| R-1 | code | |
| R-2 | code | plus a `Content-Length` note in `docs.md` |
| R-3 | code | |
| R-4 | code **and** wording (§6.1, deploy guides) | spec decides which |
| R-5 | wording (§4 / D-21) or code | spec decision first |
| R-6 | wording (§4, §10, conformance item 6, reverse-proxies.md) **and** code (body limit, client comparisons) | |
| R-7 | code | |
| R-8 | code | |
| R-9 | code | |
| R-10 | wording (README, docker.md, `.env.example`) plus a code warning; `0600` tightening would also be wording (§8) | |
| R-11 | code | |
| R-12 | code | |
| R-13 | code (or wording in §7.1) | |
| R-14 | code | |
| R-15 | code | |
| R-16 | code | |
| R-17 | code | |
| R-18 | code | |
| R-19 | code | |
| R-20 | code (and client/README.md) | |
| R-21 | code (and client/README.md) | |
| R-22 | code (both sides) and vectors | |
| R-23 | code | |
| R-24 | code | |
| R-25 | code (new Fluent strings) | |
| R-26 | workflow configuration (treated as code) and repository settings | |
| R-27 | workflow configuration (treated as code) | |
| R-28 | wording (deploy artefact and bare-metal.md) | |
| R-29 | code (tests only) | |
| C-2, C-38 | code or wording (either closes them) | C-38: `chars().count()` vs "80 bytes" |
| the other 53 pass-0 rows | wording | proposed text is in each row's Fix column |

## Review files left in the tree (all `review_r2_*`, none committed)

```
client/test/review_r2_adversarial.test.ts   (5 pass)
client/test/review_r2_pass0.test.ts         (1 pass; reproduces C-27/R-6)
client/test/review_r2_pass4.test.ts         (10 pass)
client/test/review_r2_pass5.test.ts         (12 pass; the F-5-n tests assert current behaviour)
crates/shhnote-core/tests/review_r2_pass3.rs   (3 pass)
crates/shhnote-core/tests/review_r2_pass5.rs   (4 pass)
crates/shhnote-server/tests/review_r2_adversarial.rs (24: 18 pass, 6 fail = R-1, R-2, R-9, R-10, R-11, R-13)
crates/shhnote-server/tests/review_r2_pass0.rs (4 pass)
crates/shhnote-server/tests/review_r2_pass1.rs (9 pass; `…reproduces_duplicate_create_timing_gap` passes while R-5 is present)
crates/shhnote-server/tests/review_r2_pass2.rs (11: 6 pass, 5 fail = R-3, R-4, R-14, R-15, R-6)
crates/shhnote-server/tests/review_r2_pass3.rs (10 pass; assert current behaviour, flip the FINDING-marked ones on fix)
crates/shhnote-server/tests/review_r2_pass4.rs (14: 11 pass, 3 `finding_*` fail = R-7, R-8, R-12)
crates/shhnote-server/tests/review_r2_pass6.rs (4 pass)
```

Conventions differ by pass, as in round 1: passes 2, 4 and 7 assert what the spec requires and **fail** while the finding stands; passes 1, 3 and 5 assert current behaviour and pass. A workspace-wide `cargo test` is therefore red until the `review_r2_*` files are removed. Pass 3's build directories are under `target/review-r2-pass3/` (gitignored). Pass 2's and pass 3's tests put their tier directories under `target/`; the other passes use the default temp directory, so `/tmp/shhnote-tests` grew further (R-29). No application file, template, content, document or configuration was modified by any pass (`git status` shows only untracked files plus this directory).

## Closing

Round 2 found no Critical and one High (R-1, a ceiling bypass through a disconnect during the store's acknowledgement, the gap next to S-5). The four Mediums are two incomplete round-1 fixes (R-3 against S-12, R-5 against S-9), one undocumented single-process assumption (R-4) and one cheap denial of creates (R-2). Of the 24 Lows, three are regressions or residuals of round-1 items (R-7 for S-39, R-22 for S-46, R-18/R-19 narrowing S-20), six are in the surfaces added since round 1 (setup gate, api mode, admin subdomain, `init`), and the rest are client-package hardening, deployment hygiene and one test-harness leak. The claims audit's 57 discrepancies are mostly wording; the one that is code (C-27) is also the one finding three passes reached independently (R-6).
