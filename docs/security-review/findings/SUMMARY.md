# Security review — synthesis (pass 8)

Date: 2026-10-30. Inputs: `pass1.md` … `pass7.md` in this directory. Nothing was fixed and nothing was committed; the working tree holds only the findings files and the `review_*` test files listed at the end.

How to read the ids: `S-n` is the merged item in this summary; the `From` column lists every pass finding it absorbs. Severity is the reconciled one; where passes disagreed the reason is in the notes. "Pass 7" says whether the adversarial pass, which saw only `SPEC.md`, independently hit the same thing (**yes** = reproduced with a test in `review_adversarial.rs`; *code only* = named it from reading the code but wrote no test; *no* = in its property list but not found; – = outside its property list). Pass 7 ran twice: the first run was interrupted before it wrote anything and left only a code-reading report; the second run is what `pass7.md` holds. "Code only" entries come from the first run.

## 1. Ranked findings

### High

| id | sev | one line | location | from | pass 7 |
|---|---|---|---|---|---|
| S-1 | High | `GET /config` leaks a `Settings` clone on every request (`Box::leak`); the endpoint is unauthenticated and never rate-limited, so any client grows RSS without bound (≈0.4 KB/request stock, 65 KB with a long `site_name`) | `api.rs:166-168` | F-1-1, F-2-5, F-3-1, F-4-1 | **yes** (F-7-4) |
| S-2 | High | Nothing times out: no header, body, idle or request timeout, no concurrency cap; a stalled upload keeps its socket, ~2–4 MiB of RAM and its spool file forever; graceful shutdown then never completes | `main.rs:126-133`, `api.rs:244-256`, `drain.rs:27-43` | F-2-1, F-2-9 | **yes** (F-7-3) |
| S-3 | High | The multipart `meta` part is buffered whole before its 4 KiB check; with an external tier the only bound is the body limit (`SHH_EXTERNAL_MAX_OBJECT` + 16 KiB, 64 MiB default), peak ≈2.25× the part | `api.rs:217-221` | F-2-2, F-3-2 | code only |
| S-4 | High | The tier ceiling is not atomic: check, `put` and row insert are separate awaits, so N concurrent creates all pass against the same total (16 of 16 succeeded against room for 2; up to 7× over) | `api.rs:295-329`, `secrets.rs:267-275` | F-2-4, F-3-9 | **yes** (F-7-1) |
| S-5 | High | The spool is unbounded: a blob is written to disk in full before the ceiling, length and `files_disabled` checks, and in-flight spool bytes never count toward the ceiling (4 paused uploads held 16 MiB on a "full" 300 KB tier) | `api.rs:244-305`, `storage.rs:82-88` | F-2-3, F-3-9 | **yes** (F-7-2, F-7-3) |

### Medium

| id | sev | one line | location | from | pass 7 |
|---|---|---|---|---|---|
| S-6 | Medium | Creation time is recoverable to the second from `expires_at − preset` (nine presets, `stats_daily` disambiguates) and the reveal second from `claim_expires_at − window`; with proxy access logs this links a row to an IP; `privacy.md` says creation time is not stored | `api.rs:274-275`, `secrets.rs:105-112` | F-1-2 | **yes** (F-7-5 shows the creation second) |
| S-7 | Medium | `api_keys.last_used_at` is written to the second on every keyed request and joins with S-6, linking a `user` key to the secret it created or revealed (D-17 says never) | `ratelimit.rs:234-239`, `api_keys.rs:70-77` | F-1-3 | **yes** (F-7-5) |
| S-8 | Medium | The reports ledger is keyed by the same `SHA-256(lookup)` as `secrets`, carries second-resolution timestamps, a count and a `matched` flag, and is never pruned: a joinable permanent tombstone; the content pages say only "that a report was received" is kept | `migrations/*/0003_reports.sql`, `secrets.rs:204-227` | F-1-4 (+ F-3 suspicion) | code only |
| S-9 | Medium | `POST /secrets` is an existence oracle for hash holders: `400 duplicate_key` while a row exists (active, claimed or pending_delete), `201` once it is gone; the 201 also plants a row under the victim's link | `api.rs:286-326`, `secrets.rs:77-86` | F-1-7 | **yes** (F-7-6) |
| S-10 | Medium | Settings are type-checked but not range-checked: `padding_min=0` makes a 1-byte bucket acceptable (D-6), `claim_window_secs=i64::MAX` and `rate_user_multiplier=u32::MAX` panic every reveal / keyed request (wrap in release), `rate_user_multiplier=0` is unlimited, presets of 30 days, `max_ttl` silently clamped, huge `daily_retention_days` folds today's stats; `SHH_INLINE_MAX`/`SHH_EXTERNAL_MAX_OBJECT` have no upper bound | `settings.rs:117-208`, `ratelimit.rs:120`, `secrets.rs:112`, `api.rs:341`, `scheduler.rs:27` | F-4-7, F-3-8, F-2-13 | **yes** (F-7-11, F-7-12, F-7-13) |
| S-11 | Medium | S3 error bodies (first 200 chars, which on AWS/MinIO include `<Key>blobs/…</Key>`) are written to the error log; `external_ref` maps the key to a row, so a failed reveal logs a per-secret access time | `storage.rs:520-525`, `api.rs:558-559`, `scheduler.rs:349` | F-1-10 (+ F-3 suspicion) | **yes** (F-7-7) |
| S-12 | Medium | The S3 client has no connect/TLS/request/body timeouts; a hung endpoint stalls `scrub`, and with it `sweep` and `rollup_daily` (one task), plus reveals, creates and startup; `pending_deletes` has no `LIMIT` | `storage.rs:454-476`, `scheduler.rs:16-31` | F-2-6 (+ F-3 suspicion) | – |
| S-13 | Medium | IPv4-mapped IPv6 peers (`::ffff:a.b.c.d`, what a dual-stack `SHH_HOST=::` listener reports) all hash to one /64 bucket, and IPv4 ranges in `SHH_TRUSTED_PROXIES` stop matching; shipped deployments bind `0.0.0.0` so are unaffected | `ratelimit.rs:82-100, 191-196`, `config.rs:168-185` | F-3-5 | **yes** (F-7-9) |
| S-14 | Medium | SQLite `secrets` is a rowid table, so a dump lists live secrets in creation order (`reports` likewise) | `migrations/sqlite/0001_secrets.sql` | F-1-5 | no |
| S-15 | Medium | Destroyed ciphertext and hashes survive in the SQLite `-wal` file after burn and a passive checkpoint (`secure_delete` covers the main file only); any file-level backup of a running instance carries them; the main file never shrinks | `store/lib.rs:84-98` | F-1-6 | code only |
| S-16 | Medium | `POST /reports` does different work per outcome: malformed skips the database (p50 59 µs), unmatched 396 µs, matched 556 µs (matched p10 above unmatched p90) | `api.rs:479-491`, `secrets.rs:215-224` | F-1-8 | **yes** (F-7-17) |
| S-17 | Medium | External-tier objects carry their upload time (local mtime/ctime, S3 `LastModified`) and `external_ref` links them to the row: an exact `created_at` for every large secret, visible from a bucket listing alone | `storage.rs:244-247, 370-378` | F-1-11 | – |
| S-18 | Medium | No `Cache-Control: no-store` on any admin page, including the POST response that shows a new admin key once; admin API 401/429 also lack it | `admin.rs:596-639`, `admin_api.rs:69-85` | F-4-6 | no |
| S-19 | Medium | `burnSecret` / the `/burn` page send whatever 32 bytes follow `#` as the raw burn token; given a share link (same fragment shape by design, §2.11) they post the seed to the server | `client.ts:55-58, 87-89`, `ui/burn.ts:14,28` | F-5-1 | – |
| S-20 | Medium | The client never streams: reveal buffers the whole blob (`arrayBuffer()`) and copies it 3–4×, create ≈5×; no check of the response length against the ladder, so a hostile server can send an unbounded body (D-4 promises bounded memory) | `ui/api.ts:110`, `crypto/chunks.ts:44-56`, `crypto/container.ts:76` | F-5-2 | – |
| S-21 | Medium | The client never uses the claim token: a body error loses it before the header is read, `revealSecret` throws on a wrong passphrase and discards blob and token, and `confirm:false` returns no token; the D-1 re-download path does not exist in practice | `ui/api.ts:110-111`, `ui/reveal.ts:57`, `client.ts:62-83` | F-5-3 | – |
| S-22 | Medium | Release workflow: every action pinned to a floating tag, `contents: write` + `packages: write` granted to every job | `.github/workflows/release.yml:7-9, 23-88` | F-6-1 | – |
| S-23 | Medium | Releases run on any `v*` tag with no dependency on CI, no `cargo audit`/`deny`/`npm audit` anywhere, checksums unsigned, no provenance, tarballs not reproducible | `release.yml:3-5, 35-62`, `ci.yml` | F-6-2 | – |
| S-24 | Medium | Builder and runtime images by tag, not digest (`rust:1.99-alpine`, `node:24-alpine`, compose `:latest`, `caddy:2`, `postgres:17-alpine`); the "pinned" comment on Node is only a major | `Dockerfile:1-9`, `deploy/docker/docker-compose.yml:12,32,50` | F-6-3 | – |

### Low

| id | sev | one line | location | from | pass 7 |
|---|---|---|---|---|---|
| S-25 | Low | §11 security headers (CSP, HSTS, XFO, nosniff, Referrer-Policy, Permissions-Policy) missing on every `/api/v1/*` response, the API subdomain, the trailing-slash 308 and the drain 503: the layer wraps only the web router | `web.rs:93-98`, `app.rs:21-32`, `drain.rs:329-335` | F-1-12, F-4-2 | – |
| S-26 | Low | A body that fails JSON extraction on reveal/confirm/burn/report (wrong type, missing field, bad JSON, no Content-Type) gets axum's `text/plain` 400/415/422 that echoes the input, not the uniform 404, and skips the database; `/reports` stops being "always 200" | `api.rs:354, 440, 458, 481` | F-1-13, F-3-3, F-4-11 | **yes** (F-7-15) |
| S-27 | Low | `Retry-After` on the first 429 equals exactly `3600 / per_hour`, revealing the threshold | `ratelimit.rs:167-172` | F-1-9, F-3-4 | code only |
| S-28 | Low | The bucket table is cleared whole when it passes 200 000 entries (fail-open), so one IPv6 /48 resets every client's limits on demand | `ratelimit.rs:63-65, 103-115` | F-3-6 (+ F-1, F-2 suspicions) | **yes** (F-7-10) |
| S-29 | Low | `unhex` slices a `&str` by byte offset and panics on a non-ASCII key id (admin API and panel; needs admin auth); no `CatchPanic`, so the connection is dropped | `admin_api.rs:368-376`, `admin.rs:717-725` | F-3-7, F-4-9 | **yes** (F-7-14) |
| S-30 | Low | Row exists but object is gone → `500 internal` instead of the uniform 404, after the single-view claim has already committed (the secret is consumed with no token) | `api.rs:372-383, 410-417` | F-2-7 | – |
| S-31 | Low | `SHH_SPOOL_PATH` is `remove_dir_all`'d at every start; a database placed there is destroyed | `storage.rs:327-331` | F-2-10 | – |
| S-32 | Low | Production accepts an `http://` S3 endpoint silently although uploads are `UNSIGNED-PAYLOAD` | `storage.rs:480-501`, `config.rs:424-433` | F-2-11 | – |
| S-33 | Low | Spool files and blobs are 0644, directories 0755; `blobs/` is not fsynced after the rename; `object_name` accepts any `[A-Za-z0-9_-]+` rather than exactly 22 chars | `storage.rs:147-156, 224-247, 116-130` | F-2-12, F-3-11 | – |
| S-34 | Low | `SHH_TRUSTED_PROXIES` rejects `0.0.0.0`, `::` and `/0` but accepts `1.0.0.0/1,128.0.0.0/1`, `::ffff:0:0/96` and non-network base addresses | `config.rs:207-212` | F-3-10 | – |
| S-35 | Low | Dependency surface: axum defaults (`tracing`, `tower-log`, `matched-path`, `original-uri`), tokio `full`, sqlx `sqlite` bundle (`load-extension`, `deserialize`), a second RustCrypto/base64/getrandom generation via sqlx | `Cargo.toml:31-34`, `crates/shhnote-server/Cargo.toml` | F-3-12, F-6-8 | – |
| S-36 | Low | Startup `println!`s the bind address and `SHH_URL` outside the log macros; `main.rs:29,67` use `eprintln!` | `main.rs:123-124` | F-3-13 (+ F-1 note) | – |
| S-37 | Low | Admin API compares the bootstrap-token hash with `==` where the panel uses `constant_time_eq` | `admin_api.rs:52-55` | F-3-14 | – |
| S-38 | Low | Inline `style=` attributes on 7 templates; the CSP blocks them | `home.html:102`, `report.html:19`, `how_it_works.html`, `admin/*.html` | F-4-3 | – |
| S-39 | Low | A bootstrap session is suspended, not ended, when an admin key is created: it works again after `reset-admin`, and survives a change of `SHH_ADMIN_TOKEN` | `admin.rs:145-157, 244-249` | F-4-4 | no |
| S-40 | Low | Logout checks no CSRF token (SameSite=Strict is the only guard) and does not revoke the cookie | `admin.rs:262-268` | F-4-5 | – |
| S-41 | Low | Admin API checks the credential before the login bucket, so a limited client's correct guess still gets 200 | `admin_api.rs:37-85` | F-4-8 | – |
| S-42 | Low | Region URLs and `source_url` have no scheme check; `javascript:`/`data:` links render on public pages (CSP blocks execution) | `settings.rs:135-176`, `home.html:92`, `base.html:58` | F-4-10 | – |
| S-43 | Low | Key creation and settings save render the POST response (no POST/redirect/GET); a refresh mints a second key | `admin.rs:500-509, 636-639` | F-4-12 | – |
| S-44 | Low | Argon2 work memory (including the block that yields `pass_key`) is freed unwiped in the cached WASM instance and in core (`argon2/zeroize` off) | `Cargo.toml:14`, `argon2-wasm/src/lib.rs:59-63`, `kdf.rs:74-76` | F-5-4 | – |
| S-45 | Low | Scrubbing does less than the code suggests (`blob` is nulled before the `pagehide` wipe, seed never wiped, chunk/payload copies kept) and the threat-model page lacks the caveat §10 says it has; §2.4 overstates "seed is the only raw key material" | `ui/reveal.ts:38-39,112`, `locales/en/main.ftl:315` | F-5-5 | – |
| S-46 | Low | TS and Rust diverge on BOM, duplicate keys, `1.0`, lone surrogates, missing `text`; an empty passphrase is a passphrase in Rust and "none" in TS | `crypto/container.ts`, `container.rs:359-438`, `secret.rs:414-450` | F-5-6 | – |
| S-47 | Low | Hostile blobs raise `RangeError`/`TypeError` outside the `ShhError` contract (short final fragment; `null` file entry) | `crypto/chunks.ts:47-48`, `crypto/container.ts:72` | F-5-7 | – |
| S-48 | Low | The vectors have 8 reject cases, all single-chunk; no negatives for chunk order, last flag, truncation, header length, manifest/size bounds or the parity cases | `vectors/generate.py:231-252` | F-5-8 | – |
| S-49 | Low | `dropzone.ts:10` uses a parameter property, which Node's type stripping rejects; `erasableSyntaxOnly` is not set | `client/src/ui/dropzone.ts:10` | F-5-9 | – |
| S-50 | Low | Download names are cleaned of `/` and `\` only (controls, bidi overrides, reserved names, length pass through) | `ui/reveal.ts:158` | F-5-10 | – |
| S-51 | Low | CI tests `stable`/debug/glibc without `--locked`; release is 1.99/thin-LTO/musl, aarch64 never tested | `ci.yml:25-52`, `Dockerfile:5` | F-6-4 | – |
| S-52 | Low | `build-wasm.sh` lacks `--locked`; `build-client.sh` skips `npm ci` when `node_modules` exists and lets esbuild's install script run; no `rust-toolchain.toml` or `.gitattributes` | `scripts/build-wasm.sh:6`, `scripts/build-client.sh:9-14` | F-6-5 | – |
| S-53 | Low | `build.rs` checks only that the embedded assets exist, not that they are non-empty, valid wasm or current | `crates/shhnote-server/build.rs:7-17` | F-6-6 | – |
| S-54 | Low | Workspace crates have no `license` or `publish = false`; `cargo deny` reports them unlicensed | `Cargo.toml`, `crates/*/Cargo.toml` | F-6-7 | – |
| S-55 | Low | compose `shhnote` service keeps default caps, no `no-new-privileges`, `pids_limit` or memory limit (the image runs fine with all of them) | `deploy/docker/docker-compose.yml:9-23` | F-6-9 | – |
| S-56 | Low | systemd unit lacks `ProcSubset=pid`, `LimitNOFILE`, `TasksMax`, `MemoryMax`, IP allow-list | `deploy/systemd/shhnote.service:21-47` | F-6-10 | – |
| S-57 | Low | Deploy env examples call `SHH_DB=sqlite` the default; the code requires it (container exits) | `deploy/docker/.env.example`, `deploy/systemd/env.example`, `config.rs:377` | F-6-11 | – |
| S-58 | Low | Only the first `X-Forwarded-For` header *line* is read; behind a trusted proxy that appends its own line (HAProxy `forwardfor`, some CDNs) the client's line wins and it picks its own rate-limit identity (the shipped Caddy config merges into one line, so it is unaffected) | `ratelimit.rs:86-96` | F-7-8 | **yes** (own finding) |

Severity notes:
- S-6 (F-1-2) was flagged by pass 1 as "arguably Critical" under the rubric ("any party learning a per-secret fact the spec says is hidden"). Kept at Medium because it needs a dump or operator access plus an external log source to become an identity link; on its own it is a stored per-secret timestamp, which §13 rejects. It is the pivot that makes S-7, S-8 and S-17 bite, so it should be fixed first among the Mediums.
- S-10 merges F-4-7 (Medium) and F-3-8 (Low): the panic on every single-view reveal after one bad PATCH is a remotely reachable denial of the core function, albeit by an admin, so Medium.
- S-2 absorbs F-2-9 (shutdown unbounded), which is the same missing timeout seen from the other side.
- S-4 and S-5 were one finding in pass 3 (F-3-9) and two in pass 2; kept as two because S-5 needs a spec revision and S-4 does not.

## 2. Duplicates merged

| merged into | came from | note |
|---|---|---|
| S-1 | F-1-1, F-2-5, F-3-1, F-4-1, F-7-4 | Five passes, same line, same fix. Byte-per-request figures differ (367–1 800 B) because the measured settings differed. |
| S-2 | F-2-1, F-2-9, F-7-3 (timeout part) | |
| S-3 | F-2-2, F-3-2 | |
| S-4 | F-2-4, F-3-9 (atomicity part), F-7-1 | |
| S-5 | F-2-3, F-3-9 (spool part), F-7-3 (spool past ceiling), F-2-8 and F-7-2 (orphans and `bucket` vs `blob_len`, see note) | Orphan collection is a distinct sub-fix: list `blobs/` at startup and delete unreferenced names; count `blob_len(bucket)` not `bucket`. F-7-2 shows the orphan arises from an ordinary client disconnect between `put` and the row insert, not only from a crash, which is why it sits in a High item. |
| S-6 | F-1-2, F-7-5 (the `expires_at − preset` half) | |
| S-7 | F-1-3, F-7-5 | |
| S-8 | F-1-4, pass 3 suspicion "reports ledger key equals `secrets.lookup_key`", pass 7 first-run note | |
| S-9 | F-1-7, F-7-6 | |
| S-10 | F-4-7, F-3-8, F-2-13, F-7-11, F-7-12, F-7-13 | F-2-13 (padmé overflow near `u64::MAX`) is reachable only through unbounded size config; same fix (`checked_add`). F-7-11 adds that an unbounded `claim_window_secs` keeps a *claimed* row past 14 days (D-7). |
| S-11 | F-1-10, F-7-7, pass 3 suspicion "S3 error bodies reach the log" | Pass 1 and pass 7 each reproduced it with a stand-in S3. |
| S-12 | F-2-6, pass 3 suspicion "no timeouts on the S3 client" | |
| S-13 | F-3-5, F-7-9 | Pass 7 rated it Low; kept Medium because a dual-stack bind is a one-line config change that silently merges every IPv4 client into one bucket. |
| S-16 | F-1-8, F-7-17 | Pass 7 rated it Low; kept Medium per pass 1's argument that §4 requires same work and the matched/unmatched gap is one sample wide. |
| S-25 | F-1-12, F-4-2 | |
| S-26 | F-1-13, F-3-3, F-4-11, F-7-15 | |
| S-27 | F-1-9, F-3-4 | |
| S-28 | F-3-6, F-7-10, pass 1 and pass 2 suspicions on the 200 000 clear | |
| S-29 | F-3-7, F-4-9, F-7-14 | |
| S-40 | F-4-5, F-7-16 | |
| S-33 | F-2-12, F-3-11 | |
| S-35 | F-3-12, F-6-8 | |
| S-36 | F-3-13, pass 1 out-of-scope note on `eprintln!` | |

## 3. Proposed fixes checked against SPEC §12 and §13

Allowed = can be done in code without touching the spec. Needs spec revision = the fix is fine under the principles but changes something the spec states, or the spec is silent and should not be. Rejected = the fix as proposed would violate a principle or re-propose a §13 item.

| id | proposed fix (short) | verdict |
|---|---|---|
| S-1 | Own the data in `ConfigResponse` or serialise inside the handler; delete `Box::leak` | Allowed |
| S-2 | Serve via `hyper_util` auto builder with a timer, header/idle timeouts, per-chunk `tokio::time::timeout`, a byte-budget semaphore for in-memory sinks; bound shutdown with `select!` | Allowed (Principle 7 asks for it) |
| S-3 | Read `meta` chunk-wise, refuse past 4096 bytes | Allowed |
| S-4 | In-process reservation (`Mutex<u64>`) under which `used + reserved + blob_len(bucket) ≤ max` is checked | Allowed. Note it is single-process only; a conditional-`UPDATE` counter row would be needed for multi-process, which is not a v1 deployment shape. |
| S-5 | Count in-flight spool bytes against the ceiling, refuse mid-stream; bound `SHH_SPOOL_PATH`; enforce `max_blob_bytes` and the text-only cap while streaming | **Needs spec revision**: §6.1 says the guards "count every object the tier holds"; add "and bytes being spooled", and define a bound for the S3 spool directory. Fix itself is allowed. |
| S-5 (orphans) | List `blobs/` (and `ListObjectsV2` for S3) at startup, delete unreferenced objects; count `blob_len(bucket)` | Allowed |
| S-6 | Round `expires_at` up to a coarse grid (hour, or 15 min under an hour) and `claim_expires_at` to the next minute or five, on write | Allowed and *required* by §13 ("per-secret created_at … rejected"). **Needs spec note** in §3 so the rounding is not undone. Also fix `privacy.md` wording either way. |
| S-7 | Store `last_used_at` at UTC-day resolution, update at most once per day | Allowed (§8 permits key timestamps; coarsening them reduces stored facts). Spec note in §8. |
| S-8 | Key the ledger by a domain-separated hash (`SHA-256("shhnote/report/v1" ‖ lookup)`), day-resolution dates, retention, consider dropping `matched` | **Needs spec revision**: §3 names the ledger but defines no columns. The current table is a §13 item ("terminal-status tombstones") that the spec does not notice it has. Update `acceptable-use.md`/`docs.md` to match. |
| S-9 | Answer a duplicate like a success (`201`, no write) | Allowed. **Needs spec note** in §4 ("create never distinguishes duplicates"). Re-planting after deletion stays possible but blind; a true 256-bit collision is a client RNG failure the server cannot help with anyway. |
| S-10 | Range checks in `with_overrides` (`padding_min ≥ 65536`, ladder monotone and ≤ external max, `claim_window` 60..=86400, `rate_user_multiplier ≥ 1`, presets within bounds, reject rather than clamp `max_ttl`, cap retention and `SHH_INLINE_MAX`/`SHH_EXTERNAL_MAX_OBJECT`); saturating/checked arithmetic at the five sites | Allowed. **Needs spec clarification** of D-6: is 64 KiB a floor an admin may not go under, or the default? Both passes read it as a floor. |
| S-11 | Log only the HTTP status and the S3 `<Code>`; never the body | Allowed |
| S-12 | `tokio::time::timeout` around connect/handshake/`send_request`, idle timeout on the body, `scrub` in its own task or with a budget, `LIMIT` on `pending_deletes` | Allowed |
| S-13 | `ip.to_canonical()` in `peer_of` and on each XFF hop before `is_proxy`/`ip_prefix` | Allowed |
| S-14 | New SQLite migration rebuilding `secrets` (and `reports`) `WITHOUT ROWID` | Allowed (rows then sort by hash). Postgres `xmin`/`ctid` remain, see §5 suspicions. |
| S-15 | `PRAGMA journal_size_limit = 0`, `wal_checkpoint(TRUNCATE)` after each sweep/scrub; document `sqlite3 .backup`/`VACUUM INTO` for backups | Allowed. Filesystem-level residue stays a residual: add to the threat model (see §4). |
| S-16 | Run the same statement sequence on every report path: random bytes for malformed, always the `+0` counter upsert and the `UPDATE reports` | Allowed. If the "no ledger row for garbage" policy is kept, run the write inside a rolled-back transaction, or change §4's wording. |
| S-17 | Local: `set_modified` to a fixed value after rename (ctime cannot be reset). S3 `LastModified` cannot be changed. | Partial fix allowed. **Needs spec revision**: record external-tier object timestamps as an accepted residual in §6.1 and the threat model. |
| S-18 | `no-store` layer on `admin::routes()` and on every `require_admin` response | Allowed |
| S-19 | Short term: `burnSecret`/`revealSecret` check the path (`/burn` vs `/s`) when given a URL. Full fix: distinct type byte for burn fragments or `HKDF(burn_token, "shhnote/burn/v1")` | Path check allowed now. Full fix **needs spec revision and a version bump** (§2.11, §2.13). |
| S-20 | Streaming `openStream`, incremental file assembly, refuse bodies longer than `blobLen(max bucket)` | Allowed (D-4 already describes it) |
| S-21 | Read headers before the body, carry the claim token through body errors, retry with `claim_token` while the window is open, return the token from `revealSecret` | Allowed (D-1 already describes it) |
| S-22 | Pin actions to SHAs, `permissions: {}` at workflow level, grant per job | Allowed |
| S-23 | `release` depends on CI, add `cargo deny`/`npm audit` jobs, reproducible tar, provenance attestation | Allowed |
| S-24 | `@sha256` digests on every `FROM`/`COPY --from`/compose image | Allowed |
| S-25 | Apply `security_headers` as the outermost layer in `app::router` and around `drain::track` | Allowed |
| S-26 | Custom extractor mapping any JSON rejection to the uniform path with random bytes (fixed 200 for `/reports`) | Allowed |
| S-27 | Constant `Retry-After` (or a coarse step independent of `per_hour`) | Allowed |
| S-28 | Evict per subject (full buckets first, then oldest) instead of clearing all | Allowed |
| S-29 | Validate `is_ascii_hexdigit` before slicing; one shared `unhex` | Allowed |
| S-30 | Open the object before committing the claim; map open failure to `NotFound` | Allowed. Note the overlap with the §5.1 residual (see §4): the residual covers a lost response, not a server-side fault, so this is still a finding. |
| S-31 | Remove only `*.part` at the top level, or spool into a dedicated subdirectory | Allowed |
| S-32 | Refuse `http://` S3 endpoints in production unless loopback/private, or sign the payload hash (the spool is complete before PUT) | Allowed |
| S-33 | `mode(0o600)` / `0o700`, fsync the directory, `len == 22` in `object_name` | Allowed |
| S-34 | Minimum prefix length, reject mapped/transition ranges, require `addr & !mask == 0` | Allowed |
| S-35 | `default-features = false` on axum with an explicit list, explicit tokio features; accept the sqlx duplicates with a note | Allowed (Principle 11) |
| S-36 | `log_info!` instead of `println!`; drop the URL line | Allowed |
| S-37 | Reuse `constant_time_eq` | Allowed |
| S-38 | Utility classes in `app.css` | Allowed |
| S-39 | Bind bootstrap sessions to the current token hash; for permanence, either a stored "admin keys last deleted" timestamp or a spec note that `reset-admin` revives bootstrap cookies < 12 h and operators should rotate `SHH_SECRET_KEY` | Token binding allowed. The permanence choice **needs a spec decision** (§8 says bootstrap sessions "end the moment an admin key is created"). |
| S-40 | `authenticate` + `check_csrf` in logout; for revocation, a per-key "sessions valid after" timestamp in `api_keys` | CSRF check allowed. Revocation **needs a spec decision** (§8 sessions are stateless by design; a key-level timestamp is permitted since keys are operator credentials). |
| S-41 | Peek at the login bucket before the lookup; spend a token only on failure | Allowed |
| S-42 | Accept only `https://` (and `http://` when `SHH_ENV=local`) for region/source URLs; sanity-check the email settings | Allowed |
| S-43 | Redirect after settings save; one-time nonce on key creation or document the exception | Allowed (skill rule, not spec) |
| S-44 | Allocate blocks in the WASM crate, `hash_password_into_with_memory`, wipe; enable `argon2/zeroize`; same in `kdf::argon2id` | Allowed |
| S-45 | Wipe `blob` in `display()`, seed on `pagehide`, chunk/payload intermediates, clear the passphrase input; add the caveat line to the threat-model page | Allowed. **Needs spec wording change** in §2.4/§10: the seed *and, briefly, the Argon2 output* are the raw key material in JS. |
| S-46 | Strict JSON in TS (`ignoreBOM`, duplicate-key rejection, integer tokens, well-formed strings), require `text` in Rust, one meaning for `""` | Allowed. Add the cases to the vectors (S-48). |
| S-47 | Length check on the final sealed chunk; `meta !== null` check | Allowed |
| S-48 | Add reject cases to `generate.py` | Allowed; the vectors README's "never edit `v1.json`" rule needs a decision (append-only `reject[]`, or a `v1-reject.json`). Not a spec change. |
| S-49 | Field + constructor assignment; `erasableSyntaxOnly: true` | Allowed (CLAUDE.md rule) |
| S-50 | NFC, replace controls/bidi/reserved chars, strip leading dots, cap length; `<bdi>` on the card | Allowed (§2.5 asks for it) |
| S-51–S-57 | Toolchain pin, `--locked`, `build.rs` magic check, `license`/`publish`, compose/systemd hardening, fix the `SHH_DB` comments | Allowed. S-57 alternative (give `SHH_DB` a default) would need §7.1 to say so; the comment fix does not. |
| S-58 | Join every `X-Forwarded-For` line (`get_all`) before walking from the right | Allowed |

**Rejected by principle:** none of the proposed fixes re-proposes a §13 item or violates §12. Two things to watch while fixing: (a) S-39/S-40 must not introduce server-side session state keyed to anything but the admin key (Principle 8 allows key-level timestamps, §8 keeps sessions stateless); (b) S-8 must not keep a per-secret `matched`/timestamp row in any form that joins to `secrets`, since that is exactly the §13 tombstone.

## 4. Rediscovered accepted residuals

Findings or parts of findings that `SPEC.md` already records as accepted; they are not new and should not be re-filed.

| rediscovered as | already recorded in | note |
|---|---|---|
| S-30, part: a single-view secret consumed by a reveal whose response never completed | §5.1 "Accepted residual" (lost response → destroyed unread; sender resends) | S-30's *server-side fault → 500* is not the recorded case and stays a finding; only the "consumed with no token" consequence is the residual. |
| S-21 (b), part: wrong passphrase gives no second attempt | §5.1 "A recipient who cannot produce the passphrase has no second attempt beyond local retries" | The residual assumes local retries exist. S-21 shows the library path throws instead of retrying locally, so that part remains a finding against §2.10 step 4. |
| S-44, S-45 (memory wiping is incomplete) | §10 "best effort — JavaScript cannot guarantee memory wiping, and the threat model says so" | The residual is accepted; what remains is that the code does less than the residual implies (nulling before wiping) and the threat-model *page* does not carry the caveat §10 says it does. |
| Pass 7 (first attempt) G and pass 5 suspicion: the `argon2.wasm` fetch marks passphrase use | Not recorded. §2.8 promises indistinguishable *blobs*; it is silent on the client-side side channel that only passphrase secrets fetch `/static/argon2.wasm`. | Candidate residual for §10 and the threat model (an on-path observer or the server can see that *some* visitor needed a passphrase; linking it to a secret needs S-6). Or prefetch the module on every reveal/create. |
| Pass 1 suspicion: local-tier `unlink` leaves ciphertext in free blocks; S-15's filesystem-level remnants; Postgres dead tuples/WAL | Not recorded. Principle 6 says "destroyed, not flagged" but the spec never claims physical erasure. | Candidate residual for the threat model: destruction is logical; ciphertext (never plaintext) may persist in journals, free blocks and backups until overwritten. |
| S-17 (external object timestamps) | Not recorded. | Becomes an accepted residual of the external tier if the spec revision in §3 of this file is taken. |

## 5. Suspicions worth a follow-up

Each with the experiment that settles it. Unreproduced items from all passes, deduplicated.

1. **`isTrusted` on `submit` does not prove a user gesture** (pass 4; pass 7 reached the same suspicion blind for property P). `form.requestSubmit()` or `button.click()` from in-page script fires a *trusted* submit, so an extension or a DOM-driving scanner could consume a single-view secret despite §5. Experiment: load `/en/s#<valid>` in Chromium and Firefox, run `document.querySelector('[data-reveal-form]').requestSubmit()` in the console, watch for `POST /secrets/reveal`. If it fires, guard on the button's `click` with `isTrusted && detail > 0` (plus a keydown path) and/or `navigator.userActivation.isActive`.
2. **`argon2.wasm` fetch reveals passphrase use to the server/network** (pass 7 first attempt, pass 5). Experiment: tcpdump/har of a direct reveal vs a passphrase reveal. Confirmed by code reading; needs a decision (prefetch always, or record as residual).
3. **Postgres retains destroyed rows and orders rows by creation** via dead tuples, TOAST, `xmin`/`ctid`, `pg_wal` (pass 1). Experiment with `SHH_TEST_PG_URL`: create, burn, `SELECT xmin, ctid FROM secrets` before/after, and `pageinspect.heap_page_items` on the relation and its TOAST table. Likely a deployment note (aggressive autovacuum, WAL retention) plus a residual.
4. **Large expiry backlog holds the SQLite write lock past `busy_timeout`** (pass 2): then every claim/burn/confirm/create fails with 500 for up to 5 s each. Mechanism confirmed with an external lock; 150 × 2 MiB rows swept in 0.43 s, so ~1 700+ max-size expired rows would be needed on this disk. Experiment: measure on production-class storage with the largest backlog the create limits allow over `min_ttl_secs`. Fix if confirmed: sweep in bounded batches, one transaction each.
5. **Pool starvation of `/health`** (pass 2): 8 connections, 30 s acquire timeout, shared by `/health`. Experiment: hold the write lock, fire ≥ 8 reveals plus `/health`, measure.
6. **Blob MIME type from the manifest on a same-origin `blob:` URL** (pass 5): `text/html` opened in a new tab renders under the site origin (CSP should block scripts). Experiment in Firefox ESR/Tor and Chromium. Fix regardless: always `application/octet-stream`.
7. **Tor Browser "Safer" disables WebAssembly** (pass 5): passphrase secrets would fail with a misleading "corrupt" message (Principle 9). Experiment: create and reveal a passphrase secret at Safer. Fix: a specific "WebAssembly blocked" message.
8. **Settings snapshot held across a whole upload** (pass 3): a `files_enabled=false` save does not apply to in-flight uploads. Experiment: start an upload, flip the setting, finish; expect 201. Fix: re-`load()` after the body arrives.
9. **Zero salt if the RNG fails** (pass 3): `ratelimit.rs:176-182` falls back to all-zero silently. Practically unreachable; add `log_error!` and refuse to start.
10. **Login bucket shared behind an unconfigured proxy** (pass 4): every visitor shares the proxy IP, so anyone can lock the admin out of the web login for an hour. Experiment: run behind Caddy without `SHH_TRUSTED_PROXIES`, 20 bad logins from one client, then a good one from another. Fix: a `docs/deploy` note (and S-13/S-34 for the proxy config).
11. **`rollup_daily` reads outside its transaction** (pass 7 first attempt): two schedulers at once (rolling deploy) would double-count folded days. Experiment: two `Store` handles, run `rollup_daily` concurrently against a seeded `stats_daily`, compare totals.
12. **`stats().active` excludes `claimed`** (pass 1): an admin polling `/admin/stats` on a quiet instance sees `active` drop at the exact reveal second. Within §8's "live active count" but a per-event signal. Experiment: poll in a test. Option: count `active + claimed`.
13. **BREACH via Caddy `encode`** on admin pages with CSRF tokens (pass 6): exploitable only if an admin page reflects attacker input next to the token. Experiment: grep admin templates for reflected request data (pass 4 found none reflected unescaped, which suggests this is clear). Compressing blob responses is also wasted CPU.
14. **Fly volume ownership** (pass 6): a fresh Fly volume is root-owned, the image runs as 65532. Experiment: `fly deploy` on a fresh volume, check logs for SQLite permission errors.
15. **Fly `SHH_TRUSTED_PROXIES` ranges** (`172.16.0.0/16,fdaa::/16`) trust every app on the private network (pass 6). Experiment: check Fly's documented proxy source addresses and narrow.
16. **Hostile-within-bounds Argon2 keeps ~260 MiB until the tab closes** (pass 5): within §2.9, but on 32-bit Android a grow failure is likely. Experiment on a low-memory device.
17. **Rate-limit subjects for user keys are not cleared by rotation unless an anonymous request arrives** (pass 1): `check_key` never rotates. Harmless by spec (keys are unsalted hashes), but the "rotation clears every bucket" comment is only true eventually.

## 6. Properties tested and holding

For the security page or threat model. Each was specifically exercised by a review test in this round.

- **Claim race.** 50 concurrent reveals of one single-view secret: exactly one 200 with a claim token and a full body, 49 byte-identical 404s, on inline and local tiers, at store and API level (SQLite; Postgres not run, `SHH_TEST_PG_URL` unset). Pass 7 re-proved it blind (`a_concurrent_reveals_have_exactly_one_winner`) and added that a reveal racing a burn never both succeed (`a_reveal_and_burn_race_never_both_succeed`).
- **Dump yields nothing.** Reading the SQLite file after creating secrets gives only hashes; presenting those hashes as lookup, burn token or claim token opens, burns, reports or claims nothing (`e_dump_holds_only_hashes_and_hashes_open_nothing`). The one thing a hash holder can do is S-9.
- **Blobs are indistinguishable.** Direct vs passphrase and text vs file blobs of one bucket have identical length at rest and on the wire, and direct blobs carry the default Argon2 parameters, so the server cannot tell that a secret has a passphrase (`fg_direct_passphrase_text_file_blobs_look_the_same`; see suspicion 2 for the client-side `argon2.wasm` fetch).
- **`pending_delete` is never served and counts once.** Parked rows are invisible to reveal, re-download, burn and report, and the scrubber's counter moves exactly once per row (`o_pending_delete_is_never_served_and_counts_once`).
- **Link scanners without JavaScript consume nothing.** Fetching the share link, the redirect target and every asset it references produces no reveal (`p_following_the_link_and_its_assets_consumes_nothing`). JavaScript-executing scanners are suspicion 1.
- **Rate-limit identity.** Addresses within one /64 share a bucket; a direct peer's `X-Forwarded-For` is ignored; random, oversized, `Basic` and valid *admin* bearers are all the same anonymous client (`j_ipv6_neighbours_xff_and_garbage_bearer_share_the_limit`). Exceptions: S-13, S-28, S-58.
- **TTL cap.** `max_ttl_secs = 30 d` is clamped to 14 d, `min`/`default` above it are refused as a whole, `ttl_seconds` of 14 d + 1 or `i64::MAX` get `invalid_ttl`, an invalid padded size under the live ladder gets `invalid_blob_length`, buckets mode without a ladder is refused (`n_ttl_is_capped_at_14_days_whatever_is_patched`). Exception: S-10.
- **Claim window.** Re-download works only with the matching claim token, only while `claimed` and inside the window; fails after confirm and after the window; the sweep destroys a lapsed claim as `viewed`; nothing ever reverts to `active`; burn and report never touch a claimed row.
- **Uniform negatives on reveal, confirm, burn.** Never-existed, malformed, expired-but-present, claimed-by-other, wrong claim token, consumed, burned and reported all return byte-identical `404` bodies and headers; reveal-side timings are within noise (p50 335–361 µs). Malformed credentials are replaced by `getrandom` bytes and run the same store calls. (Exceptions: S-16 on `/reports`, S-26 for body-level rejections.)
- **Schema.** `secrets` has exactly the §3 columns; no `created_at`, no triggers, no AUTOINCREMENT, no foreign keys; no statement touches `secrets` and another table at once; counters update in the same transaction as the row change; the yearly fold works.
- **Credentials at rest.** Everything presented is hashed and looked up by the full 32-byte SHA-256 (PK/UNIQUE/predicate); no `==` on secret material on secret paths; session MAC and CSRF use constant-time compare (one admin-API exception, S-37). A non-canonical base64url spelling of a real token does not match.
- **Randomness.** Claim token, object keys, spool names, salt, session nonce and API keys all come from `getrandom` per use; no seeded or cloned PRNG.
- **Rate limiter.** Key is `HMAC-SHA256(salt, ip)`, IPv6 by /64, salt only in memory, rotation clears the table, `X-Forwarded-For` honoured only from configured proxies, mutex never held across an await, no request can be keyed with a pre-rotation salt and counted after.
- **Streaming.** No database connection or transaction is held while a blob streams; external objects stream in 64 KiB chunks; a short object yields a truncated body the client rejects; a long one is cut at `Content-Length`.
- **Spool hygiene.** 100 aborted uploads (50 early EOF, 50 dropped futures) left 0 spool files; `Spool`/`Spooled` remove on drop; startup clears `tmp/`; a half-received blob is never committed; spool names are random, `create_new`, under the right root.
- **Scheduler.** Ticks never overlap; each terminal transition is one transaction with its counter; the sweep deletes by predicate without loading rows.
- **Logging.** All 29 `log_*!` sites log static text, counts, sqlx `Display` without bound values, or io errors without paths; no subscriber is installed; no IP, header, path or body is logged (exception: S-11).
- **Locale redirect.** Always `/{offered}{path}[?query]`, never absolute or off-site, adds nothing, no cookie, `Vary: Accept-Language`; hostile `Accept-Language` (60 KB, `q=NaN`, duplicates) handled; fragments never reach the server.
- **Admin sessions.** `HttpOnly; SameSite=Strict; Max-Age=43200` (+`Secure` in production); HMAC checked constant-time before any field is read; tampered expiry, flipped flags, junk and foreign-key cookies rejected; rotating `SHH_SECRET_KEY` ends all sessions; every request re-checks the key with `admin` scope; CSRF is HMAC-bound to the session nonce and enforced on settings/key create/key delete; the admin JSON API accepts Bearer only (no cookie, hence no CSRF surface); a failed login does not reveal whether a key exists.
- **Templates.** Askama escapes every value; `|safe` only on first-party Markdown and the i18n JSON; no analytics, no external origin anywhere; the report page collects only the link and posts only the derived `lookup`; static routes resist traversal; `argon2.wasm` is `application/wasm`; CSP matches §10 with no `unsafe-inline`/`unsafe-eval`.
- **Client crypto.** Both vector suites pass byte for byte; fragment decoding is strict on both sides (exactly 44 base64url chars, canonical, version checked first); `parseFragment` never picks a seed from path or query; KEK non-extractable via `deriveKey`, content key extractable only because `wrapKey` requires it, `exportKey` never called, no key material in console/storage/DOM; Argon2 bounds checked in TS, WASM and core before any allocation; a failed WASM load never falls back to anything weaker; mode detection cannot loop or leak; chunk order/last flag/truncation all reject; a failed chunk leaves nothing in the DOM; create sends only hashes, reveal sends only `HKDF(seed)`.
- **Interstitial.** `/s`, `/burn`, `/report` fetch nothing before submit; the server never receives a fragment.
- **Config.** Unknown `SHH_*` vars fail; disabled-tier vars fail; `SHH_DEBUG` with production fails; secrets < 32 chars fail; `Secret` redacts in `Debug`; `0.0.0.0`, `::`, `/0` refused (S-34 for equivalents).
- **WASM crate.** The only `unsafe` in the workspace; `shh_alloc`/`shh_free` are sound; bounds are checked before `Params::new` and any allocation; an oversized length traps.
- **Supply chain.** RustSec advisories clean (DB of 2026-10-30), no unmaintained or yanked crates, crates.io only; all third-party licences AGPL-3.0-compatible; npm 0 advisories, lockfile fully pinned with integrity hashes, nothing from npm ships; the image is `scratch` + static binary, non-root, read-only-root compatible, no CA bundle, no secret in any layer; Caddyfiles set no headers that could conflict; all 31 `KNOWN` variables are documented and no documented variable is unknown.
- **Overflow checks.** The whole existing suite passes with `-C overflow-checks=on` (the overflowing paths need the unbounded settings of S-10).

## Review test files left in the tree (all `review_*`, none committed)

```
client/test/review_pass5.test.ts
crates/shhnote-core/tests/review_pass2_padding.rs
crates/shhnote-core/tests/review_pass5.rs
crates/shhnote-server/tests/review_admin.rs
crates/shhnote-server/tests/review_config_leak.rs
crates/shhnote-server/tests/review_headers.rs
crates/shhnote-server/tests/review_pass1.rs
crates/shhnote-server/tests/review_pass1_config_leak.rs
crates/shhnote-server/tests/review_pass2.rs
crates/shhnote-server/tests/review_pass3.rs
crates/shhnote-server/tests/review_pass3_alloc.rs
crates/shhnote-store/tests/review_pass1.rs
crates/shhnote-store/tests/review_pass2.rs
crates/shhnote-server/tests/review_adversarial.rs
```

Conventions differ by pass: pass 1, 3, 5 and 7 (`broken_*`) tests *pass* while the finding exists (they assert current behaviour); pass 2 and the `spec_*` tests of pass 4 *fail* while the finding exists (they assert what the spec requires). Pass 7's tests leave temporary directories under `/tmp` (`shh-adv-*`, `shhnote-tests/adv-*`). Pass 3 noted that `crates/shhnote-core/tests/review_pass2_padding.rs` is not `rustfmt`-clean and `review_pass1.rs:832` trips `clippy::err_expect`, so a workspace-wide `cargo clippy --all-targets` is red until the review files are removed. No application file was modified by any pass (`git status` shows only untracked files).

## 7. Closing

Every finding above is mapped to the commit that fixed it, or to its accepted residual, in [`../CHANGELOG.md`](../CHANGELOG.md) (2026-10-31).
