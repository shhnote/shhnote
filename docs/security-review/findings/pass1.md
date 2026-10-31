# Pass 1 — Metadata and PII leakage — findings

Reviewed: crates/shhnote-server/src/{api.rs, web.rs, admin.rs, admin_api.rs, ratelimit.rs, log.rs, health.rs, scheduler.rs, storage.rs, i18n.rs, content.rs, app.rs, main.rs, clock.rs, drain.rs}, crates/shhnote-store/src/{lib.rs, secrets.rs, stats.rs, api_keys.rs, settings.rs}, migrations/{sqlite,postgres}/0001–0005, every template in crates/shhnote-server/templates/ (incl. admin/ and partials/), crates/shhnote-server/content/en/*.md, client/src/ui/{create,report}.ts and client/src/main.ts (form wiring only); 2026-10-30.
Tooling run: cargo 1.99.1, rustfmt (edition 2024) on the review tests only; SQLite 3.46.1 (python3 module, for reference).
- `cargo test -p shhnote-store --test review_pass1 -- --nocapture` (5 tests, all pass = all reproductions confirmed)
- `cargo test -p shhnote-server --test review_pass1 -- --nocapture --test-threads=1` (11 tests, all pass)
- `cargo test -p shhnote-server --test review_pass1_config_leak -- --nocapture` (1 test)

Review tests are written so that **passing means the finding is reproduced** (they assert the leaky behaviour); after a fix they will fail and should be inverted or deleted.

## Findings

### F-1-1: `GET /config` leaks a full `Settings` clone on every request
Severity: High
Location: crates/shhnote-server/src/api.rs:166-168 (route at api.rs:107, never rate-limited)
Violates: Principle 7 (operator cost hard-bounded); SPEC §4 (`/config` is public and unlimited)
What: `config()` does `Box::leak(Box::new((*state.settings.load()).clone()))` to hand out `'static` references, so every call permanently leaks one `Settings` (strings, presets, regions list). `/config` is unauthenticated and not behind the rate limiter, so any client can grow the server's memory without bound until OOM. Outside this pass's topic, recorded because it was found here.
Reproduction: `review_pass1_config_leak::review_config_endpoint_leaks_memory_per_request`: 100 000 requests grow RSS from 21 976 KiB to 198 488 KiB (~1.8 KB per request, with an 8-entry regions list). Flat after warm-up without the leak.
Fix: serialise from the snapshot inside the handler, e.g. build the response with owned values (`ttl_presets: settings.ttl_presets.clone()`, `regions: settings.regions.clone()`) or return `Json(serde_json::to_value(..))` while the `load()` guard is alive. No spec change.

### F-1-2: Creation and reveal times are stored to the second (`expires_at`, `claim_expires_at`), and the privacy page says they are not
Severity: Medium (dump/operator access; arguably Critical under the rubric's "per-secret fact the spec says is hidden")
Location: crates/shhnote-server/src/api.rs:274-275 (`expires_at = now + ttl_seconds`), api.rs:371-375 + crates/shhnote-store/src/secrets.rs:105-112 (`claim_expires_at = now + window`); migrations/*/0001_secrets.sql; crates/shhnote-server/content/en/privacy.md:17
Violates: Principle 5 ("No creation or access timestamps"), SPEC §13 (per-secret `created_at` rejected as a correlation handle); content page claim
What: The web client only offers the nine TTL presets (templates/home.html:39-49), so `created_at = expires_at − preset` has nine candidates, and `stats_daily.created` usually leaves exactly one. For single-view secrets in the window, `claim_expires_at − claim_window_secs` is the exact reveal second. A dump, a backup, or an operator holding reverse-proxy access logs can therefore line up a row with the `POST /api/v1/secrets` (or `/reveal`) log line of the same second, linking the secret to an IP and user agent. `privacy.md:17` promises "We don't store … when the secret was created".
Reproduction: `shhnote-store/tests/review_pass1.rs::review_expires_at_reveals_creation_second`: from `expires_at=1800271545` and `stats_daily`, the single surviving candidate is the true creation second `1800012345`. `review_dump_links_user_key_to_its_secrets` shows the `claim_expires_at − 900` join.
Fix: quantise on write: round `expires_at` up to a coarse grid (for example the next full hour, or the next 15 min for TTLs under an hour, clamped to max TTL), and round `claim_expires_at` up to the next minute or five. The hour grid matches the existing `X-Shh-Expires-In-Hours` granularity. Needs a short SPEC §3 note ("expiry values are stored rounded to …") so later changes don't undo it; no principle conflict.

### F-1-3: A `user` API key can be linked to the secrets it created or revealed
Severity: Medium
Location: crates/shhnote-server/src/ratelimit.rs:234-239 (`touch_api_key(&hash, now)` on every keyed create/reveal/confirm/burn/report); crates/shhnote-store/src/api_keys.rs:70-77; combined with F-1-2
Violates: D-17 ("user keys … are never linked to secrets"), SPEC §8 ("nothing records which key created which secret"), Principle 8
What: `api_keys.last_used_at` is rewritten to the exact second of every keyed request, and the same second sits in `secrets.expires_at − preset` (create) or `claim_expires_at − window` (reveal). One SQL join over a dump attributes the most recent secret per key to the integrator by name. On a quiet instance, polling `GET /api/v1/admin/keys` (admin) even gives the operator a live per-request timeline per key without a dump.
Reproduction: `shhnote-store/tests/review_pass1.rs::review_dump_links_user_key_to_its_secrets` (exactly one hit out of 21 secrets for `expires_at − last_used_at IN (presets)`, and the claim join); `shhnote-server/tests/review_pass1.rs::review_user_key_last_used_matches_create_second` shows the server sets `last_used_at` within the create second.
Fix: store `last_used_at` at UTC-day granularity (`now - now % 86400`), the same resolution as `stats_daily`, and preferably update it at most once per day per key. Together with F-1-2 this removes the join. SPEC §8 should say "last_used_at (UTC day)"; spec note only.

### F-1-4: The reports ledger is a permanent, timestamped tombstone keyed by the secret's own lookup hash
Severity: Medium
Location: migrations/{sqlite,postgres}/0003_reports.sql; crates/shhnote-store/src/secrets.rs:204-227; crates/shhnote-store/src/stats.rs:509-527; crates/shhnote-server/src/admin.rs:537-546, admin_api.rs:272-288; content/en/acceptable-use.md:26, content/en/docs.md:99
Violates: Principle 5 ("no terminal-status rows"), §13 ("Terminal-status tombstones kept 'for audit'"), §3 ("never joined to secrets"); content page claims
What: `reports.lookup_key` is `SHA-256(lookup)`, the same value as `secrets.lookup_key`. Each row also carries `first_reported_at`/`last_reported_at` to the second, a report `count`, and `matched` (= "this secret existed and was removed at T"), and is never pruned. A dump joins it to live rows: a report against a claimed (already consumed) secret shows as `matched=0` next to `status='claimed'`. Anyone who later holds a link (or a seized database) can confirm when that exact secret was reported and taken down. The admin page and API show the first 8 hash bytes, minute or second timestamps and `removed_secret`. acceptable-use.md:26 says "a record that a report was received is kept, nothing else".
Reproduction: `shhnote-store/tests/review_pass1.rs::review_reports_ledger_joins_secrets` (`JOIN secrets USING (lookup_key)` returns `status=claimed reported_at=1800000200 matched=0`); `shhnote-server/tests/review_pass1.rs::review_reports_ledger_is_a_timestamped_tombstone` (admin API returns `id` = hash prefix, exact `first_reported_at`, `removed_secret: true`).
Fix: needs a spec revision of what the ledger holds (§3 names it but defines no columns). Suggested: key the ledger by a domain-separated hash that cannot match a `secrets` row (for example `SHA-256("shhnote/report/v1" ‖ lookup)`, computed server-side since the server receives the raw lookup), store dates at UTC-day resolution, and give it a retention (fold or delete with `daily_retention_days`). Dropping `matched` may also be warranted, since `stats_daily.removed` already counts takedowns. Update acceptable-use.md and docs.md to describe exactly what is kept.

### F-1-5: SQLite's implicit rowid numbers secrets in creation order
Severity: Medium
Location: migrations/sqlite/0001_secrets.sql:3-14 (no `WITHOUT ROWID`); same for 0003_reports.sql
Violates: Principle 5 (no creation metadata), SPEC §3; prompt item 5
What: `secrets` is an ordinary rowid table, so every row gets a monotonically increasing rowid. A dump ordered by rowid is the creation order of all live secrets, and combined with `stats_daily.created` per day it dates each row. No query exposes the rowid, but the file does.
Reproduction: `shhnote-store/tests/review_pass1.rs::review_sqlite_rowid_orders_secrets_by_creation`: `SELECT rowid, lookup_key FROM secrets ORDER BY rowid` returns `[1..8]` in insertion order.
Fix: a new SQLite migration that rebuilds `secrets` as `WITHOUT ROWID` (rows are then stored in `lookup_key`, i.e. hash, order). Postgres has the analogous `xmin`/`ctid` (see Suspicions). No spec change.

### F-1-6: Destroyed blobs survive in the SQLite `-wal` file
Severity: Medium
Location: crates/shhnote-store/src/lib.rs:84-98 (WAL + `secure_delete`, no `journal_size_limit`, no `wal_checkpoint(TRUNCATE)`, no VACUUM anywhere in the workspace)
Violates: Principle 6 ("Secrets are destroyed, not flagged"), SPEC §5 (terminal transition destroys the row)
What: `secure_delete = ON` zeroes the pages written after the delete, but the WAL frames written by the original INSERT still hold the full ciphertext (and the `lookup_key`/`burn_key` hashes) until the WAL is overwritten or the last connection closes. A passive (auto) checkpoint does not truncate the WAL. Any file-level backup or snapshot of the database directory taken while the server runs therefore contains destroyed secrets. The main file is clean. It is ciphertext only, but it is retained ciphertext plus hashes of secrets the system reports as destroyed. The file also never shrinks (no `auto_vacuum`), so its size records peak volume.
Reproduction: `shhnote-store/tests/review_pass1.rs::review_destroyed_blob_survives_in_wal`: after create, burn and `PRAGMA wal_checkpoint(PASSIVE)`: `wal=333752 bytes, blob in wal=true, blob in db=false`.
Fix: set `PRAGMA journal_size_limit = 0` per connection and have the scheduler run `PRAGMA wal_checkpoint(TRUNCATE)` after each sweep/scrub (and optionally after each terminal transition on low-traffic instances). Document in docs/deploy that backups must use `sqlite3 .backup` / `VACUUM INTO`, not a file copy. Filesystem-level remnants are a residual worth a line in the threat model.

### F-1-7: `POST /secrets` is an existence oracle (and re-plant primitive) for anyone holding the hashes
Severity: Medium
Location: crates/shhnote-server/src/api.rs:286-291 and 319-326 (`duplicate_key`); crates/shhnote-store/src/secrets.rs:77-86 (lookup_key PK and burn_key UNIQUE both map to `false`)
Violates: D-3 ("A database dump must not let anyone … otherwise act on secrets"), SPEC §2.12, Principle 5
What: Create takes the hashes, not the preimages. Someone holding `SHA-256(lookup)` or `SHA-256(burn_token)` (a dump, a backup, or the reports ledger of F-1-4) can probe `POST /secrets` with that hash: `400 duplicate_key` while the row exists (active, claimed or pending_delete), `201` once it is gone. That tells them when the secret was consumed or destroyed, and the 201 leaves them owning a row under the victim's lookup. A stale copy of the link then serves the attacker's blob instead of the uniform negative, so the recipient's client falls into the passphrase prompt (nothing can be decrypted, and a further probe again shows when the link was opened).
Reproduction: `shhnote-server/tests/review_pass1.rs::review_create_is_an_existence_oracle_for_hash_holders`: probes give `400 duplicate_key` (by lookup_key and by burn_key) while active or claimed, then `201 Created` after confirm, and the victim link then returns `200 OK (65647 bytes)`.
Fix: answer a duplicate exactly like a success (`201`, empty) without writing, so a hash holder learns nothing (a true collision of 256-bit random keys is a client RNG failure the client cannot fix anyway). Re-planting after deletion remains possible but becomes blind. Needs a one-line SPEC §4 note that create never distinguishes duplicates.

### F-1-8: `POST /reports` does measurably different work for matched, unmatched and malformed lookups
Severity: Medium
Location: crates/shhnote-server/src/api.rs:479-491 (malformed skips the database entirely); crates/shhnote-store/src/secrets.rs:215-224 (matched adds DELETE rows, a `stats_daily` upsert and a second `UPDATE reports`)
Violates: SPEC §4 ("the same 404 … after the same work (malformed input is replaced by fresh random bytes and run through the full path)", "/reports … Uniform response"); api-endpoint skill ("Never return early")
What: The body is uniform (`200 {"status":"received"}`), but timing separates "the secret was still active" from "it was not" in one sample on a local path. Each report destroys a matching secret, so an attacker gets one sample per secret, which limits remote use. A malformed identifier skips the database, against §4 as written. Reveal, confirm and burn negatives were checked and are flat (Checked and clean).
Reproduction: `shhnote-server/tests/review_pass1.rs::review_timing_distribution` (debug build, SQLite, in-process, 200 interleaved samples each):
```
reveal never-existed             p10=332us p50=360us p90=389us p99=427us
reveal malformed                 p10=308us p50=335us p90=383us p99=448us
reveal expired-row               p10=330us p50=361us p90=396us p99=434us
reveal claimed-by-other          p10=315us p50=346us p90=384us p99=413us
report unmatched (well-formed)   p10=369us p50=396us p90=436us p99=519us
report malformed                 p10=56us  p50=59us  p90=64us  p99=81us
report matched                   p10=520us p50=556us p90=628us p99=1193us
burn unmatched                   p10=323us p50=348us p90=382us p99=423us
burn matched                     p10=429us p50=464us p90=512us p99=1103us
```
(The report matched p10 is above the unmatched p90. Burn matched vs unmatched already differ in status, 204 vs 404, so that gap reveals nothing new.)
Fix: run the same statement sequence on every path: replace a malformed lookup with random bytes and run `report()` (then roll back, if the code comment's "malformed is not notice" policy is to be kept), and always execute the counter upsert (`+0`) and the `UPDATE reports SET matched = matched OR $n`. Allowed under §12; no spec change (or change §4's wording if the no-ledger-row-for-garbage policy is kept).

### F-1-9: `Retry-After` reveals the exact rate-limit threshold
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:167-172 (`((1 - tokens) / rate).ceil()`), ratelimit.rs:272-274; content/en/docs.md:15 ("nothing about the threshold is revealed")
Violates: SPEC §4 ("a `Retry-After` that reveals no threshold")
What: Right after a bucket empties, `Retry-After = 3600 / per_hour` exactly, so a client learns the configured per-endpoint limit (and, with a user key, `rate_user_multiplier`) from one 429.
Reproduction: `shhnote-server/tests/review_pass1.rs::review_retry_after_reveals_threshold`: per_hour 10, 37 and 60 give Retry-After 360, 98 and 60, inferred 10, 37 and 60.
Fix: send a constant (for example `Retry-After: 60`, or the time to the next salt rotation rounded up to a fixed step), independent of the rate. No spec change.

### F-1-10: S3 error bodies, including the object key, are written to the error log
Severity: Medium (operator log access)
Location: crates/shhnote-server/src/storage.rs:520-525 (`status_error` embeds the first 200 chars of the S3 body), logged by api.rs:558-559 (`store error: {e}`), api.rs:320-321, scheduler.rs:349
Violates: CLAUDE.md ("nothing request- or user-specific is ever logged"), Principle 4/5; prompt item 1
What: AWS and MinIO error documents put `<Key>blobs/…</Key>` (and `<Resource>`) within the first 200 characters, so a failed GET/PUT/DELETE logs the object key with a log timestamp. `secrets.external_ref` maps that key to the row, which gives a per-secret access time, for example "reveal of this secret at 14:02". All other log sites were checked: only static text, sqlx `Display` (no bound values; Postgres `detail` is not printed) or io errors (no paths).
Reproduction: `shhnote-server/tests/review_pass1.rs::review_s3_error_body_puts_object_key_in_log_text` (a stand-in S3 answering like AWS): the logged line is `store error: S3 answered 404 Not Found: <?xml …><Error><Code>NoSuchKey</Code>…<Key>blobs/3IWPaDrZcGsikvLG87hUkQ</Key>…`.
Fix: log only the HTTP status and the S3 `<Code>` element (extract it and drop the rest of the body), never the key or resource.

### F-1-11: External-tier objects carry a creation timestamp linked to their row
Severity: Medium (operator/dump access); needs spec revision
Location: crates/shhnote-server/src/storage.rs:244-247 (local `rename`), storage.rs:370-378 (S3 PUT); `secrets.external_ref`
Violates: Principle 5 / §13 (per-secret `created_at`)
What: Every object under `SHH_LOCAL_PATH/blobs/` has mtime/ctime equal to its upload time, and every S3 object has `LastModified`. Since `external_ref` names the object, the operator has an exact `created_at` for every external (large) secret. A bucket listing alone shows creation times for all live large secrets, without any dump.
Reproduction: `shhnote-server/tests/review_pass1.rs::review_local_objects_carry_creation_time`: object mtime is within 6 ms of the upload.
Fix: local tier: `File::set_modified` / `set_times` to a fixed value (for example epoch, or the day) after the rename (ctime cannot be reset, so this only reduces the leak). S3 `LastModified` cannot be changed. Record it as an accepted residual of the external tier in SPEC §6.1 and the threat model, or quantise by batching. Needs a spec decision.

### F-1-12: API responses and redirects carry none of the §11 security headers
Severity: Low
Location: crates/shhnote-server/src/web.rs:93-98 (layer wraps only the web router), app.rs:21 (`web.nest("/api", api)` is added after the layer), app.rs:24-29 (subdomain API), app.rs:32 (trailing-slash 308 is outside every layer), drain.rs:329-335 (503)
Violates: SPEC §11 ("Headers on every response: … Referrer-Policy: no-referrer …"); web-page skill
What: All `/api/v1/*` responses (blob streams, 404s, `/config`, `/health`), the API fallback 404, every trailing-slash 308 and the drain 503 have no `Referrer-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, CSP or HSTS. Pages, static assets, web 404s and the locale redirect do have them. Practical impact is low (JSON and octet-stream, no navigation), but `nosniff` on blob responses and HSTS on the API subdomain are cheap.
Reproduction: `shhnote-server/tests/review_pass1.rs::review_security_headers_missing_outside_web_router`: missing on `GET /api/v1/config`, `GET /api/v1/health`, `GET /api/nope`, `POST reveal 404`, `GET /en/about/ (308)`.
Fix: apply `security_headers` in `app::router` as the outermost layer (after the nest and the host routing, around `redirect_trailing_slash`), and in `main.rs` outside `drain::track`.

### F-1-13: Structurally malformed bodies on credential endpoints bypass the uniform negative and echo input
Severity: Low
Location: crates/shhnote-server/src/api.rs:354, 440, 458, 481 (`Json<…>` extractor rejections)
Violates: SPEC §4 ("Every negative outcome … returns the same 404 … malformed input is replaced by fresh random bytes"; "/reports … Uniform response"); api-endpoint skill (one shared error shape)
What: A wrong JSON type, a missing field, invalid JSON or a missing `Content-Type` never reaches the handler: axum answers 422, 400 or 415 with a `text/plain` body that quotes part of the input. These are not existence leaks, since the caller only learns about its own input. But `/reports` stops being "always 200 fixed body", the error shape is not the shared JSON one, and the database path is skipped.
Reproduction: `shhnote-server/tests/review_pass1.rs::review_json_rejections_are_not_uniform`: e.g. `{"lookup": 12345}` gives `422 text/plain "Failed to deserialize the JSON body into the target type: lookup: invalid type: integer `12345`, expected a string at line 1 column 16"`; no content-type gives 415.
Fix: accept the body as `Bytes`/`Option<Json<Value>>` (or a custom extractor whose rejection maps to the endpoint's uniform answer), treat anything unusable as a malformed identifier, and run it through the normal path with random bytes.

## Suspicions

- **Postgres retains destroyed rows and orders rows by creation.** No `secure_delete` equivalent exists: deleted or updated tuples (and TOASTed BYTEA blobs) stay in heap pages until VACUUM reuses the space, and stay in `pg_wal`/archives and base backups. The system columns `xmin` (creation/last-update transaction id, monotonic) and `ctid` (physical position, roughly insertion order) order secrets by creation and show which rows were claimed recently. To confirm: with `SHH_TEST_PG_URL`, create, burn, then `SELECT xmin, ctid FROM secrets` before and after, and `pageinspect`'s `heap_page_items` on the relation and its TOAST table to find the burned blob. Likely a Medium finding needing a deployment note (frequent VACUUM, WAL retention), with the rest an accepted residual.
- **Local tier deletes are plain `unlink`.** `Local::delete` (storage.rs:254-259) does not overwrite, so blob bytes stay in free filesystem blocks, as does the spool file renamed into place. The data is ciphertext, but it was declared destroyed. Confirm with `debugfs`/`photorec` on a test volume. Probably an accepted residual for the threat model rather than a code change.
- **Reverse-proxy and access logs.** The app logs nothing per request, but `privacy.md` ("our server may briefly record … your IP address and the time") and the deploy guides should state that proxy access logs combined with F-1-2 link IPs to rows. Check `deploy/Caddyfile` for `log` directives (pass 6 scope).
- **`stats().active` and claimed rows.** The live active count excludes `claimed`, so an admin polling `/api/v1/admin/stats` sees `active` drop by one at the exact moment of each single-view reveal on a quiet instance (no counter moves until confirm or window expiry). This is the "count that lags reveals an in-flight transition" case from item 10, but at the admin level only and within spec ("the live active count"). Confirm by polling in a test; if it matters, count `active + claimed` together.
- **Rate-limit subjects for user keys are not cleared by rotation unless an anonymous request arrives.** Rotation only happens in `check()` (ratelimit.rs:103-112); `check_key` never rotates. The keys are unsalted `SHA-256(key)` by spec, so no linkability is lost, but the comment "rotation clears every bucket" only holds once some anonymous request comes in. Harmless as far as I can see.

## Checked and clean

- **Uniform negatives (reveal, confirm, burn).** Never-existed, malformed (wrong length / not base64), expired-but-present, claimed-by-someone-else, wrong claim token, consumed after confirm, burned, and reported all return byte-identical `404 {"error":{"code":"not_found","message":"No secret matches."}}` with exactly the headers `content-length: 61` and `content-type: application/json`, and no Retry-After or Cache-Control differences (`review_negatives_are_byte_identical`). Malformed identifiers are replaced by `getrandom` bytes and run through the same store calls (`decode32_or_random`, api.rs:526-535). No early return skips the database on reveal, confirm or burn. A reveal without a claim token always runs the claim UPDATE and then the TTL SELECT.
- **Negative timing on reveal.** Never-existed, expired row, claimed-by-other and malformed are within noise of each other (p50 335–361 µs; see F-1-8 table). Nothing beyond the unique-index lookup differs.
- **Database schema.** `secrets` has exactly the §3 columns. No `created_at`/`updated_at`, no defaults beyond `stats_daily` zeroes, no AUTOINCREMENT, no triggers, no foreign keys. The indexes `(status, expires_at)` and `(status, claim_expires_at)` key on values already stored. PK and UNIQUE indexes are on hashes (random order). `stats_daily` holds per-UTC-day counters only. `settings` holds overrides only. `api_keys` matches §8.
- **No cross-table statements.** No query touches `secrets` and another table in one statement. `report()` writes `reports` and `secrets` in one transaction but in separate statements, which is fine. Stats, settings and api_keys queries never reference `secrets` except `COUNT(*)` for active and `SUM(bucket)` for the tier ceiling.
- **Counters are transactional.** create, confirm, burn, report and sweep increment `stats_daily` inside the same transaction as the row change (secrets.rs:62-90, 145-163, 190-252). The day is `now − now mod 86400` (UTC). The yearly fold works (existing `store.rs` rollup test). A claim adds no counter, as §5.1 says.
- **SQLite `secure_delete = ON`** is set per pooled connection (lib.rs:84-98). The main file holds no destroyed blob after a checkpoint (see F-1-6 for the WAL). No query exposes the rowid.
- **Rate limiter.** The key is `HMAC-SHA256(salt, ip)`. IPv6 is truncated to /64 (ratelimit.rs:191-196, unit test). Rotation replaces the salt and clears the whole table (also when the table exceeds 200 000 entries). The salt lives only in memory and is never logged or persisted. `X-Forwarded-For` is honoured only when the socket peer is in `SHH_TRUSTED_PROXIES`, using the nearest untrusted hop from the right; garbage falls back to the peer (unit test plus code review). The 429 body is generic. Retry-After quantisation is the exception, see F-1-9.
- **Logging.** All 29 `log_*!` call sites were reviewed. Only static text, counts, sqlx `Display` (no bound values or Postgres `detail`), io errors (no paths) and config/startup messages are logged. The exception is the S3 body in F-1-10. No IPs, headers, paths or bodies are logged anywhere. No `tracing`/`log` subscriber is installed, so sqlx's statement logging goes nowhere. `println!` is used only for startup URLs and CLI subcommand output. No `.unwrap()` or `expect()` that formats request data is reachable from a handler (the only one is `header_value` on base64 and digit text).
- **Locale redirect** (`/s` → `/en/s`, `/burn`, with query, with `//host` path). It adds nothing, keeps the query verbatim, never emits an absolute or off-site Location, sets no cookie, and sends `Vary: Accept-Language` (`review_locale_redirect_adds_nothing`). The fragment is never seen by the server and browsers keep it. The trailing-slash redirect collapses leading slashes and backslashes (existing test).
- **Error pages** render fixed translations only and echo no path or query. The language links use the handler's fixed path.
- **Referrer-Policy on the web side.** Present on pages, static assets, web 404s, `/static/*` 404s and the locale redirect. `base.html` also has `<meta name="referrer" content="no-referrer">`. The API side is covered in F-1-12.
- **Static `?v=<hash>`.** A 6-byte content hash of the embedded assets. It is the same for every visitor and only identifies the public AGPL build, so it is not a tracking vector.
- **`/config` and `/health` content.** `/config` returns only instance policy (no active count, storage usage or key count). `/health` returns `{"status":"ok"|"degraded"}` with `no-store`. `GET /api/v1` returns `{"name":"shhnote","version":"v1"}` (no build version).
- **Admin surfaces.** The dashboard and stats API show only totals, the live active count and per-day rows. The settings page and API hold no per-secret data. The keys page shows key metadata as §8 allows. The per-secret facts the admin can see are the reports ledger (F-1-4) and key timing (F-1-3). Admin API responses are `no-store`.
- **Error bodies on create.** `invalid_meta`, `invalid_lookup_key`, `invalid_burn_key`, `invalid_lifetime`, `invalid_ttl`, `invalid_multipart`, `invalid_blob_length`, `too_large`, `files_disabled`, `storage_full` and `api_key_required` only restate public instance policy (the ladder and limits are already in `/config`). They are acceptable under §4, since create takes no credential that can be negated. The exception is `duplicate_key`, see F-1-7. Every message is a fixed generic string.
- **Templates and content.** No analytics, no external script, style, font or image URL, and no third-party request in any template or `content/en/*.md`. The only off-site link is the operator-set `source_url` footer link (navigation only, `no-referrer`). The report page collects only the link (`name="link"`), and the client sends only the derived `lookup` (client/src/ui/report.ts). The create, reveal, burn and report forms have no `method`/`action`, but they stay `hidden` until the script has attached `preventDefault` handlers in the same task, so form data never reaches a query string.
- **Response headers on success.** The blob response sets `Content-Length` from the bucket, `Cache-Control: no-store` and `application/octet-stream`. The TTL header is whole hours rounded up. The claim token is generated server-side with `getrandom` and stored only as its hash.

## Stored or transmitted but not in SPEC

- `reports` table columns: `lookup_key`, `count`, `first_reported_at`, `last_reported_at`, `matched` (§3 names "the reports ledger" only; see F-1-4).
- `api_keys.last_used_at` is refreshed on every keyed limited request and on every admin login or admin API call, to the second (F-1-3).
- External object metadata: filesystem mtime/ctime and S3 `LastModified` (F-1-11). The spool file names `<8 random bytes>.part` and the `tmp/` directory under the local root.
- `GET /api/v1/` info endpoint (`{"name","version"}`), not in the §4 table.
- Admin API `GET /admin/keys` and the keys page hidden input expose the full hex `SHA-256(key)` as `id`. Reports expose the first 8 bytes of `SHA-256(lookup)`. `GET /admin/stats?days=` accepts 1–400.
- CORS `Access-Control-Expose-Headers` includes `retry-after`. `Access-Control-Max-Age: 86400`. `Vary: Origin`.
- The drain 503 plain-text body `shutting down` with `Connection: close`. The trailing-slash `308`.
- Session cookie payload: bootstrap flag, key hash, expiry and a 16-byte nonce (§8 says "names only the key's hash"; the nonce and expiry are harmless additions).
- Startup stdout: `listening on http://…` and `site at …, API at …/v1`.
- `<body data-asset-version>` and the `data-api` attribute in every page.
- The SQLite `-wal`/`-shm` files and the never-shrinking main file (F-1-6).

## Out-of-scope observations (for other passes)

- The templates contain inline `style="…"` attributes (report.html:19, home.html:102, how_it_works.html:16,24,69,71, admin/*.html), which the CSP `style-src 'self'` blocks and the web-page skill forbids (pass 4).
- home.html:39-49 hard-codes the TTL options instead of rendering `settings.ttl_presets` (pass 4; it makes F-1-2 more precise).
- `rate_*_per_hour = 0` silently disables limiting (ratelimit.rs:155-157) (pass 4, settings validation).
- main.rs:29 and 67 use `eprintln!` instead of `log_error!` (CLAUDE.md rule; CLI-only, no request data).
