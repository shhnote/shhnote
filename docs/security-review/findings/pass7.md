# Pass 7 — Adversarial — findings

Reviewed: SPEC.md (in full); crates/shhnote-server/src/{api.rs,app.rs,web.rs,admin.rs,admin_api.rs,ratelimit.rs,storage.rs,scheduler.rs,drain.rs,log.rs,main.rs,clock.rs}, crates/shhnote-store/src/{lib.rs,secrets.rs,stats.rs,api_keys.rs}, migrations/sqlite/*, crates/shhnote-core/src/{settings.rs,padding.rs,secret.rs}, client/src/ui/reveal.ts, client/src/crypto/secret.ts, templates/secret.html. Written without reading any other findings file or any other `review_*` test. 2026-10-30.
Tooling run: `cargo test -p shhnote-server --test review_adversarial` (31 tests, all pass, 3 consecutive runs, about 5 s each); `cargo clippy -p shhnote-server --test review_adversarial -- -D warnings` (clean); `rustfmt --edition 2024` on the test file. cargo 1.99.1, rustc 1.99.1, Node v24.22.1. `SHH_TEST_PG_URL` is not set in this environment, so no Postgres runs; every result below is SQLite only.

How to read the tests: in `crates/shhnote-server/tests/review_adversarial.rs`, a test whose name starts with `broken_` passes by *demonstrating* the violation. Every other test passes by showing the property holds.

## Findings

### F-7-1: Concurrent creates overshoot the external tier's hard ceiling
Severity: High
Location: crates/shhnote-server/src/api.rs:298-311
Violates: SPEC §6.1 (tier guards are "the only hard, non-circumventable limits"), Principle 7
What: The ceiling check is a plain read (`SUM(bucket)` over external rows) followed by spool fsync, object write and row insert, with no lock or reservation in between. Requests that finish uploading at the same moment all see the same `used` value and all pass.
Reproduction: `broken_h_concurrent_creates_overshoot_the_tier_ceiling`. With a ceiling of 300 000 bytes (room for two 128 KiB objects), eight uploads released together: **8/8 created, 1 048 576 bytes counted, 1 049 592 bytes on disk**. This happens on every run.
Fix: Make check and reservation atomic. Either hold a process-wide `tokio::sync::Mutex` around check→put→insert (simple, since there is one process per tier), or keep an in-memory "reserved bytes" counter added under a lock before the put and released after the insert or the delete. No spec change.

### F-7-2: A client that disconnects after its upload leaves an object that nothing counts and nothing scrubs
Severity: High
Location: crates/shhnote-server/src/api.rs:306-328; crates/shhnote-server/src/scheduler.rs:37-65
Violates: SPEC §6.1 ("if the row cannot be written the object is deleted again"; ceilings "count every object the tier holds"), Principle 7
What: Once `storage.put` has renamed the object into `blobs/`, the cleanup only runs if the handler reaches the `match` on the insert result. When the client goes away, hyper drops the handler future. If that happens at any await between the put and the commit, the object stays on disk with no row. The ceiling counts rows, and the scrubber only visits `pending_delete` rows, so the object is never counted and never deleted. Repeating the trick fills the disk regardless of `SHH_LOCAL_MAX_TOTAL_BYTES`. On S3 it raises cost regardless of `SHH_S3_MAX_TOTAL_BYTES`.
Reproduction: `broken_h_disconnect_after_upload_leaves_an_uncounted_object`. It aborts the request task, which is what hyper does on disconnect, the moment the object appears: **10 objects / 1 311 990 bytes on disk, 0 bytes counted**, still there after `scheduler::scrub`.
Fix: Make the put→insert section cancellation-safe. Run it in a `tokio::spawn`ed task that the handler awaits, so a dropped request cannot cancel it, or hold a drop guard that deletes the key unless it was disarmed after commit. As a backstop, have the scrubber (or startup) delete objects in `blobs/` that no row references; on local disk that is a directory listing. No spec change.

### F-7-3: No request or body timeout; stalled uploads hold memory and uncounted spool disk indefinitely
Severity: High
Location: crates/shhnote-server/src/main.rs:126-131 (`axum::serve` with no timeout layer); crates/shhnote-server/src/api.rs:243-256; crates/shhnote-server/src/storage.rs:82-88
Violates: Principle 7, SPEC §6.1 (spool lives under the tier root but is not part of "every object the tier holds")
What: Nothing bounds how long a request may take to send its body. A create that sends its meta and part of its blob, then goes quiet, keeps its in-memory buffer (up to `blob_len(SHH_INLINE_MAX)`, about 2 MiB, plus Vec growth) or its spool file forever. The same goes for a JSON reveal whose body never completes. Spool bytes are not counted toward the ceiling, so N quiet uploads hold N × `SHH_EXTERNAL_MAX_OBJECT` of disk with no row and no 507. They also hold N file descriptors and N tasks.
Reproduction: `broken_i_stalled_bodies_are_never_timed_out`: a stalled create and a stalled reveal get no answer within 5 s. `broken_h_open_uploads_fill_disk_past_the_ceiling_without_rows`: six quiet uploads hold **6 spool files, 1 841 040 bytes, 0 rows** against a 300 000-byte ceiling, and the server never ends them. The spools are removed only when the client drops (Spool's `Drop`, checked in the same test).
Fix: Add a per-request deadline for the body (for example `tower_http::timeout::RequestBodyTimeoutLayer`, or a `tokio::time::timeout` around the multipart loop sized to the max object at a minimum rate) and a header-read timeout on the hyper builder. Count in-flight spool bytes toward the ceiling, or reserve the declared size up front (see F-7-1). No spec change; the spec could say that spool bytes count toward the ceiling.

### F-7-4: Every `GET /config` leaks a copy of the settings
Severity: High
Location: crates/shhnote-server/src/api.rs:168
Violates: Principle 7 (remotely triggerable unbounded resource use)
What: The handler `Box::leak`s a clone of `Settings` on every call so that it can return borrowed slices. `/config` is unauthenticated and not rate-limited, so any client can grow the process's memory without bound until the OOM killer stops it.
Reproduction: `broken_i_every_config_request_leaks_memory` uses a thread-local allocation counter: **734 000 bytes still allocated after 2 000 requests (367 bytes per request, more with regions and presets set)**.
Fix: Serialize from the `Arc<Settings>` snapshot inside the handler (owned `ConfigResponse`, or `Json(serde_json::json!{…})`), with no leak. No spec change.

### F-7-5: A user key's `last_used_at` names the second its secret was created, and `expires_at` gives that second away
Severity: Medium
Location: crates/shhnote-server/src/ratelimit.rs:237; crates/shhnote-store/src/api_keys.rs:70-77; crates/shhnote-server/src/api.rs:275; crates/shhnote-server/src/admin_api.rs:296-313
Violates: D-17 ("never linked to secrets"), SPEC §8 ("nothing records which key created which secret"), Principle 5, §13 (per-secret `created_at`)
What: Every keyed request writes `last_used_at = now` to the second, and the admin API returns it. Every row stores `expires_at = now + ttl_seconds`. The web client sends one of nine fixed presets, so `expires_at − preset` is the exact creation second of each row. Matching the two links a key to the secret it created: one candidate when traffic is low, a small set otherwise. The admin API plus a dump is enough. The second half of this finding stands without keys: `expires_at` acts as a per-secret creation timestamp at rest.
Reproduction: `broken_k_last_used_at_equals_creation_second_in_expires_at`. Three secrets are created about one second apart, the middle one with a user key and the 1-day preset. Exactly that one satisfies `expires_at − preset == last_used_at`.
Fix: Two changes. Coarsen `last_used_at` to the UTC day (it exists to spot dead keys), or do not touch it on the create path. Coarsen `expires_at` when the row is written (for example round it up to the next minute or 10 minutes, so it can never shorten a TTL; expiry is already enforced by `expires_at > now`), so creation time cannot be recovered. The spec should say both columns are coarsened, so this needs a spec note.

### F-7-6: Create's `duplicate_key` answer is a liveness oracle for anyone holding dumped hashes, and lets them plant a row behind a consumed link
Severity: Medium
Location: crates/shhnote-server/src/api.rs:287-290, 318-326; crates/shhnote-store/src/secrets.rs:77-86
Violates: D-3 ("a database dump must not let anyone … otherwise act on secrets"), §2.12, D-1 (a consumed link must show the uniform negative)
What: A dump holder sends `POST /secrets` with a dumped `lookup_key` (or `burn_key`) and a random other key. They get `400 duplicate_key` while the row exists and `201` once it is gone, so at any later time they learn when each dumped secret was consumed or destroyed, without the link. The `201` also plants a row under the victim's `lookup_key`, so the victim's already-consumed link now returns `200` with the attacker's blob (it fails to decrypt) instead of the uniform 404.
Reproduction: `broken_e_create_is_a_liveness_oracle_for_dumped_hashes`. The test sees `duplicate_key` by `lookup_key` and by `burn_key` while the secret is alive, then `201` after the recipient confirms, then `200` on the victim's own link.
Fix: Answer a key conflict with the same `201` (no row, no counter), since only a client that reused a seed can hit it honestly. That closes the oracle. Planting can't be fully prevented without keeping hashes of destroyed rows, which §13 rejects (tombstones). With the oracle closed, the attacker no longer knows when a plant would land. A spec note in §5.1 should record planting as an accepted residual.

### F-7-7: S3 error bodies, including the object key, are logged at the default level
Severity: Medium
Location: crates/shhnote-server/src/storage.rs:520-525; crates/shhnote-server/src/api.rs:416, 559; crates/shhnote-server/src/scheduler.rs:62
Violates: Principle 4/5, CLAUDE.md ("nothing request- or user-specific is ever logged")
What: `status_error` copies the first 200 characters of the S3 response body into the `io::Error`. `ApiError::internal` logs it as `store error: {e}` at `error`, which is printed at the default `SHH_LOG_LEVEL`. For a missing object (and for `AccessDenied` and similar), AWS and MinIO echo `<Key>blobs/…</Key>`. That is the row's `external_ref`, so the journal's timestamp records when that specific secret was read. The scrubber's `deleting object failed: {e}` path leaks the same way.
Reproduction: `broken_q_s3_errors_put_the_object_key_into_the_log`, against an in-test fake S3. The server actually printed: `error: store error: S3 answered 404 Not Found: <?xml …?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>blobs/CyUPGKgWx5vc4CahckMCrQ</Key>…`
Fix: Log only the status code and the S3 `<Code>` element (for example `NoSuchKey`), never the body or the key. No spec change.

### F-7-8: Behind a trusted proxy that appends its own `X-Forwarded-For` line, the client picks its rate-limit identity
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:86-96
Violates: SPEC §4 ("the nearest untrusted `X-Forwarded-For` hop is used")
What: `headers.get("x-forwarded-for")` reads only the first header line. A proxy that adds a new line rather than merging (HAProxy `option forwardfor`, some CDNs) puts the real hop in the last line. The first line is entirely the client's, so each request can claim a fresh address and never run out of tokens. The shipped Caddy config merges into one line, so it is not affected.
Reproduction: `broken_j_client_supplied_first_xff_line_wins_behind_a_proxy` (peer 10.0.0.1 trusted, limit 2/h): one merged header is limited correctly (control), while 20 requests with `XFF: <spoof>` plus `XFF: 203.0.113.9` all pass.
Fix: Iterate `headers.get_all("x-forwarded-for")` in order, join the lines, then walk from the right as now. No spec change.

### F-7-9: IPv4-mapped IPv6 peers share one rate-limit bucket
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:190-195
Violates: SPEC §4 (per-client limits), Principle 9
What: On a dual-stack listener (`SHH_HOST=::`), IPv4 clients arrive as `::ffff:a.b.c.d`, whose first 64 bits are all zero. Every IPv4 client in the world then hashes to the same /64 bucket, so one client exhausting reveal or create locks out every other IPv4 user. The same happens when a trusted proxy forwards mapped addresses.
Reproduction: `broken_j_ipv4_mapped_peers_collapse_into_one_bucket`: two reveals from `::ffff:203.0.113.5`, then `::ffff:198.51.100.7` gets 429.
Fix: Normalise with `Ipv6Addr::to_ipv4_mapped()` (and the client IP in general) before `ip_prefix`. No spec change.

### F-7-10: Flooding the limiter's table resets every client's limit
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:65, 107-112
Violates: SPEC §4 (rate limiting per client); Principle 7 makes limits best-effort, hence Low
What: When the table passes 200 000 entries it is cleared with a fresh salt, by design, to bound memory. A client with many addresses (an IPv6 /48 has 65 536 /64s; four endpoints' worth is enough) can trigger the clear at will, and with it refill its own exhausted buckets and everyone else's.
Reproduction: `broken_j_flooding_the_bucket_table_resets_everyones_limit`: an exhausted /64 gets tokens again after 200 001 other /64s.
Fix: Evict the oldest or fullest buckets instead of clearing everything (for example drop buckets that are full; they carry no state), or cap entries per /48. No spec change.

### F-7-11: `claim_window_secs` is unbounded, so a claimed secret outlives the 14-day maximum
Severity: Low
Location: crates/shhnote-core/src/settings.rs:152; crates/shhnote-store/src/secrets.rs:112, 125-142, 231-252
Violates: D-7 (maximum TTL 14 days), Principle 6 (`claimed` is time-bounded)
What: The settings PATCH and the panel accept any `claim_window_secs`. The claim, re-download and sweep predicates ignore `expires_at` once a row is claimed. A 60-second single-view secret claimed under a 365-day window stays stored, and re-downloadable by the claimant, for a year. `max_ttl_secs` is clamped to 14 days, but this second clock is not.
Reproduction: `broken_n_claim_window_keeps_a_secret_past_14_days`: after `PATCH {"claim_window_secs": 31536000}`, `sweep(now+300d)` destroys nothing and `redownload(now+300d)` still returns the blob.
Fix: Validate `claim_window_secs` to a small range (for example 60 s to 1 h), and set `claim_expires_at = min(now + window, expires_at + window_max)` or similar. A spec line in §7.2 should give the bound.

### F-7-12: The 64 KiB padding minimum, the ladder and the TTL presets can be patched past the spec
Severity: Low
Location: crates/shhnote-core/src/settings.rs:150-151, 158, 184-193; crates/shhnote-core/src/padding.rs:395-407
Violates: D-6 ("with a 64 KiB minimum padded size"), §6.2 ("every file under 64 KiB looks like text"), D-7 for presets
What: `padding_min` takes any u64, including 1, and ladder entries take any value, including 7. Under such a policy the server accepts 1-, 104- or 4096-byte buckets, which leak text length to within a few bytes. In buckets mode `padding_min` is ignored altogether, and `as_strings` reports the default for it. `ttl_presets` is never checked against the TTL bounds, so 30 days or −5 s are accepted and shown in the UI, and creates with them then fail.
Reproduction: `broken_n_padding_minimum_can_be_patched_away`: after `padding_min = 1`, buckets 1, 104 and 4096 are created (201); ladder `[7, 1048576]` and presets `[2592000, -5]` are accepted.
Fix: Reject `padding_min < 65536` and ladder entries below it, and apply `padding_min` in buckets mode too (or drop it from that mode explicitly). Require every preset to lie within `[min_ttl_secs, max_ttl_secs]`. If operators are meant to go below 64 KiB, the spec must say so (spec revision).

### F-7-13: Accepted settings values overflow arithmetic on the request path
Severity: Low
Location: crates/shhnote-store/src/secrets.rs:112 (`now + window_secs`); crates/shhnote-server/src/ratelimit.rs:120 (`per_hour * user_multiplier`, u32); crates/shhnote-server/src/api.rs:341 (`2 * text_max_bytes`); crates/shhnote-core/src/padding.rs:436 (`len + mask` with a huge `padding_min`)
Violates: SPEC §8 (settings "validated as a whole"), Principle 12
What: The PATCH accepts `claim_window_secs = i64::MAX`, `rate_user_multiplier = u32::MAX` and very large `text_max_bytes` and `padding_min`. In debug builds every single-view reveal then panics. Release has no `overflow-checks`, so it wraps silently instead: a negative `claim_expires_at` means re-download never works, and a wrapped multiplier can reach 0, which means "unlimited", for user keys.
Reproduction: `broken_n_patched_values_overflow_on_the_request_path`. After the PATCH, a reveal panics with `attempt to add with overflow` at `crates/shhnote-store/src/secrets.rs:112:15`.
Fix: Bound every numeric setting in `with_overrides` (window, multiplier ≤ 1000, `text_max_bytes` ≤ inline max, `padding_min` ≤ external max), and use `checked_`/`saturating_` arithmetic at those four sites. No spec change.

### F-7-14: Admin key deletion panics on a non-ASCII id
Severity: Low
Location: crates/shhnote-server/src/admin_api.rs:368-375; crates/shhnote-server/src/admin.rs:717-724
Violates: CLAUDE.md / Pass 3 rule (no panic reachable from a handler)
What: `unhex` checks the byte length and then slices `&text[i..i + 2]`. A multi-byte character lands mid-slice and panics. The caller needs an admin key, or the bootstrap token while no key exists, and the panel needs a CSRF token too. The panic kills that connection's task rather than the process.
Reproduction: `broken_i_admin_key_delete_panics_on_non_ascii_id` sends `{"id": "aé" + 61×"a"}`: `end byte index 2 is not a char boundary` at admin_api.rs:374.
Fix: Reject non-ASCII first (`text.is_ascii()`), or iterate `text.as_bytes().chunks(2)`. No spec change.

### F-7-15: Malformed JSON bodies skip the uniform negative and echo parser detail
Severity: Low
Location: crates/shhnote-server/src/api.rs:354, 440, 458, 481 (`Json<…>` extractors)
Violates: SPEC §4 ("every negative outcome on an endpoint that takes a secret credential returns the same 404 with the same body")
What: A body that is not JSON, lacks a field, has a wrong type or has the wrong content type is answered by axum's default rejection. That is 400, 415 or 422 as `text/plain`, quoting serde's message (for example `burn_token: invalid type: integer 7`). The answer does not depend on any secret, so it is not an oracle, but it is a second response shape on credential endpoints, and not JSON.
Reproduction: `broken_i_malformed_bodies_skip_the_uniform_negative` (output in the test log: reveal "not json" gets 400, `{}` gets 422, text/plain gets 415, `{"burn_token":7}` gets 422 with the field name).
Fix: Take `Bytes` and parse with `serde_json::from_slice`, mapping any failure to the random-bytes path, which ends in the uniform 404. Alternatively, wrap the routes in a rejection mapper that returns `uniform_negative()`. No spec change.

### F-7-16: Logout needs no session and no CSRF token
Severity: Low
Location: crates/shhnote-server/src/admin.rs:34, 262-268
Violates: SPEC §8 ("Forms carry a CSRF token derived from the session; a request without it gets 403")
What: `POST /{locale}/admin/logout` clears the cookie for anyone. SameSite=Strict stops the cookie from being *sent* cross-site, but a cross-site top-level form POST still receives and applies the clearing `Set-Cookie`. So any page can log an admin out. The impact is nuisance only.
Reproduction: `broken_m_logout_needs_no_session_or_csrf`: no cookie and no token still get 303 and `shh_admin=; … Max-Age=0`.
Fix: Authenticate and `check_csrf` in `logout` like the other POSTs. No spec change.

### F-7-17: A report that matches does measurably more work than one that does not
Severity: Low
Location: crates/shhnote-store/src/secrets.rs:204-227
Violates: SPEC §4 ("after the same work")
What: A matching report also deletes the row (or parks it), upserts the `removed` counter and sets `matched`. In-process on SQLite the medians are **532 µs matched vs 374 µs unmatched**, and the matched p10 (501 µs) is above the unmatched p90 (447 µs), so one sample over a quiet low-latency path can tell them apart. The value to an attacker is small: the reporter already holds the link (a TTL reveal is a pure read), and a matching report destroys the secret, so each secret gives at most one sample.
Reproduction: `c_report_answer_is_identical_and_timing_is_measured` (199 interleaved pairs; the numbers are printed with `--nocapture`). The same test shows status, body and headers are byte-identical.
Fix: Accept it as a residual and record it in §4, or pad the response time to a floor (for example respond no earlier than 2 ms after receipt) on all five credential endpoints. Recording it in §4 needs a spec note.

## Suspicions

- **P with JavaScript: `isTrusted` on the form's `submit` event does not stop a script-driven click.** Per the DOM and HTML specs, the `submit` event fired by the form-submission algorithm is UA-dispatched, so it has `isTrusted = true` even when the submission was triggered by `button.click()` or `form.requestSubmit()` from a script. Only `dispatchEvent(new Event("submit"))` is untrusted. A JavaScript-executing scanner that "clicks" every button would therefore consume the secret (client/src/ui/reveal.ts:48-50). No browser is available here, and Node has no form submission, so this is not reproduced. To confirm: in Chromium, Firefox and Tor Browser, open `/en/s#…` for a live single-view secret, run `document.querySelector('[data-reveal-form] button').click()` in the console, and watch for the POST to `/secrets/reveal`. A fix would check `event.submitter` together with a trusted `pointerdown` or `keydown` seen on the button. Note that §5.1 already accepts "revealed by an automated link scanner" as a residual.
- **F-7-2 over a real socket.** The test simulates disconnection with `JoinHandle::abort`. It is worth confirming with a raw TCP client that sends the full multipart body and closes immediately, then counting files in `blobs/`. Hyper 1.x drops the service future on HTTP/1 connection close, which is the premise here.
- **A missing external object on a claimed row gives a 500, and the secret is consumed.** Seen in the Q test: the claim commits, then `storage.get` fails, so the reveal answers `500 internal` rather than the uniform 404. Only a link holder sees this, and the body is generic. Whether the claim should be undone on that path is a D-1 question (reverting is rejected). Confirm the intended behaviour with the spec owner.
- **Postgres.** None of the race tests (A, O, F-7-1) ran against Postgres, because `SHH_TEST_PG_URL` is unset. The claim race uses `UPDATE … RETURNING` inside a READ COMMITTED transaction, which should also give exactly one winner. Run `a_concurrent_reveals_have_exactly_one_winner` with a Postgres store to confirm.

## Checked and clean

- **A (concurrent single-view reveals):** `a_concurrent_reveals_have_exactly_one_winner`: 5 rounds × 50 concurrent reveals on an 8-thread runtime gave exactly one 200 with a claim token, and every loser got the byte-identical uniform 404 (no busy-database 500). `a_reveal_and_burn_race_never_both_succeed`: 20 reveal/burn races, never both.
- **B (re-download without the claim token):** `b_claimed_secret_needs_the_exact_claim_token`: no token, a random token, another secret's token, the stored claim hash, a one-bit flip, a padded, uppercased or empty token all get the uniform 404. The right token works, and after confirm even the right token fails. `b_claim_token_dies_with_the_window`: works at +899 s, not at +901 s.
- **C (reporter learns existence), status, body and headers:** `c_report_answer_is_identical_and_timing_is_measured`: live, claimed, never-existed, malformed and already-reported all get the same `200` with the same body and headers. Timing is F-7-17.
- **D (burn with a wrong token):** `d_wrong_burn_token_is_indistinguishable_and_harmless`: random, bit-flipped, the stored `burn_key`, the lookup value, garbage and empty all get the identical 404 with identical headers. Nothing is destroyed or counted, and a claimed secret refuses burn (§5.3).
- **E (dump lets you act):** `e_dump_holds_only_hashes_and_hashes_open_nothing`: the SQLite file plus `-wal`/`-shm` contain no raw lookup, burn token or claim token, raw or base64. They do contain the hashes. Presenting any stored hash to reveal, re-download, burn, confirm or report has no effect, and both secrets still work afterwards. The liveness oracle is F-7-6.
- **F / G (same-bucket blobs distinguishable; passphrase visible):** `fg_direct_passphrase_text_file_blobs_look_the_same`: direct-text, direct-file, passphrase-text and passphrase-file blobs, made with the shipped default Argon2 parameters, have equal length, an identical argon field (bytes 16..28), the same 201 at create, the same reveal headers and Content-Length, and are served byte-for-byte as received. The server stores only `bucket` and `lifetime` about them. Both clients use `ARGON2_DEFAULT` in direct mode (client/src/crypto/secret.ts:85, crates/shhnote-core/src/secret.rs:115-123).
- **J, the three named attacks:** `j_ipv6_neighbours_xff_and_garbage_bearer_share_the_limit`: three addresses in one /64 share a bucket, a direct peer's `X-Forwarded-For` is ignored, and random 43-character bearers, a 500-character bearer, `Basic` auth and a valid *admin* key are all treated as the same anonymous client. The evasions that do work are F-7-8, F-7-9 and F-7-10.
- **L (locale redirect):** `l_locale_redirect_stays_on_site_and_adds_nothing`: 15 hostile paths and `Accept-Language` values (`//evil.com`, `/\evil.com`, encoded slashes, `../`, `/./\evil.com/`, a hostile Host) all redirect to a path-absolute same-origin `Location` that never contains `#` or `://`, and the query is carried unchanged.
- **M (admin without a session):** `m_admin_needs_session_csrf_and_retires_bootstrap`: missing, empty, re-tagged, expiry-stretched, key-swapped and MAC-less cookies are redirected to login on GET and POST. A valid session without a CSRF token, with an empty or foreign token, or with a junk token gets 403 on key create and delete. The first admin key ends live bootstrap sessions and retires the token for panel login and the admin API. A user key opens neither. Deleting an admin key ends its session. The one gap is logout (F-7-16).
- **N (TTL above 14 days; invalid padded size):** `n_ttl_is_capped_at_14_days_whatever_is_patched`: `max_ttl_secs = 30d` is clamped to 1 209 600, `min_ttl_secs`/`default_ttl_secs` above it are refused as a whole (422), `ttl_seconds` of 14d+1 and `i64::MAX` get `invalid_ttl`, a blob that is invalid under the live ladder gets `invalid_blob_length`, and buckets mode without a ladder is refused. The gaps are F-7-11, F-7-12 and F-7-13.
- **O (scheduler serves pending_delete or double-counts):** `o_pending_delete_is_never_served_and_counts_once`: 4 concurrent sweeps of a lapsed external claim count `viewed` exactly once. The parked row is refused by reveal, re-download, confirm and burn, and report does not count it. A later sweep counts nothing more. 10 confirm-versus-sweep races each add exactly one `viewed`. The scrubber deletes objects and then rows, leaving `blobs/` empty.
- **P (scanner without JavaScript):** `p_following_the_link_and_its_assets_consumes_nothing`: GET, HEAD and OPTIONS on `/s#…`, `/s`, `/burn`, every redirect and every same-origin `src`/`href` in the pages leave the single-view secret revealable, with `viewed = 0`. For JavaScript-executing scanners, see Suspicions.
- **Q (logs), apart from F-7-7:** there are no `log_*` call sites at debug or trace (log.rs only defines them), no tracing or log subscriber is installed for dependencies, and no request, IP or header is logged anywhere. SQLite error `Display` output carries no bound values. So `SHH_LOG_LEVEL=trace` prints nothing more than `error`.
