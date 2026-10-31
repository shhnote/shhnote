# Pass 2 — Resource exhaustion, races and lifecycle — findings

Reviewed: `crates/shhnote-server/src/{api.rs,storage.rs,scheduler.rs,drain.rs,app.rs,main.rs}` (in full), `ratelimit.rs` (bucket table only), `crates/shhnote-store/src/{lib.rs,secrets.rs}` (in full), `crates/shhnote-core/src/{padding.rs,chunks.rs,blob.rs}`, storage/size parts of `config.rs` and `settings.rs`, `client/src/crypto/padding.ts`, the body-limit and serve paths in axum 0.8.9 (`src/serve/mod.rs`), hyper 1.12.0 (`server/conn/http1.rs`), sqlx-core 0.9.0 pool options; 2026-10-30.
Tooling run: cargo 1.99.1 / rustc 1.99.1;
`cargo test -p shhnote-server --test review_pass2 -- --nocapture`,
`cargo test -p shhnote-store --test review_pass2 -- --nocapture`,
`cargo test -p shhnote-core --test review_pass2_padding`,
`cargo clippy` on all three test targets (`-D warnings`, clean). SQLite only:
`SHH_TEST_PG_URL` is not set in this environment, so the Postgres claim race
(`review_fifty_concurrent_claims_one_winner_postgres`) skipped itself. No real S3:
the S3 tests use an in-process fake endpoint.

Tests that reproduce a finding assert the behaviour the spec requires, so they **fail**
while the finding stands.

## Findings

### F-2-1: No header, body, idle or request timeouts and no concurrency cap; stalled clients hold memory, spool files and sockets forever
Severity: High
Location: crates/shhnote-server/src/main.rs:126-133 (`axum::serve` with no timer or timeouts); crates/shhnote-server/src/api.rs:244-256 (`blob_field.chunk()` awaited with no deadline); crates/shhnote-server/src/api.rs:243,253 (in-memory sink); crates/shhnote-store/src/secrets.rs:72 (`secret.blob.clone()`)
Violates: Principle 7 (operator cost is hard-bounded); D-4 ("bounded memory")
What: `axum::serve` builds hyper's `auto::Builder` without a timer, so hyper's default 30 s `header_read_timeout` never takes effect, and nothing else sets a header, body, idle or total timeout. The create handler then waits on `chunk()` with no deadline. A client that sends half a request line, or sends ~2 MiB of blob and then stops, keeps its connection, its in-flight slot and its buffer (or spool file) for as long as it likes. Nothing caps concurrent requests, so N stalled uploads hold N × `blob_len(inline_max)` of RAM (about 2 MiB each by default; the `Vec` grows by doubling, so its capacity reaches 4 MiB, and `Store::create` clones it once more). The per-IP create limit (30/h) only caps each IP at 30 stalled connections, and IPv6 is bucketed by /64, so one /48 gives 65 536 buckets. Slow readers on the reveal side hold the same 2 MiB inline `Vec`, or an open file or S3 socket, for as long as they take.
Reproduction: `review_stalled_clients_are_never_timed_out` sends `POST /api/v1/secrets HTTP/1.1\r\nHost: local` on one socket, and on another sends full headers plus 1 MiB of blob, then waits 35 s. Observed: `header-stall closed=false; upload-stall closed=false; spool (1, 1048576)`, so both connections are still open and the spool file is still on disk.
Fix: Serve with `hyper_util::server::conn::auto::Builder` directly (already a dependency; enable its `server-auto` feature): set `.timer(TokioTimer::new())` with `http1().header_read_timeout(..)` and an idle keep-alive limit. Wrap every `chunk()`/`next_field()` in `tokio::time::timeout` (an idle timeout per chunk, plus an overall deadline scaled to `max_blob_bytes`). Add a process-wide `tokio::sync::Semaphore` sized in bytes (the inline in-memory budget) that a create acquires before it buffers. Pre-size the buffer and pass it into the store by value instead of cloning it. No spec change is needed.

### F-2-2: The `meta` part is read whole before its 4096-byte check; one request can make the server buffer up to the full body limit (64 MiB by default) in RAM
Severity: High
Location: crates/shhnote-server/src/api.rs:218-221; crates/shhnote-server/src/api.rs:102,112
Violates: SPEC §4 ("`meta` precedes `blob` so the server can validate before streaming"); D-4; Principle 7
What: `meta_field.text()` collects the entire part into a `String` and only then checks `len() > 4096`. The only bound on it is the route's body limit, `max_blob_bytes + 16 KiB`, which is `SHH_EXTERNAL_MAX_OBJECT` (default 64 MiB, and the operator can set it to any size) whenever an external tier is enabled. Every concurrent request can hold that much, so this multiplies with F-2-1.
Reproduction: `review_meta_part_is_buffered_whole_before_its_size_check` streams a 32 MiB `meta` part to a local-tier instance and counts the bytes the server pulls. Observed: `status 400 code "invalid_meta", server pulled 33554658 bytes`, so the whole part was buffered before the refusal.
Fix: Read `meta` with `while let Some(c) = field.chunk().await?` into a `Vec` and refuse with `invalid_meta` the moment it passes 4096 bytes. No spec change is needed.

### F-2-3: The spool is unbounded: whole blobs are written to disk before the ceiling, length or `files_disabled` checks, and spool bytes never count toward the ceiling
Severity: High
Location: crates/shhnote-server/src/api.rs:244-272 (checks after the loop), crates/shhnote-server/src/api.rs:296-305 (ceiling check after spooling); crates/shhnote-server/src/storage.rs:82-88 (spool under the local root, or under `SHH_SPOOL_PATH` for S3)
Violates: Principle 7 ("Disk and object-storage ceilings are absolute"); SPEC §6.1 tier guards
What: Once a blob outgrows the inline tier it is streamed to `<local root>/tmp` (or to `SHH_SPOOL_PATH`) until the client stops sending, up to the body limit. The length check, the `files_disabled` cap and the ceiling check all run afterwards. Spool files are not part of `external_bytes()`. So on a local tier that is already full, N concurrent uploads still write N × `SHH_EXTERNAL_MAX_OBJECT` to the same disk the ceiling is meant to protect. Combined with F-2-1 they can stay there indefinitely. On an S3 instance, the spool disk has no bound at all.
Reproduction: `review_spool_files_exceed_the_tier_ceiling` fills a 300 000-byte local tier with two 128 KiB objects, then opens 4 uploads that each send 4 MiB and pause. Observed: `tier holds 262144 bytes of 300000; 4 spool files hold 16777216 bytes more (mode Some("644"))`. Each upload ends with a 400 or 507 only once the client finishes or disconnects.
Fix: Keep a process-wide reservation counter of in-flight spool bytes. When a request spills, and on every chunk after that, refuse with 507 as soon as `external_bytes + reserved + written` would pass `max_total_bytes()`. Release the reservation when the spool is dropped. Enforce `max_blob_bytes`, and with `files_enabled = false` the text-only cap `blob_len(text_only_bucket)`, while streaming rather than after. For S3, bound the spool directory too (by the S3 ceiling or a separate cap). Spec revision: §6.1 should say that in-flight spool bytes count against the local ceiling, and should define a bound for `SHH_SPOOL_PATH`.

### F-2-4: The ceiling check and the write are not atomic; concurrent creates together cross the ceiling by any factor
Severity: High
Location: crates/shhnote-server/src/api.rs:298-318; crates/shhnote-store/src/secrets.rs:267-275 (`external_bytes` sums rows)
Violates: Principle 7; SPEC §6.1 ("a create that would cross the ceiling gets `507 storage_full`")
What: `used = external_bytes()` is read, compared, then the object is put and finally the row is inserted, each step with an `await` between. Every request that reads `used` before any of the others has inserted its row passes the check.
Reproduction: `review_concurrent_creates_cross_the_ceiling` fires 16 concurrent 128 KiB creates at a 300 000-byte local tier (room for 2). Observed: `created 16, refused 0; rows count 2097152 bytes, 16 objects use 2099184 bytes, ceiling 300000`. The ceiling was crossed by 7×.
Fix: There is one server process per database, so a process-wide `tokio::sync::Mutex<u64>` reservation is enough. Under the lock, check `external_bytes + reserved + bucket <= max` and add `bucket` to `reserved`. Release it after the row insert succeeds or the object is deleted. This shares the reservation with F-2-3. If several processes are ever supported, use a single-row counter updated with a conditional `UPDATE ... WHERE used + $1 <= $2` in the create transaction.

### F-2-5: `GET /config` leaks a clone of the settings on every request (`Box::leak`), and the endpoint is never rate-limited
Severity: High
Location: crates/shhnote-server/src/api.rs:166-168
Violates: Principle 7; SPEC §4 (`/config` is unthrottled by design, so it must be free)
What: Each call runs `Box::leak(Box::new((*state.settings.load()).clone()))`, so the memory is never freed. The comment's premise ("the settings live for the process") holds for the snapshot but not for a fresh clone made on every request. Any client can grow the server's RSS without limit by polling an endpoint that is never limited.
Reproduction: `review_config_leaks_memory_per_request` (run it alone for a clean number): `RSS 19976 KiB -> 41256 KiB after 50000 GET /config: 435 bytes per request`. That is about 435 MB per million requests, never reclaimed.
Fix: Make `ConfigResponse` own its data (`ladder: Vec<u64>`, `ttl_presets: Vec<i64>`, `regions: Vec<Region>`, cloned from the snapshot), or serialise straight from the `Arc` snapshot held for the duration of the handler. No spec change is needed.

### F-2-6: The S3 client has no connect, TLS, request or body timeouts; a hung endpoint stalls the whole scheduler loop, reveals and creates indefinitely
Severity: Medium
Location: crates/shhnote-server/src/storage.rs:454-476 (`send`), :380-387 (`get` streams `Incoming` with no idle bound), :337-342 (startup versioning check); crates/shhnote-server/src/scheduler.rs:16-31 (sweep, scrub and roll-up run serially in one task), :55-64
Violates: SPEC §5 ("expiry is enforced ... by the scheduler durably"); Principle 6 ("both time-bounded"); Principle 7
What: Every S3 call opens a fresh TCP/TLS connection and waits without limit. One hung `DELETE` in `scrub` blocks the scheduler task forever, so `sweep` and `rollup_daily` never run again. Expired inline rows (blobs included) and lapsed claims then stay in the database until restart, and `pending_delete` objects stay in the bucket, still counting toward the ceiling. Reveals and creates against S3 hang the same way, and a hung endpoint at startup hangs `Blobs::open`. Triggering this needs the object store to misbehave, not a remote client, so it is Medium.
Reproduction: `review_hung_s3_hangs_scheduler_reveal_and_create` runs against a fake S3 that answers 200 and then stops answering. Observed: `within 10s: scrub finished=false, reveal finished=false, create finished=false`.
Fix: Wrap connect, handshake and `send_request` in `tokio::time::timeout` (for example 30 s). Wrap the response body in an idle-timeout adapter. Run `scrub` in its own task, or give each pass a time and row budget, so `sweep` always runs every 60 s. Also add `LIMIT` to `pending_deletes` (secrets.rs:255-264 uses an unbounded `fetch_all`). Retries are not needed: the scrubber already retries on its next pass.

### F-2-7: If a row exists but its object is gone, reveal answers 500 instead of the uniform 404, after the single-view claim has already been committed
Severity: Low
Location: crates/shhnote-server/src/api.rs:372-383, :410-417; crates/shhnote-store/src/secrets.rs:94-122 (claim commits before the object is opened)
Violates: SPEC §4 (uniform negative on every endpoint that takes a secret credential)
What: `blob_response` opens the object only after `claim` has committed. If the open fails (object deleted or corrupted, an S3 error, or the narrow race where a re-download's `SELECT` succeeds just before the sweep parks the row and the scrubber deletes the object), the client gets `500 internal`, while a lookup that never existed gets `404 not_found`. For single-view secrets the claim is already committed and the 500 carries no claim token, so the secret is consumed and cannot be re-downloaded. The rough match is the §5.1 accepted residual, but that residual covers a lost response, not a server-side fault. Only a link holder learns the difference, and it needs a storage fault, so this is Low.
Reproduction: `review_missing_object_is_not_the_uniform_negative` deletes the object files and reveals. Observed: `ttl 500 "internal"; single-view 500 "internal" then 404 "not_found"; never existed 404 "not_found"`.
Fix: Open the object (local `File::open`, or the S3 GET response headers) before committing the claim transaction. On failure, roll back and return `ApiError::NotFound` (and log it). For TTL, map an open failure to `NotFound`. No spec change is needed.

### F-2-8: Orphan objects are never counted or collected; the ceiling sums `bucket` from rows, not the objects the tier holds
Severity: Medium
Location: crates/shhnote-store/src/secrets.rs:267-275; crates/shhnote-server/src/api.rs:308-327 (orphan only logged when cleanup fails); crates/shhnote-server/src/storage.rs:222-238 (startup clears only `tmp/`)
Violates: SPEC §6.1 ("They count every object the tier holds, parked deletes included"); Principle 7
What: The counter is `SUM(bucket)` over rows that have an `external_ref`. An object written without a row is invisible to the ceiling and survives every restart. That happens after a crash between `put` and the row insert, or when the cleanup `delete` after a failed insert fails (it is only logged). Each counted object is also short by `95 + 16 × chunks` bytes (`bucket` instead of `blob_len(bucket)`), so the ceiling is systematically undercounted by about 0.025 %.
Reproduction: `review_orphan_objects_are_invisible_to_the_ceiling` places a 500 000-byte object with no row in `blobs/` and reopens the tier. Observed: `ceiling counts 131072 bytes; 2 objects use 631199 bytes on disk; orphan survived restart: true`.
Fix: At startup (`Local::open`), list `blobs/`, delete every name that no row references, and do the same for S3 with a ListObjectsV2 under `blobs/` (or at least add the listed bytes to the count). Count `blob_len(bucket)` in `external_bytes`.

### F-2-9: Graceful shutdown is unbounded: one stalled upload keeps the process alive after SIGTERM
Severity: Low
Location: crates/shhnote-server/src/drain.rs:27-43; crates/shhnote-server/src/main.rs:126-131
Violates: CLAUDE.md ("SIGTERM drains in-flight requests"), whose 30 s bound is not actually enforced
What: `Drain::wait_for` gives up after the grace period, but axum's `with_graceful_shutdown` then calls hyper's `graceful_shutdown()` on every connection and waits for all of them to finish, with no bound. With no body timeouts (F-2-1), a client that stops sending keeps the server alive until the supervisor sends SIGKILL. SIGKILL skips every `Drop`, so spool files are left behind (they are removed at the next start, see "Checked and clean"). A half-received blob is never committed.
Reproduction: `review_stalled_upload_blocks_graceful_shutdown` (grace 1 s, one stalled 256 KiB upload). Observed: `server stopped within 10 s: false; spool (1, 262144)`.
Fix: In `main`, race the serve future against `drain_finished + small margin` with `tokio::select!`, then return from `main`. The runtime then drops the remaining connection tasks, which runs `Spool::drop`.

### F-2-10: `SHH_SPOOL_PATH` is deleted recursively at every start
Severity: Low
Location: crates/shhnote-server/src/storage.rs:327-331
Violates: Principle 12 (secure and functional by default; a misconfiguration should not destroy data)
What: `S3::open` runs `remove_dir_all(spool_dir)` on whatever directory the operator configured. If it is pointed at a shared directory (for example the data directory that holds `shhnote.db`, or `/tmp`), everything in it is deleted on boot. The local tier does the same, but only on its own `tmp/` subdirectory.
Reproduction: `review_spool_path_is_wiped_recursively_at_startup` sets `SHH_SPOOL_PATH` to a directory containing `shhnote.db` and opens the tier. Observed: the file is gone (`a file in SHH_SPOOL_PATH was deleted at startup`).
Fix: Remove only `*.part` files at the top level of the spool directory, or spool into a dedicated `<SHH_SPOOL_PATH>/shhnote-spool/` subdirectory and wipe only that.

### F-2-11: A production config accepts an `http://` S3 endpoint silently, even though uploads are `UNSIGNED-PAYLOAD`
Severity: Low
Location: crates/shhnote-server/src/storage.rs:480-501 (`parse_endpoint`); crates/shhnote-core/src/config.rs:424-433
Violates: SPEC §6.1 ("`UNSIGNED-PAYLOAD` for uploads, which is why the endpoint should be HTTPS in production"); Principle 12
What: With `SHH_ENV=production`, `SHH_S3_ENDPOINT=http://…` is accepted with no error and no warning. Over plain HTTP, an on-path attacker sees every ciphertext with its object key and access pattern, and can swap PUT bodies, because the payload is not signed. Client-side AEAD detects tampering, but the operator's integrity and privacy assumptions do not hold.
Reproduction: `review_production_accepts_plain_http_s3_endpoint`. Observed: `production with http:// S3 endpoint accepted: true`.
Fix: In production, refuse an `http://` endpoint unless the host is loopback or a private address (for example MinIO on the same host or network), or at least `log_warn!` at startup. Alternatively sign the payload hash: the spool file is complete before the PUT, so its SHA-256 can be computed while spooling.

### F-2-12: Spool files and stored objects are created with the default mode (0644 under a 022 umask)
Severity: Low
Location: crates/shhnote-server/src/storage.rs:152-156 (spool `OpenOptions`), :244-247 (rename keeps the mode)
Violates: hardening (least privilege on the host)
What: Spool files and the local objects they are renamed into are readable by every local user. The contents are ciphertext, but object names, sizes and mtimes give other host users the same per-day size and timing view that §12 tries to minimise.
Reproduction: `review_spool_files_exceed_the_tier_ceiling` prints `mode Some("644")` for a live spool file.
Fix: Use `std::os::unix::fs::OpenOptionsExt::mode(0o600)` on unix, and create `blobs/` and `tmp/` with 0700.

### F-2-13: Padding length arithmetic overflows near `u64::MAX` (panics in debug builds, wraps in release)
Severity: Low
Location: crates/shhnote-core/src/padding.rs:61 (`len + mask`), :69 (`blob_len`), reached through `bucket_for_blob_len` at :44
Violates: hardening; SPEC §6.2 validation should fail closed
What: `padme`, `blob_len` and `bucket_for_blob_len` use unchecked `+`. For inputs within about 2^16 of `u64::MAX` they overflow: a panic in debug builds, a wrong value in release. The server never sees such lengths (the body limit bounds them), the bucket in a row comes only from the server, and on 32-bit targets `u64` is still used throughout, so this is not reachable remotely. Every length near chunk boundaries round-trips correctly (see "Checked and clean").
Reproduction: `review_extreme_lengths_do_not_panic` (core). Observed: overflow panics for `bucket_for_blob_len`, `padme` and `blob_len` at `u64::MAX`, `u64::MAX-1` and `u64::MAX-95`.
Fix: Use `checked_add`, returning `None` or `Err(InvalidBlobLength)`.

## Suspicions

- **A large expiry backlog makes the sweep hold the SQLite write lock for longer than `busy_timeout`.** `sweep` is one unbounded transaction, and with `secure_delete = ON` it overwrites every expired blob. In that window every claim, burn, confirm and create waits up to 5 s and then fails with `database is locked`, which the API turns into 500. `review_sqlite_lock_holder_makes_claims_fail_after_busy_timeout` confirms the mechanism: with an external write lock held, both an existing and a missing lookup fail after 5 s each (no existence oracle, availability only). `review_sweep_duration_with_large_inline_backlog` measured 150 × 2 MiB rows swept in 0.43 s here, so on this disk you would need roughly 1 700 or more max-size expired rows. To confirm or clear it, measure on production-class storage with the largest backlog the create rate limits allow over `min_ttl_secs`. A fix would sweep in bounded batches (`... WHERE rowid IN (SELECT ... LIMIT n)`), one transaction per batch, each with its counter increment.
- **The pool can starve `/health`.** The pool has 8 connections and sqlx's default 30 s acquire timeout, and `/health` shares it. No request holds a connection while streaming (claim commits first, and re-download reads without a transaction), so exhausting the pool seems to require the SQLite busy waits above, 8 at a time. To confirm, hold the write lock and fire 8 or more concurrent reveals plus `/health`, and measure the health latency (expected up to about 35 s, then 503). This was not run.
- **Failing open on a full rate-limit table removes the limit.** `MAX_BUCKETS = 200_000` clears the table when it is passed (ratelimit.rs:115). Anyone who controls a few IPv6 /48s can create more than 200 000 buckets, which resets every client's limit, and repeat it. Rate limits are best-effort under Principle 7, but they are also the only thing bounding concurrent uploads per client (F-2-1). To confirm, send 200 001 requests from distinct /64 addresses and check that a previously limited client is allowed again. Pass 1 or 3 may own this.

## Checked and clean

- **Claim race, SQLite.** Store level: 50 concurrent `claim` calls produce exactly 1 win, 49 `None`, 0 errors (`review_fifty_concurrent_claims_one_winner_sqlite`). API level: 50 concurrent reveals produce exactly 1 × 200 with `X-Shh-Claim-Token` and a full-length body, plus 49 byte-identical uniform 404s, on both the inline and the local tier (`review_fifty_concurrent_reveals_have_one_winner`). Journal mode is WAL, `busy_timeout = 5000`, `synchronous = NORMAL`, `secure_delete = ON` (store lib.rs:88-93). The claim `UPDATE` is the first statement of its transaction, so there is no read-then-upgrade deadlock. Postgres was not run (`SHH_TEST_PG_URL` unset). The statement is a single conditional `UPDATE ... RETURNING`, which serialises correctly under READ COMMITTED.
- **Claim window** (`review_claim_window_lifecycle`). Re-download works only with the matching claim token and only inside the window. It fails after confirm and after the window. Confirm fails after the window. The sweep destroys a lapsed claim as `viewed`, and the row never reverts to claimable. Burn and report both return false on a claimed row and leave it alone (§5.3). A window that outlives `expires_at` still allows re-download until the window ends, as §5.1 intends.
- **No database connection is held while a blob streams.** `claim` commits before `blob_response`, `redownload` and `read_ttl` run on the pool without a transaction, and the body streams afterwards.
- **External blobs are streamed, not buffered.** Local reads go through `file_stream` in 64 KiB chunks, and S3 passes `Incoming` through. If an object is shorter than its bucket, the response sends `Content-Length: 131199`, delivers 110 048 bytes and the server closes the connection, so the client sees a truncated body (and the chunk `last` flag rejects it anyway). If it is longer, exactly `Content-Length` bytes are delivered and the excess is dropped (`review_object_shorter_or_longer_than_bucket`).
- **Aborted uploads leave nothing behind.** 100 uploads were aborted mid-blob after spilling: 50 by the body ending early (a 400 response) and 50 by dropping the request future (a disconnect). 0 spool files remain (`review_aborted_uploads_leave_no_spool_files`). `Spool` and `Spooled` remove their file on `Drop`, the release profile unwinds (only `profile.wasm` aborts), and a failed S3 PUT or local rename drops `Spooled`, which removes the file. Startup clears `<local>/tmp` and the S3 spool directory, so files left by SIGKILL are cleaned on the next start. The spool name is 8 random bytes in base64url, created with `create_new`, under the right root.
- **Multipart shapes** (`review_multipart_shapes`). Blob before meta returns 400 `invalid_multipart`. Meta alone returns 400. A body cut off mid-blob returns 400 with no spool left. A third part after the blob is never read and the create succeeds with 201. That is lenient but harmless, since the body limit still applies. A missing `Content-Length` works, because axum's `DefaultBodyLimit` wraps the body in `Limited` whatever the framing. The rate-limit layer is outside the body limit, so limited requests are refused before any body is read.
- **Padding and length math** (`review_blob_len_and_bucket_agree_around_chunk_boundaries`, `review_padme_edges`). For every bucket within ±40 of each of the first 40 chunk boundaries, `bucket_for_blob_len(blob_len(b)) == b`. Every length in 0..196 996 either fails or maps back exactly. Bucket 0 is never produced (`b > 0` filter). `ceil(bucket / 65536)` agrees with `chunk_count`. Padmé outputs are fixed points with overhead at most 12 % for L ≥ 256, which covers everything above the 64 KiB floor. Note that L in 16..255 can reach 12.5 %, below any allowed `padding_min` in practice. `client/src/crypto/padding.ts` uses BigInt for Padmé, so there is no 2^31 bit-operator bug.
- **Body limit.** It is set per route on `/secrets` (`max_blob_bytes + 16 KiB`) before multipart parsing. Other JSON routes use axum's default 2 MiB limit. In inline-only mode the in-memory sink is bounded by that limit, since `memory_limit` is skipped when there is no external tier.
- **Scheduler ticks never overlap.** It is one task looping over `interval.tick()`, and missed ticks fire back to back (Burst). Each terminal transition is one transaction with its counter increment (`destroy` + `count` in the same `tx`, for sweep, confirm, burn and report). The sweep deletes by predicate and does not load rows. The scrubber deletes the object before the row and retries every pass.
- **A half-received blob is never committed during shutdown.** The row is written only after the multipart stream completes and the length is validated.
