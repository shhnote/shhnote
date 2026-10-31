# Pass 3 — Rust-specific correctness — findings

Reviewed: every `.rs` file under `crates/` (core: blob, chunks, config, container, error, fragment, kdf, lib, padding, secret, settings; store: lib, secrets, api_keys, settings, stats; server: admin, admin_api, api, app, clock, content, drain, health, i18n, lib, log, main, ratelimit, scheduler, storage, web, build.rs; argon2-wasm: lib) plus `client/src/crypto/argon2.ts` (the WASM caller), `Cargo.toml` manifests and `migrations/*/0001_secrets.sql`, 2026-10-30.

Tooling run:
- `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1`, `clippy 0.1.99`.
- `CARGO_TARGET_DIR=target/review-pass3 cargo clippy --all-targets -- -D warnings -W clippy::pedantic -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing -W clippy::arithmetic_side_effects -W clippy::cast_possible_truncation -W clippy::cast_sign_loss -W clippy::as_conversions -W clippy::unwrap_in_result`: stops at the first target, `shhnote-server`'s `build.rs` (`clippy::panic`, `manual_assert` on the missing-asset `panic!`), so it was re-run without `-D warnings` (`--message-format=short`) to collect every hit. 673 warnings across all targets (259 `unwrap` on `Result`, 69 `arithmetic_side_effects`, 57 `indexing_slicing`, 47 `as_conversions`, 24 `slicing`, 25 `unwrap` on `Option`, 12 + 5 `cast_possible_truncation`, 6 + 5 `cast_sign_loss`, 3 `cast_possible_wrap`, 6 `panic`, plus pedantic style lints). Triage is under "Clippy triage" below; hits that are findings are F-3-7 and F-3-8.
- `RUSTFLAGS="-C overflow-checks=on" CARGO_TARGET_DIR=target/review-pass3-oc cargo test`: all 107 existing tests pass (core 42 + vectors 7, server unit 25 + api 22 + others, store 2 + 9). The existing suite never drives the overflowing paths; the review tests do (F-3-8).
- `cargo geiger`: not available. `cargo install cargo-geiger --locked` failed (no OpenSSL headers for `openssl-sys`); the retry with `--features vendored-openssl` failed with a rustc SIGSEGV while compiling `crates-io` (out of memory on this machine). Fallback: `grep -rn unsafe crates/`. The only `unsafe` in the workspace is in `crates/shhnote-argon2-wasm/src/lib.rs` (lines 18, 28-30, 38-57), justified under "Checked and clean". (`tests/review_pass3_alloc.rs` adds a test-only `unsafe impl GlobalAlloc`.)
- `cargo deny 0.20.2 check advisories` (default config, fresh advisory DB): `advisories ok`.
- `cargo tree -e normal --workspace -d` and `-e features` for F-3-12. 259 crates in the normal dependency graph.
- Review tests: `CARGO_TARGET_DIR=target/review-pass3 cargo test -p shhnote-server --test review_pass3 --test review_pass3_alloc -- --nocapture`. 12 tests, all pass. They assert the current behaviour, so flip each assertion when its finding is fixed.

## Findings

### F-3-1: Every `GET /config` leaks a full clone of the settings (`Box::leak`)
Severity: High
Location: crates/shhnote-server/src/api.rs:166-168
Violates: Principle 7 (operator cost is hard-bounded), §4 (`GET /config` is never rate-limited)
What: The handler calls `Box::leak(Box::new((*state.settings.load()).clone()))` on every request so that the response can borrow from the settings. Nothing ever frees that memory. The endpoint is unauthenticated and, by design, sits outside the rate limiter, so anyone can grow the server's heap without limit just by repeating one cheap GET. The leak grows with the settings: a long `site_name`, `regions` or `padding_ladder` makes every request leak more.
Reproduction: `review_pass3_alloc.rs::review_memory_findings` (counting global allocator). With stock settings, 1000 requests leave 367 000 bytes live (367 B per request, about 1.3 GB per million requests). With a 64 KiB `site_name`, 200 requests leave 13 179 200 bytes live (65 896 B per request).
Fix: Make `ConfigResponse` own its data (`Vec<u64>`, `Vec<i64>`, `Vec<Region>`, cloned out of the snapshot), or keep the `Arc<Settings>` snapshot in a local and serialise it with `Json(...)` inside the handler. Delete the `Box::leak`.

### F-3-2: The multipart `meta` field is read into memory whole before its 4096-byte limit is checked
Severity: High
Location: crates/shhnote-server/src/api.rs:217-221 (with the body limit at api.rs:102)
Violates: Principle 7; `file-uploads` skill ("Never buffer a whole external blob in memory"); SPEC §6.1 ("while it fits the inline tier it stays in memory")
What: `meta_field.text().await` collects the entire field before `meta_text.len() > 4096` is tested. The only bound is the route's body limit, `max_blob_bytes + 16 KiB`, which is `SHH_EXTERNAL_MAX_OBJECT` (default 64 MiB) whenever an external tier is enabled. The blob field next to it is carefully spooled to disk, but sending the same bytes as `meta` gets them buffered in memory. Peak use is about 2.25× the field size, because the bytes are collected and then converted to a `String`. The rate limiter takes its token before the body is read, so one IPv4 address can run 30 of these at the same time (30 × ~144 MiB ≈ 4.3 GB), and IPv6 /64s are cheap. On a default inline-only instance the body limit is about 2 MiB, so the exposure there is small.
Reproduction: `review_pass3_alloc.rs::review_memory_findings`, local tier with a 64 MiB external cap, body streamed in 64 KiB frames: a 32 MiB `meta` field gives `400 invalid_meta` after a peak of **+72 MiB**. The same 32 MiB sent as the `blob` field peaks at **+0 MiB** (spooled).
Fix: Read `meta` with `field.chunk()` into a `Vec` capped at 4096 bytes and return `400 invalid_meta` as soon as the cap is passed. Or give the `meta` field its own small limit, for example with `multer`'s per-field size limit through a custom `Multipart` constraint.

### F-3-3: Malformed JSON on credential endpoints bypasses the uniform 404
Severity: Low
Location: crates/shhnote-server/src/api.rs:354, 440, 458, 481 (`Json<T>` extractors on reveal, confirm, burn, report)
Violates: SPEC §4 ("Every negative outcome on an endpoint that takes a secret credential returns the same 404 with the same body ... malformed input is replaced by fresh random bytes and run through the full path"); `api-endpoint` skill (uniform negatives, one shared JSON error shape)
What: Only a malformed credential string is replaced by random bytes. A body that does not deserialise (wrong type, missing field, bad JSON, no `Content-Type`) never reaches the handler. Axum's `JsonRejection` answers instead, with 400, 415 or 422 and a plain-text serde message that echoes the offending value. No per-secret fact leaks, because the rejection comes before any lookup. Still, these responses are neither the uniform negative nor the project's JSON error shape, and they skip the full-path work the spec asks for.
Reproduction: `review_pass3.rs::review_json_rejection_is_not_the_uniform_negative`: `{"lookup": 5}` on reveal gives 422 text/plain; `{"lookup":"x"}` on confirm gives 422; `not json` on burn gives 400; a reveal with no Content-Type gives 415.
Fix: Take the body as `Bytes` (or as `Result<Json<T>, JsonRejection>`), and on any parse failure substitute random credentials and run the normal path so the answer is `uniform_negative()`. For `/reports`, return the fixed `200 {"status":"received"}`.

### F-3-4: `Retry-After` reveals the rate-limit threshold
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:147-172 (`take`; the wait is computed at :171)
Violates: SPEC §4 ("a generic `429` and a `Retry-After` that reveals no threshold"); `api-endpoint` skill
What: Right after the bucket empties, the wait is `(1 − ε) / (per_hour / 3600)`, which rounds up to exactly `3600 / per_hour`. So one 429 tells a client the per-hour limit of that endpoint.
Reproduction: `review_pass3.rs::review_retry_after_reveals_the_threshold`: with `rate_burn_per_hour` = 20 / 30 / 45, the first 429 carries `Retry-After: 180 / 120 / 80`.
Fix: Send a constant (for example `Retry-After: 60`), or round the wait up to a coarse step that does not depend on `per_hour` (for example the next multiple of 300 s, capped at 3600).

### F-3-5: IPv4-mapped IPv6 peers all share one rate-limit bucket, and trusted IPv4 proxies stop matching
Severity: Medium
Location: crates/shhnote-server/src/ratelimit.rs:191-196 (`ip_prefix`), 82-100 (`client_ip` / `is_proxy`), crates/shhnote-core/src/config.rs:168-185 (`Cidr::contains`)
Violates: SPEC §4 (per-client limiting, IPv6 by /64), Principle 7
What: `ip_prefix` keys every IPv6 address by its first 8 octets. For an IPv4-mapped address (`::ffff:a.b.c.d`) those octets are all zero, so every IPv4 client gets the same HMAC key. A dual-stack listener reports IPv4 peers in exactly this form: `SHH_HOST=::` is accepted by config, and on Linux a `[::]` socket is dual-stack by default. One IPv4 client can then use up an endpoint's limit for every IPv4 user, for example 60 reveals an hour for the whole IPv4 internet. In the same setup, `Cidr::contains` never matches a mapped peer against an IPv4 range in `SHH_TRUSTED_PROXIES`, so `X-Forwarded-For` is silently ignored. The shipped deployments bind `0.0.0.0` or `127.0.0.1`, so they are not affected.
Reproduction: `review_pass3.rs::review_ipv4_mapped_peers_share_one_bucket`: with a limit of 1, `::ffff:198.51.100.1` is allowed and then the unrelated `::ffff:203.0.113.9` is refused. With `10.0.0.1` trusted, a peer of `::ffff:10.0.0.1` is not recognised as a proxy.
Fix: Normalise at the edge: `let ip = ip.to_canonical();` in `peer_of` and on every parsed `X-Forwarded-For` hop, before `is_proxy` and `ip_prefix`. Optionally canonicalise in `Cidr::contains` too.

### F-3-6: Flooding the bucket table resets everyone's limits
Severity: Low
Location: crates/shhnote-server/src/ratelimit.rs:63-65, 103-112
Violates: Principle 7 (best-effort, but it should not be trivially reset)
What: Once the table holds more than 200 000 buckets it is cleared completely ("fail open"). An attacker with one routed IPv6 /48 (65 536 /64s), or a /44 to be safe, can push it past the threshold whenever they like. That resets every client's buckets, their own included, and gives a fresh quota on every endpoint. Each flood request costs only one token per /64.
Reproduction: `review_pass3.rs::review_bucket_flood_resets_every_limit`: the victim is exhausted, 200 002 distinct /64 checks follow, and the victim's next request is allowed.
Fix: Evict per subject instead of clearing all. For example, drop buckets that have refilled to capacity (they carry no state), or evict the oldest `updated` first, before falling back to a clear. Optionally aggregate IPv6 at /56 or /48 once the table is under pressure.

### F-3-7: Admin key deletion panics on a non-ASCII id (`&str` sliced by byte offset)
Severity: Low
Location: crates/shhnote-server/src/admin_api.rs:368-376, crates/shhnote-server/src/admin.rs:717-725
Violates: CLAUDE.md (reachable panics in handlers); `api-endpoint` skill (400 on bad input)
What: Both `unhex` functions check the byte length and then index `&text[i..i + 2]`. If a multi-byte character straddles an even offset, the slice is not on a char boundary and the handler panics. There is no `CatchPanic` layer, so the connection is dropped instead of getting a 400. The release profile unwinds, so only that task dies, not the process. An admin key or the bootstrap token (plus CSRF on the panel) is needed to reach either one.
Reproduction: `review_pass3.rs::review_admin_key_delete_panics_on_non_ascii_id`: `POST /api/v1/admin/keys/delete {"id":"aé" + 61×"a"}` with the bootstrap token panics at `admin_api.rs:374:42` ("end byte index 2 is not a char boundary").
Fix: Work on bytes: `text.as_bytes().chunks(2).map(|p| std::str::from_utf8(p).ok().and_then(|s| u8::from_str_radix(s, 16).ok()))`, or reject anything that is not `is_ascii_hexdigit()` first. Keep one shared `unhex`.

### F-3-8: Settings and size variables are not range-checked, so accepted values overflow arithmetic on request and scheduler paths
Severity: Low
Location: crates/shhnote-core/src/settings.rs:150-173 (no bounds on numeric settings); overflow sites: crates/shhnote-server/src/ratelimit.rs:120 (`per_hour * user_multiplier`, u32), crates/shhnote-store/src/secrets.rs:112 (`now + window_secs`), crates/shhnote-server/src/api.rs:341 (`2 * text_max_bytes + 1024`), crates/shhnote-core/src/padding.rs:61 (`len + mask` in `padme`), crates/shhnote-server/src/scheduler.rs:27 (`retention * 86_400`), crates/shhnote-server/src/api.rs:102, 239 (`blob_len(inline_max)`, `max_blob_bytes + 16 KiB`), crates/shhnote-store/src/secrets.rs:71 (`bucket as i64`)
Violates: SPEC §8 ("validated as a whole"), §7.2; CLAUDE.md (invalid values fall back to defaults)
What: `Settings::with_overrides` only checks that a value parses, plus the TTL ordering and the `daily_retention_days` sign, and the admin panel and `PATCH /api/v1/admin/settings` rely on it. As a result `rate_user_multiplier = 4294967295`, `claim_window_secs = i64::MAX`, `text_max_bytes ≥ 2⁶³` and a huge `daily_retention_days` are all stored. In test builds (overflow checks on) these panic. Release builds have overflow checks off and wrap silently instead:
- the user-key limit becomes `per_hour × m mod 2³²`, which can be lower than the anonymous limit or effectively unlimited;
- `claim_expires_at` goes negative, so the claim lapses at once and re-download is impossible;
- `retention = i64::MAX` gives `now + 86 400` as the cut-off, so `rollup_daily` folds every daily row, today's included, into the year rows. In a debug build the same value instead kills the scheduler task for good, so pending deletes are never scrubbed.
The size variables `SHH_INLINE_MAX` and `SHH_EXTERNAL_MAX_OBJECT` have no upper bound either. They can wrap `blob_len` and the body limit, and the `bucket as i64` bind.
Reproduction: `review_pass3.rs::review_unbounded_settings_overflow_on_the_request_path`: `PATCH {"rate_user_multiplier": 4294967295, "claim_window_secs": 9223372036854775807}` → 200. A reveal with a `user` key then panics at `ratelimit.rs:120:24` ("attempt to multiply with overflow"), and an anonymous single-view reveal panics at `secrets.rs:112:15` ("attempt to add with overflow"). The scheduler arithmetic was checked by hand: (2⁶³−1)·86 400 ≡ −86 400 (mod 2⁶⁴).
Fix: Give each numeric setting a range in `with_overrides` (for example `claim_window_secs` 60..=86 400, `salt_rotation_secs` 60..=86 400, `rate_*` ≤ 1 000 000, `rate_user_multiplier` 1..=1000, `text_max_bytes` ≤ 16 MiB, `padding_min` within [4096, `SHH_INLINE_MAX`], `daily_retention_days` ≤ 36 500, TTL presets within [min, max], ladder entries > 0 and sorted). Use `saturating_mul` / `checked_add` at the sites above as a second line of defence. In `config.rs`, cap `SHH_INLINE_MAX` and `SHH_EXTERNAL_MAX_OBJECT` (for example ≤ 2⁴⁰). Consider `overflow-checks = true` in `[profile.release]`: with unwind it turns a silent wrap into a dropped request.

### F-3-9: The external-tier ceiling is not a hard limit: concurrent creates overshoot it
Severity: Medium
Location: crates/shhnote-server/src/api.rs:295-329 (check at 298-305, write at 306-317)
Violates: SPEC §6.1 ("Tier guards ... The only hard, non-circumventable limits"), Principle 7
What: `external_bytes()` is read, compared with the ceiling, and only then is the object fsynced, renamed and its row inserted. Nothing reserves the space in between, so every create in flight passes the check against the same total. The check also counts `bucket` rather than the bytes actually stored (`blob_len(bucket)` adds 95 + 16 per chunk). Spool files of uploads still in progress are not counted at all, even though they share the same disk (`<root>/tmp`).
Reproduction: `review_pass3.rs::review_concurrent_creates_overshoot_the_local_ceiling` (multi-thread runtime, local tier, `SHH_LOCAL_MAX_TOTAL_BYTES=131072`, which holds one 128 KiB bucket, and 6 concurrent creates, repeated 10 times). Observed per round: 2, 3, 1, 4, 1, 4, 4, 5, 4, 6 objects stored, up to 787 194 bytes on disk against the 131 072-byte ceiling.
Fix: Reserve before writing, then release on failure. One way is an in-process `Mutex<u64>` of reserved bytes, checked as `used_in_db + reserved + blob_len(bucket) ≤ max`, taken before `spool.finish()` and released after the row commit or the cleanup. Another, for multi-process deployments, is a conditional insert that sums inside the same transaction. Count `blob_len(bucket)`, not `bucket`. Reserve spool space as bytes arrive, or cap concurrent spools.

### F-3-10: `SHH_TRUSTED_PROXIES` accepts ranges that trust everyone
Severity: Low
Location: crates/shhnote-core/src/config.rs:207-212
Violates: SPEC §7.1 ("never `0.0.0.0`, `::` or a `/0`", in intent), Principle 12
What: The guard rejects only the literal unspecified address and a prefix of 0. `1.0.0.0/1,128.0.0.0/1` (all of IPv4), `::1/1,8000::/1` (all of IPv6) and `::ffff:0:0/96` (every IPv4-mapped peer) are all accepted. Each lets any client choose its rate-limit identity through `X-Forwarded-For`. The base address is also not checked to be the network address (`0.0.0.1/1` is accepted).
Reproduction: `review_pass3.rs::review_trusted_proxies_accept_trust_everyone_equivalents`: each of those lists gives `Config::from_vars(..).is_ok()`.
Fix: Require a minimum prefix (for example ≥ /8 for IPv4 and ≥ /32 for IPv6, as real proxy ranges are), reject `::ffff:0:0/96` and other mapped or transition ranges, and require `addr & !mask == 0`.

### F-3-11: Filesystem hardening on the local tier
Severity: Low
Location: crates/shhnote-server/src/storage.rs:147-156 (spool `OpenOptions` without a mode), 224-230 (`create_dir_all` with default mode), 244-247 (rename without a directory fsync), 116-130 (`object_name` shape)
Violates: SPEC §6.1 ("a key read back from the database is validated against that shape"); hardening
What:
- Spool files, and therefore blob files, are created with the process umask, typically `0644`, and the directories `0755`. Other local users can read every ciphertext and can see the object count and sizes.
- The spool is fsynced before the rename, but the `blobs/` directory is not fsynced after it, so a crash right after the row commit can leave a row whose object never reached disk.
- `object_name` accepts any non-empty `[A-Za-z0-9_-]+`, not the spec's exact shape: 22 base64url characters for 16 bytes.
None of these permits path traversal.
Reproduction: `review_pass3.rs::review_blob_files_use_default_permissions` prints `blob file mode 644, blobs dir mode 755`.
Fix: Use `OpenOptions::mode(0o600)` (via `std::os::unix::fs::OpenOptionsExt`) and `DirBuilder::mode(0o700)`. After the rename, `File::open(dir)?.sync_all()` before returning. Check `name.len() == 22` in `object_name`.

### F-3-12: Dependency surface: default features and a duplicated crypto stack
Severity: Low
Location: Cargo.toml:31-34 (`axum` with default features, `tokio = { features = ["full"] }`)
Violates: CLAUDE.md ("turn off default features that aren't needed"), Principle 11
What: `tokio` "full" brings in `process`, `io-std`, `parking_lot` and `signal-hook-registry` alongside what is needed (`rt-multi-thread`, `macros`, `net`, `fs`, `time`, `sync`, `signal`, `io-util`). `axum`'s defaults bring in `tracing`, `tower-log`, `matched-path` and `original-uri`, none of which are used (no subscriber is installed). `sqlx 0.9` pulls a second crypto and encoding stack next to the workspace's own: `sha2 0.10`/`digest 0.10`/`block-buffer 0.10`/`crypto-common 0.1`/`cpufeatures 0.2`, `base64 0.22`, and `getrandom 0.2` via `ring`. `cargo deny check advisories` is clean.
Reproduction: `cargo tree -e normal --workspace -d`; `cargo tree -e features -p shhnote-server -i tokio`; `... -i axum`.
Fix: Set `axum = { default-features = false, features = ["http1", "json", "form", "query", "multipart", "tokio"] }` and list tokio's features explicitly. Accept the sqlx duplicates until upstream moves to the RustCrypto 0.11 line, and record that in the dependency notes.

### F-3-13: Startup prints configuration values with `println!`, outside the log macros
Severity: Low
Location: crates/shhnote-server/src/main.rs:123-124 (also 27-29, 51, 56, 67 for the subcommands)
Violates: CLAUDE.md ("Diagnostics in the server go through `crate::log_error!`, `log_warn!` and `log_info!` (honouring `SHH_LOG_LEVEL`), never `eprintln!`"); review checklist item 9 ("no configuration value is printed on startup")
What: `serve` always prints `listening on http://<bind>` and `site at <SHH_URL>, API at <api_url>/v1` to stdout, whatever `SHH_LOG_LEVEL` says. Neither value is a credential, but both are configuration values, and they bypass the logging policy. The subcommand output (`ok`, `unhealthy: …`) is CLI output and is fine.
Reproduction: `grep -n 'println' crates/shhnote-server/src/main.rs` → lines 123-124 on the serve path.
Fix: Use `log_info!("listening on {}", …)` and drop the URL line, or put it behind `log_info!` too.

### F-3-14: The bootstrap-token hash is compared with `==` in the admin API
Severity: Low
Location: crates/shhnote-server/src/admin_api.rs:52-55
Violates: Review checklist item 3; internal consistency with admin.rs:59-68 (`constant_time_eq` for the same check)
What: `require_admin` compares `SHA-256(presented)` with `SHA-256(SHH_ADMIN_TOKEN)` using a short-circuiting `==`. The panel's login does the same comparison in constant time. The leak is the length of the matching prefix of a hash the attacker cannot steer without SHA-256 preimages, so it is not exploitable in practice. It is still the only `==` on credential-derived material on a request path.
Reproduction: `sed -n 52,55p crates/shhnote-server/src/admin_api.rs`.
Fix: Reuse `admin::constant_time_eq` (make it `pub(crate)`), or better, compare in one shared `fn bootstrap_matches(state, hash) -> bool`.

## Suspicions

- **S3 error bodies, including the object key, reach the error log.** `status_error` (storage.rs:520-525) copies up to 200 characters of the S3 error XML into the `io::Error`. That error is logged by `ApiError::internal` on reveal (api.rs:416 → 559, "store error: …") and by the scrubber (scheduler.rs:62). A standard `NoSuchKey` body is about 160 characters up to and including `<Key>blobs/…</Key>`, so a log line would carry a per-secret identifier with the time of a failed reveal (Principle 4, CLAUDE.md "nothing request- or user-specific is ever logged"). To confirm: point `SHH_TEST_S3_*` at MinIO, delete an object behind a live row, reveal it, and read stderr. To clear: log only the status code.
- **No timeouts on the S3 client.** `S3::send` (storage.rs:399-477) awaits TCP connect, the TLS handshake and the response headers without any deadline, and `scheduler::spawn` awaits `scrub` inline before the next `sweep`. A black-holed endpoint would stall the scheduler (claim lapses and expiries are no longer destroyed, though the query predicates still hide them) and pin request tasks during `put` and `get`. To confirm: set `SHH_S3_ENDPOINT` to a host that accepts TCP and never answers.
- **A settings snapshot is held across the whole upload.** `create` loads `settings` at api.rs:229 and validates the finished blob against it at 261-272, possibly minutes later. An admin save in between (for example `files_enabled=false`) does not apply to uploads already in flight. This is low impact, and it is against the spirit of "never hold one across a save". To clear: re-`load()` after the body is received.
- **The salt falls back to all zeros if the RNG fails** (ratelimit.rs:176-182). This fails open silently. With a zero salt the bucket keys are `HMAC(0, ip)`, which anyone can compute from an IP, and they would show up in a core dump. getrandom failure on Linux is practically impossible after boot, so this is unverified; a `log_error!` on that path would make it visible.
- **The reports ledger key is the same value as `secrets.lookup_key`** (secrets.rs:204-227, `reports.lookup_key = SHA-256(lookup)` with first and last timestamps). That makes the "never joined to secrets" tables joinable on equality. This belongs to the data-model pass; flagged here only because it showed up while reading the store.

## Checked and clean

- **95-byte header** (`blob.rs:36-54`): the length is checked before every fixed-offset slice, so the `try_into().unwrap()` calls cannot fail. Argon2 bounds are checked before any KDF in core (`check_bounds` in `parse`, `encrypt` and `argon2id`), in WASM (`shh_argon2id` before `Params::new`) and in TS (`checkArgon2Bounds` before the WASM call). `padding::unpad`, `Payload::decode` and `ChunkCipher::open_all` use `get` and `split_at_checked`; client-side only, no server path.
- **Credential decoding** (`api.rs:517-535`, `fragment.rs:32-49`): exactly 43 (or 44) characters, `URL_SAFE_NO_PAD` with the base64 0.23 defaults, so padding, whitespace, `+`/`/` and non-zero trailing bits are all rejected. A non-canonical spelling of a real burn token does not burn it (`review_credential_decoding_is_strict`). Malformed credentials are replaced with `getrandom` bytes and run the full path (except body-level rejections, F-3-3).
- **No `==` on secret material** on secret paths: lookup, claim and burn are SQL lookups by `SHA-256` (full 32 bytes, PK / UNIQUE / predicate); API keys likewise. Session MAC and CSRF use `constant_time_eq`. The one exception is F-3-14. API keys are hashed over their base64 text, both when minted (`admin.rs:701-703`) and when presented (`ratelimit.rs:280-288`, `admin_api.rs:43`), which is consistent.
- **Randomness**: claim token (api.rs:368-369), object keys (storage.rs:75-79, 16 bytes), spool names (8 bytes), rate-limit salt, session nonce and API keys all come straight from `getrandom::fill` (OS CSPRNG) per use. No seeded, cloned or thread-local PRNG anywhere in the workspace.
- **Hashing and HMAC**: `credential_hash` = SHA-256, never truncated before it becomes a key. Rate-limit subject = `HMAC-SHA256(32-byte salt, IPv4 octets | IPv6 /64)`, full 32-byte output. SigV4 matches the AWS worked example (existing unit test). Only display values are truncated (asset hash 6 bytes, report id 8 bytes).
- **Rate limiter concurrency**: the std `Mutex` is never held across an `.await` (`check`, `check_key` and `take` are synchronous), and a poisoned lock is recovered. The salt is read, rotated and used under the same lock as the bucket update, so no request can be keyed with a salt from before a rotation and counted after it. Rotation clears API-key buckets too. `salt_rotation_secs.max(60) as u64` cannot lose its sign.
- **No sqlx connection or transaction held across a streamed response**: `claim` commits and returns the inline bytes or the object key before `blob_response` opens the file or the S3 stream. `redownload` and `read_ttl` use the pool directly.
- **Error handling**: `ApiError` carries only `&'static str` codes. There are no `From` impls; every `?` goes through an explicit `map_err`; 500 bodies are the generic `{"error":{"code":"internal",…}}`, with the details only in `log_error!`. sqlx errors are logged without bound values. Local io errors carry no paths.
- **Store integers**: `bucket`, `expires_at` and `claim_expires_at` are i64 on both engines (BIGINT / INTEGER). `bucket as u64` and `as i64` are lossless within the config bounds, except for the absurd values in F-3-8. `count` uses `rem_euclid`. Every SQL statement is parameterised. `destroy()` predicates are file-local literals (`AssertSqlSafe` justified).
- **Filesystem**: `object_name` allows only `[A-Za-z0-9_-]` after `blobs/` before any `join` or S3 path, so a key from the database cannot traverse. The spool lives under `<root>/tmp`, the same filesystem, so `rename` is atomic. The spool is `sync_all`ed before the rename. `Spool` and `Spooled` remove their file on drop, which covers every early return in `create`. A failed row insert deletes the object.
- **Configuration** (`review_config_rules_hold`): unknown `SHH_*` variables fail; variables for a disabled tier (local vars under inline or S3, S3 vars under local, `SHH_EXTERNAL_MAX_OBJECT` without a tier) fail; `SHH_DEBUG=true` with production fails; secrets shorter than 32 characters fail; `Secret` redacts in `Debug`; `.env` parse errors drop the offending line's text. `0.0.0.0`, `::`, `/0` and `0.0.0.0/8` are refused (but see F-3-10).
- **WASM crate** (the only `unsafe`): `shh_alloc` hands out a leaked `Vec` with capacity `len.max(1)`, and `shh_free` rebuilds it with the same capacity and length 0 (sound for `u8` with the default allocator). An oversized `len` panics (`capacity overflow`), which is `abort` under `profile.wasm`, so the module traps and memory stays safe. `shh_argon2id` checks m ∈ [8 MiB, 256 MiB], t ∈ [1, 8] and p ∈ [1, 4] before `Params::new` and before any Argon2 allocation, so a hostile blob cannot make it allocate past 256 MiB. The output length is fixed at 32. `pwd`, `salt` and `out` come from `shh_alloc` in `argon2.ts:46-63` with matching lengths, and the TS side zeroes the password and output before freeing. Raw pointer validity is the documented caller contract; with no MMU inside wasm, out-of-range pointers can only touch the module's own linear memory.
- **Overflow-checked test run**: the whole existing suite passes with `-C overflow-checks=on`. `clock::civil`, `stats::year_start` and the `days_from_civil` arithmetic are safe for every timestamp between 1970 and year 292 billion.
- **Release panic strategy**: `profile.release` unwinds (`panic = "abort"` is set only in `profile.wasm`), so a handler panic (F-3-7, F-3-8) drops one connection, not the process. Panics in the scheduler task are not caught and would stop it permanently (see F-3-8).

### Clippy triage (non-test code)

- `unwrap`/`expect` that cannot fail: `Hmac::new_from_slice` (any key length: admin.rs:54, ratelimit.rs:185, storage.rs:603), `Aes256Gcm::new_from_slice` on `[u8; 32]` (chunks.rs:23, secret.rs:88/101), AES-GCM `encrypt` in memory, the HKDF 32-byte expand (kdf.rs:55), `HeaderValue::from_str` on base64url and digits (api.rs:538) and on ASCII cookies (admin.rs:127), the CSP literal (web.rs:544), `write!` to a `String` (store lib.rs:175), and the `try_into().unwrap()` on length-checked slices in blob.rs:40-52.
- Startup only: app.rs:25 (`HeaderValue::from_str(SHH_URL)`; panics at startup under subdomain routing if `SHH_URL` holds non-ASCII, e.g. an IDN; validate it in config.rs), web.rs:60, i18n.rs:27-35, main.rs:120-126, storage.rs:309 (rustls default versions), build.rs.
- Indexing and slicing that is guarded: admin.rs:93-96 (after `len == 57`), i18n.rs:92 (`locales` non-empty), storage.rs:568 (`min(8)`), health.rs `split_url` (index from `find`), admin.rs:540 / admin_api.rs:280 (`lookup_key[..8]` on a BLOB the code always writes as 32 bytes; a hand-edited short row would panic the reports page, which is acceptable).
- Findings: admin.rs:723 and admin_api.rs:374 (F-3-7); ratelimit.rs:120, secrets.rs:112, api.rs:341, padding.rs:61, scheduler.rs:27 (F-3-8).
- Casts that are fine: `u64 as usize` (64-bit targets only; the server does not build for 32-bit), `f64 as u64` saturating (ratelimit.rs:171), `usize as u32` in core `pad`/`encode` (guarded by `payload.len() > u32::MAX` and the 1 MiB manifest cap), and `as_secs() as i64`.
