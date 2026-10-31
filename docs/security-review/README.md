# shhnote security review — prompts

This file drives a multi-pass security review of the repository. Each pass is
self-contained and written to be handed to a subagent. The orchestrator prompt
at the top is what a human pastes into Claude Code.

Ground rules for every pass:

- `SPEC.md` is the authority. A finding is a place where the code, a header, a
  log line, a database column or a response differs from what `SPEC.md` says,
  or where `SPEC.md` is silent and the behaviour violates a principle in §12.
- Every finding needs evidence: `path:line`, a reproduction (a failing test, a
  concrete request, or a command) and the principle or decision it violates.
  A finding that cannot be reproduced goes in the "Suspicions" section, not in
  "Findings".
- Do not propose fixes that violate §12 or §13. If the only fix would, say so
  and mark it for a spec revision.
- Write to `docs/security-review/findings/<pass>.md` using the output format
  below. Never edit application code or commit. Writing tests under
  `crates/*/tests/` or `client/test/` to reproduce a finding is allowed and
  encouraged; name them `review_*` so they are easy to find and remove.
- Read `CLAUDE.md` and the project skills in `.claude/skills/` first; they
  state conventions whose violation is itself a finding.

## Output format (every pass)

```
# <Pass name> — findings

Reviewed: <files or areas>, <date>
Tooling run: <commands and versions>

## Findings
### F-<pass>-<n>: <one line>
Severity: Critical | High | Medium | Low
Location: path:line (one or more)
Violates: SPEC §x / D-n / Principle n / CLAUDE.md rule
What: two to four sentences.
Reproduction: test name, request, or command, and the observed result.
Fix: concrete change; note if it needs a spec revision.

## Suspicions
Things that look wrong but could not be reproduced, each with what would
confirm or clear it.

## Checked and clean
Properties that were specifically tested and hold, so the next reviewer does
not redo them.
```

Severity: Critical = plaintext, key or seed exposure, or any party learning a
per-secret fact the spec says is hidden. High = remotely triggerable crash,
OOM or unbounded resource use; auth bypass; a consumed secret served to a
non-claimant. Medium = a leak that needs operator or dump access; a race with
a narrow window; a dependency issue. Low = hardening.

---

## Orchestrator prompt

Paste this into Claude Code at the repo root.

```
Run the security review described in docs/security-review/README.md.

Read that file, CLAUDE.md, SPEC.md and the five skills under .claude/skills/
first. Then run passes 1 to 6 as separate subagents, each with the full text
of its pass prompt plus the "Ground rules" and "Output format" sections. Passes
1, 2 and 3 use the most capable model available; passes 4 and 5 may use the
same; pass 6 may use a faster model. Run passes that touch different crates in
parallel. Each subagent writes docs/security-review/findings/<pass>.md and
nothing else outside crates/*/tests/ and client/test/.

When passes 1 and 2 have written their files, run pass 7 (adversarial) as a
fresh subagent that is given SPEC.md, the pass 7 prompt and NOTHING from the
other findings files. It must try to break the listed properties with tests.

Finally run pass 8 (synthesis) yourself: read every findings file, dedupe,
reconcile severities, check each proposed fix against SPEC §12 and §13, and
write docs/security-review/findings/SUMMARY.md with a ranked list, the
accepted residuals that were rediscovered (point at the SPEC section that
already records them), and the items that need a spec revision rather than
a code change.

Do not fix anything. Do not commit. Report when SUMMARY.md exists.
```

---

## Pass 1 — Metadata and PII leakage (ethos audit)

```
You are reviewing the shhnote server for anything that lets an operator, a
database dump, a backup, a reverse proxy, or a network observer learn a fact
about an individual secret or an individual user. SPEC.md §12 principles 3, 4,
5 and 6, §3 (stored data), §4 (uniform negatives), and §13 define what must be
hidden. The threat actors are the operator, a database-dump holder, a
traffic analyst and an email link scanner.

Read, in full: crates/shhnote-server/src/{api.rs,web.rs,admin.rs,admin_api.rs,
ratelimit.rs,log.rs,health.rs,scheduler.rs,storage.rs,i18n.rs,content.rs},
crates/shhnote-store/src/, every file in migrations/, every template in
crates/shhnote-server/templates/, and crates/shhnote-server/content/en/*.md.

Check each of the following and record the result under Findings or under
Checked and clean:

1. Logging. Every log_error!/log_warn!/log_info! call site and every place an
   error is formatted into a string: can a lookup hash, burn hash, claim token,
   object key, IP, header value, request path or body fragment reach a log at
   any SHH_LOG_LEVEL, including through a dependency's Display/Debug impl
   (sqlx errors, hyper errors, S3 response bodies, multipart errors)? Check
   panic messages too; a panic in a handler prints to stderr.
2. Response uniformity. For every endpoint that takes a secret credential:
   same status, same body bytes, same headers (including Content-Length,
   Cache-Control, Retry-After absence) for never-existed, expired, consumed,
   burned, reported, claimed-by-someone-else, and malformed. Confirm malformed
   input is replaced by random bytes and run through the same database path,
   as SPEC §4 says. Look for early returns that skip the database.
3. Timing. Does any negative path do measurably less work than the positive
   path (missing row vs present row, inline vs external blob, claimed vs
   active)? Write a test that times 200 requests of each kind against SQLite
   and report the distribution. Note that a unique-index lookup on a hash is
   the design; the question is whether anything else differs.
4. Database. Every column in every migration: is there anything beyond what
   SPEC §3 lists? Any default created_at/updated_at columns, any autoincrement
   id that orders secrets by creation, any index whose key order leaks
   insertion order, any trigger. Check that stats_daily, reports, settings and
   api_keys are never joined to secrets and that no query touches secrets and
   another table in one statement. Check what the reports ledger stores.
5. SQLite specifics. WAL and journal files, freelist pages and the rowid of
   deleted rows can retain data; check whether secure_delete is set and
   whether VACUUM is ever run. Check whether the implicit rowid orders rows
   by creation and whether any query exposes it.
6. Rate limiting. Confirm the bucket key is HMAC(salt, ip), that the salt
   rotation clears every bucket, that IPv6 is bucketed by /64, that the salt
   never persists to disk, that Retry-After is quantised, and that
   X-Forwarded-For is only honoured from SHH_TRUSTED_PROXIES. Check the
   user-key path: can a user key be correlated with a secret anywhere,
   including last_used_at timing against stats_daily?
7. Headers and redirects. Does the locale redirect (/s -> /en/s) preserve the
   fragment and add nothing to the path or query? Does any redirect or error
   page echo input? Is Referrer-Policy: no-referrer on every response
   including static assets, 404s and 5xxs? Does the static asset ?v=<hash>
   query reveal the build in a way that matters?
8. /config and /health. Anything per-secret or per-instance that should not be
   public (active count, storage usage, key count)?
9. Admin surfaces. Can the stats, reports or settings pages or the admin API
   reveal anything about an individual secret, including through the reports
   ledger's timestamps correlated with stats_daily?
10. Stats. Confirm counters are per UTC day only, that folding into yearly rows
    works, and that a counter increment never happens outside the same
    transaction as the row change (a crash between them would skew counts, and
    a count that lags could reveal an in-flight transition).
11. Error bodies. Every JSON error body: is the message generic? Does any
    validation error reveal which field or which byte was wrong in a way that
    helps an attacker enumerate (e.g. invalid_blob_length telling the caller
    the valid ladder)? Decide whether each is acceptable under §4.
12. Templates and content. Any analytics snippet, external URL, or form field
    that collects reporter or user data. Confirm the report page collects only
    the link.

Also list every place where the code stores or transmits something the SPEC
does not mention, even if it looks harmless.
```

---

## Pass 2 — Resource exhaustion, races and lifecycle

```
You are reviewing shhnote for remotely triggerable memory or disk exhaustion,
hangs, and race conditions in the secret lifecycle. SPEC.md §4, §5, §6.1 and
D-1 define the intended behaviour. Principle 7 says operator cost is
hard-bounded; a way around a ceiling is a High finding.

Read, in full: crates/shhnote-server/src/{api.rs,storage.rs,scheduler.rs,
drain.rs,app.rs,main.rs}, crates/shhnote-store/src/, and the axum/hyper body
limit configuration wherever it lives.

Check and record:

1. Upload path. Trace POST /secrets byte by byte. Is a global request body
   limit set before multipart parsing? Is the meta part size-limited on its
   own? Is meta fully validated (including that the declared blob length is a
   valid padded size) before any blob byte is buffered? What is the maximum
   memory one request can hold, and can N concurrent requests multiply it
   past the inline ceiling? What happens if the client declares one length and
   sends another, or omits Content-Length, or sends the parts in the wrong
   order, or sends a third part? Write a test for each.
2. Spool. When bytes cross SHH_INLINE_MAX they go to a spool file. Is the
   spool created under the right root, with a random name, with restrictive
   permissions, and removed on every error path including client disconnect
   mid-upload, a panic, and process shutdown during drain? Count spool files
   after a test that aborts 100 uploads. Can spool files exceed the tier
   ceiling, since the ceiling counts stored objects?
3. Ceilings. SHH_LOCAL_MAX_TOTAL_BYTES and SHH_S3_MAX_TOTAL_BYTES: how is the
   current total computed (walk, cached counter, HEAD requests)? Is the
   check-and-write atomic under concurrent creates, or can N requests each
   pass the check and together exceed the ceiling? Does the counter drift
   after a crash between object write and row write, or after a failed
   delete? Does pending_delete count toward the ceiling as the SPEC says?
4. Slow clients. A client that sends one byte per second on upload, or reads
   one byte per second on download of a 64 MiB blob: what timeouts apply,
   and how many such clients exhaust the connection pool or file descriptors?
   Check hyper/axum timeouts, the database pool size and acquire timeout, and
   whether a streaming download holds a database connection open.
5. Claim race. The conditional UPDATE in reveal: run 50 concurrent reveals of
   one single-view secret against SQLite and Postgres (if SHH_TEST_PG_URL is
   set) and assert exactly one receives the blob and a claim token. Check the
   SQLite journal mode and busy timeout; a busy error on the losing side must
   still produce the uniform 404.
6. Claim window. Can a claimant re-download after confirm? After the window?
   Can the scheduler destroy a claimed row while a re-download is streaming
   its blob, and what does the client receive? Can a burn or report succeed
   against a claimed row (SPEC §5.3 says no)?
7. Scheduler. It runs every 60 s. What if a tick takes longer than 60 s (large
   pending_delete backlog with a slow S3)? Do ticks overlap? Is the expiry
   query bounded, or does it load every expired row into memory? Is each
   terminal transition one transaction with its counter increment?
8. External tier serving. Content-Length is set from bucket; what happens if
   the object is shorter or longer than bucket (corruption, partial write)?
   Does the server stream or buffer? Can a missing object (row exists, object
   gone) leak a different error than the uniform 404?
9. S3 client. Retries, timeouts, and what happens on a 5xx mid-stream. Is the
   spool deleted if the S3 put fails? Is UNSIGNED-PAYLOAD acceptable given the
   endpoint check, and does the server refuse http:// endpoints in production?
10. Shutdown. drain.rs: in-flight uploads during SIGTERM; is a half-received
    blob ever committed? Are spool files cleaned at next startup?
11. Padding and length math. For every arithmetic expression in padding,
    blob length validation and chunk counting (server and core): can a
    hostile bucket or payload_len value overflow u32 or usize on 32-bit, or
    produce a bucket of 0, or make ceil(bucket / 65536) wrong? Fuzz
    is_valid_padded_size and blob_len with proptest or a loop over edge values.
12. Database pool. Pool size, acquire timeout, and behaviour when the pool is
    exhausted: does /health still answer? Does a stuck transaction in the
    scheduler starve requests?
```

---

## Pass 3 — Rust-specific correctness

```
You are reviewing the Rust workspace for panics reachable from a request,
unsound or risky code, and misuse of the libraries. Read every .rs file under
crates/. Run the tooling below and include its output in the findings file.

Tooling (run from the repo root, record versions):
- cargo clippy --all-targets -- -D warnings -W clippy::pedantic
  -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic
  -W clippy::indexing_slicing -W clippy::arithmetic_side_effects
  -W clippy::cast_possible_truncation -W clippy::cast_sign_loss
  -W clippy::as_conversions -W clippy::unwrap_in_result
  Triage every hit: in a request handler or anything it calls, it is a
  finding; in tests or startup code, note and move on.
- cargo geiger (install if missing) on the workspace; list every unsafe block
  with a justification or a finding.
- cargo test with RUSTFLAGS="-C overflow-checks=on" to catch arithmetic that
  wraps silently in release.

Check and record:

1. Panics. Every unwrap/expect/index/slice/divide in code reachable from a
   handler, the scheduler or the storage layer. For each, construct the input
   that triggers it or show why it cannot be reached.
2. Integer conversions. Every `as` cast and every u32/u64/usize/i64 boundary,
   especially blob lengths, bucket sizes, ttl_seconds, expires_at, claim
   window, stats counters, Content-Length, and anything read from the
   database or a header. SQLite stores i64; check the u32/i64 round trips.
3. Byte handling. Header parsing in core (95-byte header), base64url decoding
   of credentials (exact 32-byte checks, no padding accepted, no whitespace),
   constant-time concerns (the design is lookup-by-hash so comparisons should
   not exist; find any == on secret material).
4. Filesystem. The object key shape check before any path join; path
   traversal via a key read from the database; symlink following under the
   local root; file permissions on created blobs and spool files; atomic
   rename on the same filesystem; fsync before the row write.
5. Concurrency. Anything held across an .await that should not be (a
   SettingsCell snapshot, a std Mutex guard, a sqlx connection during a
   stream); Arc/RwLock usage in ratelimit.rs under rotation; the salt rotation
   itself (is a request mid-flight keyed with the old salt after rotation?).
6. Error handling. Error types that carry request data; From impls that
   convert a storage or database error into a response without going through
   the uniform-404 path; `?` in handlers that returns a 500 with a body.
7. Randomness. Where random bytes come from (claim token, object keys, salt),
   that it is a CSPRNG, and that the RNG is not seeded or cloned per request.
8. Hashing and HMAC. SHA-256 of credentials and HMAC for rate limiting: right
   algorithm, right key handling, no truncation of the hash before it becomes
   a primary key.
9. Configuration. config.rs: every parse, every default, that unknown SHH_*
   vars fail, that disabled-tier vars fail, that SHH_TRUSTED_PROXIES rejects
   0.0.0.0, ::, and /0, that SHH_DEBUG is refused in production, and that no
   configuration value is printed on startup.
10. Dependencies. cargo tree for anything with default features that pull
    in more than needed; anything duplicated at two versions; anything
    unmaintained.
11. The wasm crate. The C-ABI exports in crates/shhnote-argon2-wasm: pointer
    and length validation, allocation ownership, what happens when the caller
    passes a bad length or out-of-bounds parameters, and whether a hostile
    blob can make Argon2 allocate past the client-enforced bounds before the
    bounds are checked.
```

---

## Pass 4 — Web layer, admin and authentication

```
You are reviewing the website and admin panel of shhnote for authentication,
session, CSRF, header and injection issues. SPEC.md §8, §10 (CSP), §11 define
the intended behaviour. Read crates/shhnote-server/src/{web.rs,admin.rs,
admin_api.rs,app.rs,i18n.rs,content.rs}, every template, locales/, and the
Markdown renderer configuration.

Check and record:

1. Headers. Fetch every route (each locale, each page, each static asset, each
   API endpoint, a 404, a 405, a 500 if you can force one, the locale redirect)
   and record CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy, Cache-Control. Any route missing one is
   a finding. Confirm no inline script or style anywhere, including in
   Markdown-rendered pages and error pages.
2. Session cookie. HMAC construction, what is signed (key hash, expiry,
   anything else), expiry enforcement, Secure/HttpOnly/SameSite, whether the
   cookie is re-validated against api_keys on every admin request, and what
   happens when SHH_SECRET_KEY rotates. Try: a cookie with a tampered expiry,
   a cookie for a deleted key, a bootstrap-token session after the first
   admin key is created.
3. CSRF. How the token is derived from the session, whether it is checked on
   every state-changing admin route (settings save, key create, key delete,
   logout), whether it is checked on the admin JSON API or whether Bearer auth
   is the only guard there, and whether SameSite=Strict is relied on.
4. Login. Rate limit on failed attempts, constant-time or lookup-by-hash
   comparison of the key, bootstrap token handling, lockout recovery via
   reset-admin, and whether a failed login reveals whether a key exists.
5. Admin API. Bearer parsing (whitespace, case, empty), an admin key used on
   a user route and vice versa, a user key on an admin route, the settings
   PATCH validation (can a setting be set to a value that breaks the instance:
   padding_min of 0, TTL max above 14 days, rate limits of 0, a regions URL
   with javascript: scheme, a site name with markup), and that validation is
   whole-settings not per-field.
6. Injection. Askama auto-escaping on every variable, especially settings
   values rendered into templates (site name, contact email, regions names
   and URLs), file names from manifests (client side, but check the
   templates' expectations), and the Markdown renderer (raw HTML allowed?
   link schemes filtered?).
7. Locale handling. Accept-Language parsing with hostile input (very long,
   invalid, duplicate), path locale validation against SHH_LOCALES, open
   redirect through the locale redirect, fragment preservation.
8. Static assets. The ?v=<hash> handling, path traversal in the static route,
   content types (wasm must be application/wasm for streaming compile), and
   caching headers that do not conflict with no-store on secret responses.
9. The interstitial. templates/secret.html and the reveal script: confirm no
   fetch happens on load, the isTrusted check cannot be bypassed by a
   synthetic click or keyboard event on a focused button, and nothing in the
   page reads the fragment before the gesture in a way that sends it anywhere.
10. Report and burn pages. Same no-fetch-before-gesture property; confirm
    the client derives lookup from the fragment and the server never receives
    the fragment.
```

---

## Pass 5 — Client cryptography and protocol conformance

```
You are reviewing the TypeScript client and the Rust core for protocol
correctness against SPEC.md §2 and the conformance vectors. Read client/src/
in full, crates/shhnote-core/src/ in full, vectors/README.md and
vectors/generate.py. Run scripts/build-wasm.sh, then `npm test` and
`npm run typecheck` in client/, and `cargo test -p shhnote-core`.

Check and record:

1. Vectors. Both suites pass. Then check what the vectors do NOT cover: list
   the reject cases and find protocol paths with no negative vector (wrong
   version byte, truncated header, chunk out of order, last flag on a middle
   chunk, missing last chunk, payload_len > bucket-4, manifest_len > 1 MiB,
   manifest size field not matching bytes, duplicate or empty file names,
   zero files and null text). Write a review test for each gap.
2. Fragment. Decoding accepts exactly 44 base64url chars with no padding;
   rejects standard base64, whitespace, longer or shorter input; the version
   byte is checked before anything else; parseFragment on a full URL does not
   pick up a fragment from the path or query by mistake.
3. Key material. The seed is the only raw key material in JS; KEK via
   deriveKey non-extractable; EK via wrapKey/unwrapKey with the extractable
   flags SPEC §10 describes and exportKey never called. Grep for exportKey,
   for any Uint8Array copy of key material, and for key material reaching
   console, localStorage, sessionStorage, history or the DOM.
4. Argon2. Parameter bounds checked before the WASM call; the WASM module is
   fetched same-origin with a stable path; what happens when the module fails
   to load (does the client fall back to anything weaker? it must not); memory
   growth on 256 MiB m; behaviour on a 32-bit or low-memory device.
5. Mode detection. Trial-unwrap with KEK_direct then passphrase prompt: can a
   crafted blob make the client prompt for a passphrase on a direct secret or
   vice versa in a way that leaks anything, or loop forever?
6. Chunk decryption. In-order enforcement, the last flag, truncation handling
   when the stream ends early, memory bound while streaming (is the whole blob
   buffered anyway?), and that decryption failure of chunk i does not leave
   chunks 0..i-1 in the DOM.
7. Container parsing. manifest_len bounds, UTF-8 decoding errors, file size
   sum vs remaining bytes, offsets, name sanitisation before use as a download
   filename (path separators, control characters, very long names, RTL
   override characters), type field used for anything security-relevant.
8. API client. The api base is passed by the caller; confirm nothing derived
   from the seed is ever sent anywhere except that base, that the burn token
   hash (not the token) is sent at create, and that revealSecret with
   confirm:false behaves as documented.
9. Memory scrubbing. SPEC §10 calls it best effort; confirm the code does
   what the threat model page claims and nothing more is promised.
10. Rust core parity. Any place the Rust and TS implementations could accept
    different inputs (lenient parsing on one side), since the vectors only
    prove they agree on the vectors.
11. CSP interaction. wasm-unsafe-eval is required; confirm no 'unsafe-inline'
    or 'unsafe-eval' crept in and that the WASM instantiation path works under
    the shipped CSP in Firefox, Chromium and Tor Browser (at least by reading
    the instantiation code).
```

---

## Pass 6 — Supply chain, build and deployment

```
You are reviewing the dependency tree, build scripts and deployment artifacts
of shhnote. Run and record: cargo audit, cargo deny check (write a deny.toml
if none exists and note that), cargo tree --duplicates, cargo tree -e features
for the server crate, npm audit in client/, and docker build of the root
Dockerfile if Docker is available.

Check and record:

1. Advisories and unmaintained crates from cargo audit.
2. Licences in the tree compatible with AGPL-3.0 distribution.
3. Default features: for each dependency, which default features are enabled
   and whether they are needed (e.g. TLS stacks, compression in hyper/axum,
   sqlx runtime features). Principle 11 says minimal; each unnecessary
   feature is a Low finding.
4. Build scripts. scripts/build-client.sh and build-wasm.sh: pinned toolchain
   versions, reproducibility, whether build.rs could be tricked into
   embedding a wrong file, and whether `include_bytes!` targets are verified.
5. Dockerfile. Base image pinning (digest, not tag), non-root user, read-only
   filesystem compatibility, what is in the final image, exposed ports,
   health check command, and whether build secrets could land in a layer.
6. deploy/. Caddyfile header behaviour vs the server's own headers (duplicate
   or conflicting), docker-compose volume permissions, the systemd unit's
   hardening options (ProtectSystem, PrivateTmp, NoNewPrivileges,
   RestrictAddressFamilies, etc.), Fly config secrets handling, and that
   .env.example never carries a real-looking secret.
7. CI. .github/workflows: pinned action versions, token permissions, whether
   release artifacts are built reproducibly and checksummed, whether tests
   run with the same features as release.
8. Documentation drift. docs/deploy/*.md vs config.rs: any variable
   documented but unknown to the code, or known to the code but undocumented.
```

---

## Pass 7 — Adversarial (fresh eyes)

```
You are an attacker who has read SPEC.md and nothing else about this review.
Your job is to break the properties below by writing tests in
crates/shhnote-server/tests/review_adversarial.rs (and client/test/ where a
browser-side property is involved). For each property, either produce a
failing test with the attack, or explain in two sentences what you tried and
why it holds. Do not read docs/security-review/findings/.

Properties to attack:

A. Two concurrent reveals of one single-view secret both receive the blob.
B. Someone without the claim token re-downloads a claimed secret.
C. A reporter learns whether a secret existed, from status, body, headers or
   timing.
D. A burn with a wrong token learns anything.
E. A database dump (read the SQLite file after creating secrets) lets you
   reveal, burn, report or claim any secret.
F. Two blobs of the same bucket are distinguishable at rest or on the wire
   (direct vs passphrase, text vs file).
G. The server can tell that a secret has a passphrase.
H. A create request exceeds the storage ceiling, or consumes memory or disk
   without producing a row (zombie spool, zombie object).
I. A request causes a panic, a 500 with a non-uniform body, or a hang.
J. An anonymous client exceeds the rate limit by varying IP within a /64,
   by adding a bogus X-Forwarded-For, or by sending a garbage Bearer token.
K. A user key can be linked to a secret it created, using everything the
   admin API exposes plus the database.
L. The locale redirect can be made to leak the fragment or redirect off-site.
M. The admin panel can be driven without a valid session (CSRF, cookie forge,
   bootstrap token after first key).
N. A settings PATCH puts the instance into a state where secrets are accepted
   with a padded size the policy should reject, or where TTL exceeds 14 days.
O. The scheduler can be made to serve a pending_delete row or to double-count
   a counter.
P. An email link scanner that follows the share link, with or without
   executing JavaScript, consumes the secret.
Q. Anything in a log at SHH_LOG_LEVEL=trace identifies a secret or a client.

Report in the standard output format. A property that holds goes under
Checked and clean with the test name that proves it.
```

---

## Pass 8 — Synthesis (orchestrator runs this itself)

```
Read every file in docs/security-review/findings/. Produce SUMMARY.md with:

1. A ranked table: id, severity, one line, location, which pass found it,
   whether pass 7 independently confirmed it.
2. Duplicates merged, with the ids they came from.
3. For each proposed fix, a check against SPEC.md §12 and §13: Allowed /
   Needs spec revision / Rejected by principle (and which one).
4. Rediscovered accepted residuals: findings that SPEC.md already records as
   accepted (D-1's lost-response case, §5.1 accepted residual, §10 best-effort
   scrubbing), with the section cited, so they are not treated as new.
5. Suspicions that deserve a follow-up, each with the experiment that would
   settle it.
6. A short list of properties that were tested and hold, to put in the
   security page or threat model.

Keep it factual. No fixes applied, nothing committed.
```
