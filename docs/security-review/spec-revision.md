# SPEC.md revision — security review follow-up

Status: draft for application. Nothing is deployed, so protocol and schema
changes are made in place: edit the existing migrations, keep fragment
version 1, regenerate `vectors/v1.json`. No v2, no new migration files.

Decisions taken (2026-10-30, @Rene):
- S-19: burn fragments carry a distinct type byte, now.
- S-6: `expires_at` is rounded up on store; `claim_expires_at` to the minute.
- S-7: `api_keys.last_used_at` becomes `last_used_on` (UTC date).
- S-8: the reports ledger is removed; reports are a daily counter.
- OPEN: whether the reveal page keeps "hours remaining" on TTL secrets
  (see §5.2 / §11 below). Apply the rest regardless.

Apply the edits below to `SPEC.md`, then the listed follow-ups.

## Working procedure (read first)

Work through the numbered steps below **one at a time**. For each step:

1. Make only that step's change. Do not start, prepare or stage anything
   from a later step, and do not fix unrelated things you notice; write
   them down under "Noticed" at the end of your message instead.
2. Run the checks that step names (at minimum `cargo test` for Rust
   changes, `npm test` in `client/` for TypeScript, `python3
   vectors/generate.py` for vector changes) and make them pass.
3. Stop. Report in one short message: the step number, the files changed
   (`git status --short`), the check results, and a proposed commit message
   on its own line in the form `<area>: <what changed>` (under 60
   characters, imperative, no trailing period). Examples: `spec: add kind
   byte to burn fragments`, `store: round expires_at to grid`,
   `api: refuse meta parts over 4 KiB`.
4. Do not commit. Wait for the human to commit and say "next" (or to ask
   for changes). Only then begin the following step.

If a step turns out to need more than about 300 changed lines or touches
more than one subsystem, stop before changing anything and propose how to
split it.

## Steps

Spec and content pages first, then schema and protocol (which change tests), then
the review tests become the regression suite, then code.

| # | step | checks |
|---|---|---|
| 1 | Apply the `SPEC.md` edits below (text only). Leave the three `OPEN` items marked as they are. | none |
| 2 | Content pages: `privacy.md`, `security.md`, `acceptable-use.md`, `docs.md` (en and de) per Follow-ups. | `cargo test -p shhnote-server` (content tests) |
| 3 | Migrations: `WITHOUT ROWID` on `secrets` (SQLite), delete the reports table, add `reports` to `stats_daily`, rename `last_used_at` → `last_used_on DATE`. Update the store code and tests that touch these columns, nothing else. | `cargo test` |
| 4 | Protocol: kind byte `0x02` for burn fragments in core, TS and `generate.py`; wrong-kind refusal in `parseFragment`/`burnSecret`/`revealSecret` and the `/s` and `/burn` pages; regenerate `v1.json`. | `cargo test`, `npm test` |
| 5 | Vectors: add the new reject cases (S-46, S-48) to `generate.py`; regenerate; make both suites consume them. | `cargo test -p shhnote-core`, `npm test` |
| 6 | Review tests: flip pass 1/3/5/7 tests to assert the spec'd behaviour, rename all `review_*` files and tests to `spec_*`, fix the rustfmt/clippy issues in them. They are expected to fail until the matching fix lands; mark each with `#[ignore = "S-n"]` / `test.skip` carrying the finding id, to be un-ignored by the step that fixes it. | `cargo clippy --all-targets`, `cargo fmt --check` |
| 7 | S-1: `/config` leak. | un-ignore its tests, `cargo test` |
| 8 | S-3: bounded `meta` read. | same |
| 9 | S-2: server timeouts and upload cap (`SHH_MAX_UPLOADS`), bounded shutdown. | same |
| 10 | S-4 + S-5: ceiling reservation, spool bytes counted, declared-length checks before spooling, startup orphan collection, `blob_len(bucket)`. | same |
| 11 | S-12: S3 timeouts, scrub in its own task, bounded batch. | same |
| 12 | S-6: expiry grid and claim-expiry rounding. | same |
| 13 | S-7 + S-23 counters: `last_used_on` write path, daily `reports` increment, `/reports` same-work statement sequence (S-16). | same |
| 14 | S-9: duplicate create → 201, no write. | same |
| 15 | S-26: uniform handling of framework-level body rejections; `/reports` fixed 200. | same |
| 16 | S-11 + S-36: S3 error logging, startup prints. | same |
| 17 | S-13 + S-58 + S-34: IP canonicalisation, XFF line joining, proxy range validation. | same |
| 18 | S-27 + S-28: constant `Retry-After`, per-subject eviction. | same |
| 19 | S-25 + S-18: headers on every response, `no-store` on admin. | same |
| 20 | S-10: settings range checks and checked arithmetic; env upper bounds. | same |
| 21 | S-30 + S-31 + S-32 + S-33: open-before-claim, spool dir handling, http S3 refusal, file modes/fsync/22-char names. | same |
| 22 | S-15 + S-14 remainder: `journal_size_limit`, WAL truncate after sweep, backup docs. | same |
| 23 | S-20 + S-21: client streaming, claim-token retry, body length cap. | `npm test` |
| 24 | S-22 (D-22) + suspicion 1: always-prefetch `argon2.wasm`; reveal guard on trusted `click`/key activation with `detail > 0` and `userActivation`. | `npm test`, manual check in Firefox and Chromium |
| 25 | S-44 + S-45 + S-47 + S-50 + suspicions 6/7: wiping, error contract, download names, octet-stream, WebAssembly-unavailable message. | `npm test`, `cargo test -p shhnote-argon2-wasm` |
| 26 | S-29 + S-37 + S-39 + S-40 + S-41 + S-43: admin fixes. | `cargo test` |
| 27 | S-42 + S-38: URL scheme checks, inline styles → classes. | `cargo test` |
| 28 | S-35 + S-49 + S-54: dependency features, `erasableSyntaxOnly`, crate metadata. | `cargo build`, `cargo deny check`, `npm test` |
| 29 | S-22 to S-24 + S-51 to S-53: workflows, Dockerfile digests, `--locked`, toolchain pin, `build.rs` checks. | `docker build .` if available |
| 30 | S-55 to S-57 + suspicions 10/14/15: compose/systemd hardening, env example comments, Fly notes. | `shhnote check` against each example |
| 31 | Remaining suspicions (3, 4, 5, 8, 9, 11, 12, 13, 16, 17): run the named experiment, report, fix only if confirmed and small; otherwise record as a residual or a new finding. | per item |
| 32 | **OPEN decision:** reveal-page expiry display. Skip until the human has decided; then apply to §4, §5.2, §11, the header and the template in one step. | `cargo test` |

---



---

## §1 Decisions

**D-2, rewrite:**
> A separate random burn token, hashed at rest, carried in a fragment whose
> first byte differs from the share fragment's so the two links can be told
> apart before anything is sent. Burn = creator only; report = any link
> holder. Stats distinguish `burned` from `removed`.

**Add:**

| ID | Decision | Why |
|---|---|---|
| D-18 | `expires_at` is stored rounded up to a grid that scales with the TTL (§3); `claim_expires_at` is stored rounded up to the next minute. | `expires_at − preset` and `claim_expires_at − window` would otherwise be creation and reveal timestamps to the second, which §13 rejects. |
| D-19 | Reports are counted per UTC day in `stats_daily`. No per-report row exists. | A ledger keyed by the secret's hash is a joinable tombstone (§13); the operator question ("how many, when") is answered by the daily count. |
| D-20 | Storage ceilings count bytes being spooled as well as stored objects; a create that would cross the ceiling is refused mid-stream. | Principle 7: the ceiling must bound disk, not only committed objects. |
| D-21 | `POST /secrets` answers a duplicate `lookup_key` exactly like a success and writes nothing. | A distinguishable duplicate response is an existence oracle for anyone holding a hash. |
| D-22 | The client fetches `argon2.wasm` on every create and reveal, whether or not a passphrase is involved. | Fetching it only when needed marks passphrase use to the server and the network. |
| D-23 | API keys record the UTC day of last use (`last_used_on`), never the time. | Enough for an operator to see that a key is dead; too coarse to join with anything. |

## §2.2 Seed and fragment

Replace the fragment definition with:

> Fragment = `kind(1) ‖ payload(32)` = 33 bytes = 44 base64url characters.
> The kind byte names both the suite and the fragment's role:
>
> | kind | fragment | payload |
> |---|---|---|
> | `0x01` | share link `https://host/s#…` | seed |
> | `0x02` | burn link `https://host/burn#…` | burn token |
>
> A client given a fragment of the wrong kind for the page or function it is
> on refuses before deriving or sending anything. Future suites allocate a
> new pair of kind bytes. The blob carries no version and no flags.

## §2.11 Burn token

Replace "Burn link: `https://host/burn#version(1) ‖ burn_token(32)` (44 chars,
same shape as the share link, same locale redirect)" with:

> Burn link: `https://host/burn#0x02 ‖ burn_token(32)` (44 chars, same locale
> redirect). The kind byte makes a burn fragment distinguishable from a share
> fragment on sight; the `/burn` page and `burnSecret` reject a `0x01`
> fragment, and the `/s` page and `revealSecret` reject a `0x02` fragment,
> without contacting the server.

## §2.13 Versioning

Replace "Bump the fragment version" with "Allocate a new pair of kind bytes".

## §2.14 Conformance vectors

Add: "Every vector includes the burn fragment as well as the share fragment,
and the reject cases include a share fragment presented as a burn fragment
and vice versa." Add the reject cases from S-48 (chunk order, last flag,
truncation, header length, manifest and size bounds, the parity cases of
S-46). Regenerate `vectors/v1.json`; the "never edit" rule in
`vectors/README.md` is satisfied because this is the pre-release definition.

## §3 What the server stores

Replace the `secrets` block and its paragraph with:

```
secrets  (SQLite: WITHOUT ROWID)
  lookup_key        32 bytes  PK      SHA-256(lookup)
  burn_key          32 bytes  UNIQUE  SHA-256(burn_token)
  status            active | claimed | pending_delete
  lifetime          single_view | ttl
  bucket            u32 (bytes)
  blob              bytes, NULL when external
  external_ref      text, NULL when inline
  expires_at        unix seconds, rounded up to the expiry grid
  claim_key         32 bytes NULL     SHA-256(claim_token) while claimed
  claim_expires_at  unix seconds NULL, rounded up to the next minute
```

> **Expiry grid (D-18).** On write, `expires_at = ceil((now + ttl) / g) × g`
> where `g` is 300 s for `ttl < 3600`, 3600 s for `ttl < 3 × 86400`, and
> 86400 s otherwise. The recipient-facing remaining time is already in whole
> hours, so nothing visible changes; the creator receives at least the TTL
> asked for. The grid is part of the schema contract: a refactor that stores
> the exact second reintroduces a per-secret timestamp.

> No `created_at`, no IPs, no counters, no foreign keys to anything, and in
> SQLite no rowid, so a dump cannot order secrets by creation (Principle 5,
> 8). Daily counters (`stats_daily`: created, viewed, burned, expired,
> removed, **reports** per UTC day), settings, and API keys live in their own
> tables and are never joined to `secrets`. There is no reports table (D-19).
> Lifetime totals are the sum of the daily rows; the number of active secrets
> is counted live. One table per migration.

Follow-up: edit `migrations/*/0001_secrets.sql` (`WITHOUT ROWID` in SQLite),
delete `0003_reports.sql` (or repurpose the number) and add the `reports`
column to the `stats_daily` migration; rename `api_keys.last_used_at` to
`last_used_on DATE`.

## §4 API

- `POST /secrets`: replace the Notes with "`meta` precedes `blob` so the
  server can validate before streaming; `meta` is read in bounded chunks and
  refused past 4 KiB. Blob length must match a ladder entry exactly. A
  `lookup_key` that already exists returns `201` and writes nothing (D-21)."
- `POST /secrets/reveal`: the `X-Shh-Expires-In-Hours` header — **OPEN**; if
  the reveal page stops showing remaining time, delete the header here.
- `POST /reports`: replace Notes with "Automatic takedown; increments
  `reports`, and `removed` when a secret was destroyed (D-19). Uniform
  response."
- Replace the uniform-negative paragraph with:

> Every negative outcome on an endpoint that takes a secret credential
> returns the same `404` with the same body, after the same work. This
> includes bodies the framework would otherwise reject (malformed JSON, wrong
> types, missing fields, missing `Content-Type`): the handler takes the raw
> body, substitutes fresh random bytes for anything unparseable, and runs the
> full path. `/reports` always returns its fixed `200` and always performs
> the same statement sequence (counter upserts of `+0` or `+1`). Reveal and
> blob responses carry `Cache-Control: no-store`. `Retry-After` on a `429` is
> a constant that does not depend on the threshold.

- Rate limiting paragraph, add: "Peer addresses are canonicalised
  (IPv4-mapped IPv6 is treated as IPv4) before bucketing or proxy matching.
  All `X-Forwarded-For` header lines are joined before the walk from the
  right. When the bucket table is full, individual subjects are evicted; the
  table is never cleared except by salt rotation."
- Add: "The §11 security headers are applied to every response, API and
  drain responses included."

## §5 Lifecycle

- §5.1 step 1: "`claim_expires_at = now + window`, rounded up to the next
  minute (D-18)". Add to step 1: "For an external blob the object is opened
  before the claim is committed; a missing object yields the uniform
  negative and leaves the row untouched."
- §5.2 — **OPEN.** Either keep "The response carries the remaining lifetime
  in whole hours, rounded up, never an absolute time", or replace with "The
  response carries no expiry information; the reveal page says only that the
  secret expires when the sender chose."
- Add to §5.1 accepted residual: "A browser driven by automation (a scanner
  that injects real input events, an extension with input access) can reveal
  a secret as a user would; the recipient then sees the uniform negative.
  Page scripts cannot: the reveal requires a trusted pointer or keyboard
  activation of the button (`click` with `isTrusted` and `detail > 0`, or a
  trusted key activation), not merely a trusted `submit`."

## §6.1 Tiers

- Tier guards bullet: "They count every object the tier holds, parked
  deletes included, **and every byte currently being spooled (D-20)**; the
  check is made under one reservation so concurrent creates cannot jointly
  exceed the ceiling, and a create that would cross it is refused as soon as
  that is known, including mid-stream, with `507 storage_full`."
- Receiving bullet, add: "The length, ladder and `files_disabled` checks run
  against the declared length before the first blob byte is spooled; the
  spool is capped at the declared length."
- Add: "At startup the server lists the tier and deletes objects no row
  references. Spool files are `0600` in a `0700` directory; the blob
  directory is fsynced after rename. Object names are exactly 22 base64url
  characters."
- Add an **Accepted residuals** sub-bullet: "External-tier objects carry a
  modification time the server cannot fully control (S3 `LastModified`; local
  `ctime`), so an operator with object-store access learns when each large
  secret was created. Destruction is logical: ciphertext (never plaintext)
  may persist in SQLite WAL, Postgres dead tuples, filesystem free blocks and
  backups until overwritten. The server sets `journal_size_limit = 0` and
  truncates the WAL after each sweep; backups should use `VACUUM INTO` or
  `.backup`, not file copies."
- S3 bullet: "An `http://` endpoint is refused in production unless it is a
  loopback or private address."
- Add: "The S3 client applies connect, request and body timeouts; scrubbing
  runs in its own task with a bounded batch per tick."

## §6.2 Padding policy

D-6 clarification: "`padding_min` is a floor: the instance may raise it but
not set it below 64 KiB. In `buckets` mode the ladder must be strictly
increasing and must not exceed `SHH_EXTERNAL_MAX_OBJECT`."

## §7 Configuration

- §7.1: add upper bounds: `SHH_INLINE_MAX ≤ 64 MiB`, `SHH_EXTERNAL_MAX_OBJECT
  ≤ 4 GiB`; `SHH_TRUSTED_PROXIES` also rejects prefixes shorter than /8 (v4)
  or /32 (v6), mapped and transition ranges, and non-network base addresses;
  `SHH_SPOOL_PATH` must be a dedicated directory (only `*.part` files are
  removed at start). The server applies header, idle and request timeouts and
  a concurrent-upload cap (`SHH_MAX_UPLOADS`, default 64).
- §7.2: "Every setting is range-checked as a whole: `padding_min ≥ 65536`,
  ladder monotone, `claim_window_secs` in `60..=86400`,
  `rate_user_multiplier ≥ 1`, every preset within `[min_ttl, max_ttl]`,
  `max_ttl ≤ 14 d` (refused, not clamped), `daily_retention_days ≥ 1` or
  `-1`, region and source URLs `https://` only (`http://` when `SHH_ENV` is
  `local`). Arithmetic on settings is checked or saturating." Remove any
  mention of a reports retention setting.

## §8 Admin and API keys

- API keys: "stored as `SHA-256(key)` with a name, scopes, `created_at`, and
  `last_used_on` (UTC date, written at most once per day, D-23)".
- Bootstrap: "A bootstrap session is bound to the hash of the token that
  created it and is invalid once any admin key exists; `reset-admin` does not
  revive earlier bootstrap sessions."
- Sessions: "Logout requires the CSRF token." Add: "Deleting a key ends its
  sessions immediately; keys carry a `sessions_valid_after` timestamp so an
  operator can also end a key's sessions without deleting it."
- Panel: replace "the read-only reports ledger" with "the daily report
  counts (part of stats)". Every admin response carries
  `Cache-Control: no-store`. Settings save and key creation respond with a
  redirect; the new key is shown once on the redirected page via a one-time
  server-side nonce.
- Admin API: "Credentials are compared in constant time or looked up by
  hash; the login bucket is consulted before the lookup."

## §10 Client

- Replace "The seed is the only key material that does" (§2.4 and here) with
  "The seed, and for passphrase secrets the Argon2 output until it is
  consumed by `deriveKey`, are the only raw key material in JavaScript; both
  are overwritten when the page is left (best effort)."
- Add: "`argon2.wasm` is fetched on every create and reveal (D-22)."
- Add: "The client streams: it reads response headers before the body, keeps
  the claim token through any body or passphrase error, retries with it
  while the window is open, and refuses a body longer than the largest valid
  blob. Decryption runs chunk by chunk and files are assembled
  incrementally."
- Add: "Download names are normalised (NFC), stripped of control, bidi and
  path characters, capped in length, and rendered with `<bdi>`. Blob URLs
  are always `application/octet-stream`."
- Add: "Wrong-kind fragments (§2.2) are refused before any derivation."
- Add: "If WebAssembly is unavailable (Tor Browser at Safer), the client
  says so instead of reporting a corrupt secret."

## §11 Web layer

- Headers paragraph: "on every response, including API, redirect, error and
  drain responses". Remove inline `style=` attributes (CSP already blocks
  them).
- Copy rules — **OPEN:** if remaining time is removed, add "no expiry
  information on the reveal page".
- Startup prints nothing but through the log macros.

## §13 Rejected by principle

Add:
- **Per-report ledger rows.** A row keyed by a secret's hash with a time and
  an outcome is a tombstone whatever its retention; reports are a daily
  count (D-19).
- **Timestamps on API-key use finer than a day.** Joinable with the expiry
  grid (D-23).
- **Fragments of different roles sharing one shape.** A burn fragment must
  be distinguishable from a share fragment before it is sent (D-2).
- **Distinguishable duplicate-create responses.** An existence oracle
  (D-21).

---

## Follow-ups outside SPEC.md

- `content/en/privacy.md`, `security.md`, `acceptable-use.md`, `docs.md`:
  remove the ledger wording; add the residuals above (object timestamps,
  logical destruction, automation-driven reveal); add the memory-wiping
  caveat §10 says is there.
- `vectors/generate.py`: burn fragment kind byte, new reject cases,
  regenerate.
- Review tests: flip pass 1/3/5/7 tests to assert the spec'd behaviour and
  rename all to `spec_*`; they become the regression suite.
