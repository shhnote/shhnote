# Security review: what was done about each finding

Closes the review in `findings/SUMMARY.md` (run 2026-10-30) and the plan in
`spec-revision.md` (steps 1–32, 2026-10-30 to 2026-10-31). Every `S-n` below
is either fixed by the listed commit(s), or recorded as an accepted residual in
`SPEC.md`. The regression tests that pin each fix carry the finding id in their
name or comment (`spec_*` files; the former `review_*` files were converted in
`1283113`, `b0067f4`, `deefc8a`, `8beaa42`, `83f66e9`).

Groundwork shared by several findings: `c7612bc` (SPEC.md revision),
`133f9f0` (content pages), `fe532b0` (executable build scripts, the CI failure
that started this).

## Findings → commits

| id | sev | fixed by | notes |
|---|---|---|---|
| S-1 | High | `6eb6e01` | `/config` serialises from the settings snapshot; nothing leaked |
| S-2 | High | `7be7ae9` | header/body-idle/upload timeouts, `SHH_MAX_UPLOADS`, bounded drain |
| S-3 | High | `d1d5650` | `meta` read in bounded chunks, refused past 4 KiB |
| S-4 | High | `289839d` | ceiling reservation (`Ledger`/`Reservation`) atomic across the create |
| S-5 | High | `289839d` | declared-length checks before spooling, spool bytes count toward the ceiling (D-20), orphan collection at start |
| S-6 | Medium | `567c79e` | expiry grid (D-18), claim expiry to the next minute |
| S-7 | Medium | `daedd5a`, `cd60b21` | `last_used_on` is a UTC day (D-23), written at most once per day |
| S-8 | Medium | `daedd5a`, `3852223`, `cd60b21`, `133f9f0` | reports ledger gone; daily `reports` counter in `stats_daily` (D-19); pages say so |
| S-9 | Medium | `88a9a00` | duplicate create answers `201` and writes nothing (D-21) |
| S-10 | Medium | `bd48ed0` | every setting range-checked, arithmetic saturating, `SHH_INLINE_MAX`/`SHH_EXTERNAL_MAX_OBJECT` ceilings |
| S-11 | Medium | `1e8847c` | S3 error text never names the object |
| S-12 | Medium | `dfe5240` | S3 connect/response/body timeouts, scrub in its own task, bounded batches |
| S-13 | Medium | `29c1337` | IPv4-mapped peers canonicalised |
| S-14 | Medium | `daedd5a` (SQLite `WITHOUT ROWID`), `a996d5c` (backup guidance) | **Postgres part is a residual** (below) |
| S-15 | Medium | `a996d5c` | `journal_size_limit = 0`, WAL truncated after every sweep, `.backup`/`VACUUM INTO` only |
| S-16 | Medium | `cd60b21` | `/reports` runs the same statement sequence for every outcome |
| S-17 | Medium | `133f9f0`, `c7612bc` | **residual** (below): object store modification times |
| S-18 | Medium | `b189063` | `Cache-Control: no-store` on every admin response |
| S-19 | Medium | `3f56f34`, `4d7b563` | kind byte `0x02` on burn fragments; wrong-kind refused before any derivation |
| S-20 | Medium | `e0b1b88`, `b614a12`, `fda682d` | streaming decryption, incremental payload assembly, body cap |
| S-21 | Medium | `b614a12`, `fda682d` | claim token kept through every failure, re-download on retry, `confirm:false` returns it |
| S-22 | Medium | `1f2f63a` | actions pinned to commits, `permissions: {}` with per-job grants |
| S-23 | Medium | `1f2f63a` | release depends on CI, `cargo deny` + `npm audit` jobs, reproducible tarballs, provenance attestations |
| S-24 | Medium | `1f2f63a` | digests on every image (Dockerfile, compose, CI service) |
| S-25 | Low | `b189063` | security headers on every response, including API, redirects, errors and drain |
| S-26 | Low | `4419e43` | framework-level body rejections take the uniform path (`Lenient`/`Strict` extractors) |
| S-27 | Low | `1a786d4` | constant `Retry-After` |
| S-28 | Low | `1a786d4` | per-subject eviction instead of clearing the table |
| S-29 | Low | `f2c6afc` | one `unhex` that checks hex digits before slicing |
| S-30 | Low | `466bf98` | object opened before the claim commits; open failure is the uniform 404 |
| S-31 | Low | `466bf98` | only `*.part` files removed from the spool directory |
| S-32 | Low | `466bf98` | plain-`http://` S3 refused in production unless loopback/private |
| S-33 | Low | `466bf98` | 0600 files, 0700 directories, fsynced rename, 22-character object names |
| S-34 | Low | `29c1337` | proxy ranges must be network addresses, `/8` (v4) and `/32` (v6) at widest, transition ranges refused |
| S-35 | Low | `86cb2e1` | axum/tokio/sqlx features trimmed; sqlx's duplicate crates **accepted** (`deny.toml`) |
| S-36 | Low | `1e8847c` | startup goes through the log macros |
| S-37 | Low | `f2c6afc` | constant-time bootstrap compare on the admin API |
| S-38 | Low | `5518060` | utility classes replace every inline `style=` |
| S-39 | Low | `95c4a5e` | bootstrap sessions bound to the token hash and to the last `reset-admin` (`admin_state`) |
| S-40 | Low | `95c4a5e` | CSRF on logout; `sessions_valid_after` with an "End sessions" action |
| S-41 | Low | `f2c6afc` | login bucket consulted before the lookup, charged only on failure |
| S-42 | Low | `bd48ed0`, `5518060` | web URLs only, `https://` outside `SHH_ENV=local`; email sanity check |
| S-43 | Low | `dec32c1` | redirect after settings save and key creation; the key shown once via a one-time nonce (login page for the first admin key) |
| S-44 | Low | `f8ce537` | Argon2 work memory wiped in the WASM module and in core (`argon2/zeroize`) |
| S-45 | Low | `c7612bc`, `133f9f0`, `fda682d`, `40f5875` | spec wording, threat-model caveat, seed/ciphertext/passphrase wiped on `pagehide` |
| S-46 | Low | `4d7b563`, step 33 | parsing parity cases pinned by vectors; an empty passphrase is an error at the API boundary on both sides (§2.10), pinned by the `empty-passphrase` reject vector |
| S-47 | Low | `e0b1b88`, `40f5875` | hostile blobs stay inside the `ShhError` contract |
| S-48 | Low | `4d7b563` | multi-chunk and truncation negatives in the vectors |
| S-49 | Low | `86cb2e1` | no parameter properties; `erasableSyntaxOnly` |
| S-50 | Low | `40f5875` | download names normalised and cleaned, rendered in `<bdi>` |
| S-51 | Low | `1f2f63a` | `rust-toolchain.toml` 1.99.1, `--locked`, tests on amd64 and arm64 |
| S-52 | Low | `1f2f63a` | `--locked` wasm build, `npm ci --ignore-scripts`, `.gitattributes` |
| S-53 | Low | `1f2f63a` | `build.rs` checks presence, non-emptiness, wasm magic and a source stamp |
| S-54 | Low | `86cb2e1` | license, repository, `publish = false`, descriptions; `deny.toml` |
| S-55 | Low | `8c10d2f` | compose: all caps dropped, `no-new-privileges`, pids and memory limits |
| S-56 | Low | `8c10d2f` | systemd: `ProcSubset`, `IPAddressDeny/Allow`, `TasksMax`, `MemoryMax`, `LimitNOFILE` |
| S-57 | Low | `8c10d2f` | env examples: `SHH_DB` is required |
| S-58 | Low | `29c1337` | every `X-Forwarded-For` line joined before the hop walk |

## Suspicions (SUMMARY §5) → outcome

| # | outcome | commit |
|---|---|---|
| 1 | confirmed by design; reveal needs a real pointer press (`detail > 0`) or key press, with `userActivation` | `4d2b4d8` |
| 2 | decided (D-22): `argon2.wasm` fetched on every create and reveal | `4d2b4d8` |
| 3 | **confirmed** on Postgres 17 (`pageinspect`): deleted rows keep their bytes until `VACUUM`; `ctid`/`xmin` order by creation → residual + deploy note | `88900d0` |
| 4 | **confirmed** (external lock test); sweep now in batches of 200, one transaction each | `88900d0` |
| 5 | confirmed by reading; `ping` waits at most 2 s for a connection | `88900d0` |
| 6 | fixed regardless: blob URLs are always `application/octet-stream` | `40f5875` |
| 7 | fixed: specific WebAssembly-unavailable message | `40f5875` |
| 8 | fixed: settings re-loaded once the body is in | `88900d0` |
| 9 | fixed: RNG failure refuses startup / skips rotation loudly | `88900d0` |
| 10 | documented (reverse-proxies guide) | `8c10d2f` |
| 11 | fixed: rollup folds only the rows its `DELETE … RETURNING` removed | `88900d0` |
| 12 | partly: `active` counts claimed secrets, so the number moves on confirm, not reveal → residual | `88900d0` |
| 13 | **clear**: no admin page reflects request data without a CSRF token; Caddy does not compress octet-stream | – |
| 14 | undocumented by Fly; guide says how to check and fix a root-owned volume | `8c10d2f` |
| 15 | narrowed to the org's own 6PN `/48`; `fdaa::/16` is refused by the server | `8c10d2f` |
| 16 | not testable here → residual in §2.9 | `88900d0` |
| 17 | fixed: rotation applies to key subjects too | `88900d0` |

The one OPEN decision (reveal-page expiry display) was taken on 2026-10-31:
no remaining time anywhere on TTL secrets, single-view keeps its "destroyed"
message (`81c7619`).

## Accepted residuals

Recorded in `SPEC.md`; none of them has a code fix pending.

- **Object store timestamps (S-17, §6.1).** External-tier objects carry a
  modification time the server cannot control (S3 `LastModified`, local
  `ctime`), so an operator with object-store access learns when each large
  secret was created.
- **Logical destruction (S-14 Postgres part, S-15 remainder, suspicion 3,
  §6.1).** Ciphertext may persist in the SQLite WAL until the next sweep's
  truncation, in Postgres heap pages, TOAST and `pg_wal` until vacuumed or
  recycled, in filesystem free blocks and in backups. Postgres also orders
  rows by creation (`ctid`, `xmin`). Mitigations are operational
  (`docs/deploy/operations.md`: `.backup`/`VACUUM INTO`, aggressive
  autovacuum, short WAL retention, disk encryption).
- **Lost reveal and automated readers (§5.1).** A single-view secret whose
  response was lost before any byte arrived, or that was revealed by a browser
  driven with real input events, is destroyed unread; the recipient sees the
  uniform negative. Page scripts cannot trigger it.
- **Argon2 memory at the top of the bounds (suspicion 16, §2.9).** A blob at
  `m = 256 MiB` makes the recipient's browser hold that much until the page is
  left; on a low-memory device the grow can fail and shows as the
  WebAssembly-unavailable message.
- **Admin `active` count (suspicion 12, §8).** The live count still moves on
  each terminal transition (confirm, burn, expiry), so an admin polling it
  sees those events to the second; it no longer moves on the reveal itself.
- **sqlx's dependency generation (S-35).** sqlx brings its own base64,
  getrandom and RustCrypto versions next to the ones the core uses;
  `deny.toml` warns on duplicates rather than failing.

## Left for a human

- Browser checks that need a real browser: the reveal guard (`4d2b4d8`: console
  `requestSubmit()` / `button.click()` must not reveal), the streaming reveal
  flow (`fda682d`), and the `argon2.wasm` prefetch on `/` and `/s`.
- The first push and tag will show whether the GitHub-side pieces of
  `1f2f63a` behave: the `ubuntu-24.04-arm` runner, the reusable-workflow call,
  and the attestations.
- A by-hand check that takes 10 s and stays `#[ignore]`:
  `spec_sqlite_lock_holder_makes_claims_fail_after_busy_timeout`.
