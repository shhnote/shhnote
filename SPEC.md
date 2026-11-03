# shhnote — Specification

**Status:** current as of 2026-10-30. This is the authoritative description of what shhnote is and how it works. Code defers to this document; where they disagree, the code is wrong. The principles in §12 govern every decision here and every future change.

---

## 1. Decisions

| ID | Decision | Why |
|---|---|---|
| D-1 | A single-view secret is consumed when its bytes are served. The claim token lets the same client re-download within a 15-minute window; unconfirmed claims are destroyed, never reverted. | An intercepted or scanned link must always show as "already viewed" to the intended recipient. Reverting hides interception. |
| D-2 | A separate random burn token, hashed at rest, carried in a fragment whose first byte differs from the share fragment's so the two links can be told apart before anything is sent. Burn = creator only; report = any link holder. Stats distinguish `burned` from `removed`. | Accurate attribution of why a secret was destroyed; the share link carries no burn authority. |
| D-3 | The server stores `SHA-256(lookup)`, never the raw lookup value. | A database dump must not let anyone consume, report, or otherwise act on secrets. |
| D-4 | Content is encrypted in 64 KiB chunks (STREAM construction). | Streaming upload and download with bounded memory; large files for self-hosted instances. |
| D-5 | One secret carries optional text plus zero or more files, described by a JSON manifest inside the encrypted payload. | Text only, text + files, or files only with one payload structure. |
| D-6 | Padding policy is an instance setting: `padme` (default) or fixed `buckets`, with a 64 KiB minimum padded size. Advertised by the API, not part of the crypto version. Random padding is rejected. | Low overhead with shared sizes and a published analysis; the minimum makes every small file look like text. |
| D-7 | Maximum TTL 14 days. | Product decision. |
| D-8 | Runtime settings live in the database with code defaults; deployment settings in the environment. Admin panel: settings, stats, reports, API keys. | Operators change site policy without redeploying. |
| D-9 | Admin bootstrap via `SHH_ADMIN_TOKEN`, then an admin-scoped API key; the token is retired. | No long-lived password in the environment. |
| D-10 | Environment variables are prefixed `SHH_`. | Avoids collisions in shared environments. |
| D-11 | API served at `/api` or on an `api.` subdomain, chosen by env. | Deployment flexibility. |
| D-12 | Multi-region is a list of sibling instances in settings, shown as a quiet selector near the create form; navigation only. | Isolated instances; nothing shared. |
| D-13 | Client code is TypeScript, published as one npm package `@shhnote/client` with three entry points, and also served by every instance as two bundles plus one WASM file. `@shhnote/client/crypto` is the pure protocol (no fetch, no DOM) and the unit the conformance vectors test; the package root adds the API client, streaming reveal and the frontend-safety helpers (no DOM); `@shhnote/client/ui` holds the reference page controllers (DOM). A third-party client takes the layer it needs. | Type safety in the open-source client; an integration kit for CLIs, other clients and other frontends. |
| D-14 | Argon2id in the browser is compiled to WASM from the same Rust `argon2` crate the server uses. | One implementation on both sides; no npm runtime dependency. |
| D-15 | The passphrase KEK takes the seed directly; no intermediate derivation. | HKDF's info strings already separate the derivations. |
| D-16 | Not in v1: external cache, compile-time feature flags, nonce-based CSP, runtime content overlay, sqlx compile-time query macros. One binary builds every tier. The built-in website is a minimal reference frontend. Operators who want a different site run their own frontend against the API (`SHH_WEB=api`) using the client package; the binary carries no instance-specific content and no content overlay. | Minimal attack surface and build friction. |
| D-17 | API keys have scopes `admin` and `user`; `user` keys raise rate limits and are never linked to secrets. | Integrators and trusted users get higher limits without identity touching secrets. |
| D-18 | `expires_at` is stored rounded up to a grid that scales with the TTL (§3); `claim_expires_at` is stored rounded up to the next minute. | `expires_at − preset` and `claim_expires_at − window` would otherwise be creation and reveal timestamps to the second, which §13 rejects. |
| D-19 | Reports are counted per UTC day in `stats_daily`. No per-report row exists. | A ledger keyed by the secret's hash is a joinable tombstone (§13); the operator question ("how many, when") is answered by the daily count. |
| D-20 | Storage ceilings count bytes being spooled as well as stored objects; a create that would cross the ceiling is refused mid-stream. | Principle 7: the ceiling must bound disk, not only committed objects. |
| D-21 | `POST /secrets` answers a duplicate `lookup_key` exactly like a success and writes nothing. | A distinguishable duplicate response is an existence oracle for anyone holding a hash. |
| D-22 | The client fetches `argon2.wasm` on every create and reveal, whether or not a passphrase is involved. | Fetching it only when needed marks passphrase use to the server and the network. |
| D-23 | API keys record the UTC day of last use (`last_used_on`), never the time. | Enough for an operator to see that a key is dead; too coarse to join with anything. |
| D-24 | `SHH_WEB` selects `full` (website, API, admin, static) or `api` (API, admin and `/static/*` only; every other public route is `404`). | An operator with their own frontend should not expose a second one. |
| D-25 | The admin panel is routed like the API: `SHH_ADMIN_ROUTING=path` (`/{locale}/admin`) or `subdomain` (`admin.<host>/{locale}/`). | Operators choose where the panel is reachable; a subdomain is easy to firewall. |
| D-26 | `allowed_origins` is a settings list of origins the API answers to with CORS headers. Empty (the default) means the site origin only, as before. | A frontend on another origin needs it; nothing else does. |
| D-27 | The server version is public: in `GET /config`, in the footer of every built-in page, and in `/health`. | Open-source software with tagged releases; a visitor can see what an instance runs. |
| D-29 | Setup is a derived state, never stored: an admin-scoped key exists, `site_name` is non-empty and `contact_email` is non-empty. `site_name` has no default; `security_email` falls back to `contact_email` at the settings layer; once set, neither `site_name` nor `contact_email` can be cleared. Until setup is met, `/health` reports `configured: false` and every route but the admin panel, the admin API, `/static/*` and `/health` answers `503` with the full header set and `Cache-Control: no-store`: a setup page for pages (naming the three requirements and linking the admin login, never saying whether a bootstrap token is set), the error envelope with `code: not_configured` for the API. The state is derived while unmet and remembered once met. | Secure by default and usable once the operator has said who runs the site; a derived state cannot drift from the facts. |
| D-28 | The reference frontend is minimal: the create form, the reveal, burn and report pages, the policy pages, a short how-it-works, the public API docs, and the admin panel. Every page is written for "this site", with `{{site_name}}` and contact placeholders. | The binary is the same for every operator; nothing in it should read as one operator's marketing. |

---

## 2. Cryptographic protocol (fragment version `0x01`)

Everything in this section runs in the client. The server performs no cryptography on secrets beyond SHA-256 of credentials it receives.

### 2.1 Primitives

| Purpose | Algorithm | Standard |
|---|---|---|
| Key derivation from the seed | HKDF-SHA-256 | RFC 5869 |
| Passphrase key derivation | Argon2id | RFC 9106 |
| Content and key-wrap AEAD | AES-256-GCM | NIST SP 800-38D |
| Credential hashing at rest | SHA-256 | FIPS 180-4 |
| Randomness | `crypto.getRandomValues` | W3C Web Crypto |

No public-key cryptography. There is nothing to migrate for post-quantum: AES-256 keeps ~128-bit strength under Grover, and all identifiers derive from a 256-bit seed.

### 2.2 Seed and fragment

- `seed`: 32 random bytes. Lives only in the URL fragment.
- Fragment = `kind(1) ‖ payload(32)` = 33 bytes = 44 base64url characters. Share link: `https://host/s#<fragment>`; the server redirects `/s` to the visitor's language and the browser carries the fragment across. When the website is disabled (`SHH_WEB=api`) the frontend performs this redirect.
- The kind byte names both the suite (KDF, AEAD, chunking, blob layout, container format) and the fragment's role:

  | kind | fragment | payload |
  |---|---|---|
  | `0x01` | share link `https://host/s#…` | seed |
  | `0x02` | burn link `https://host/burn#…` | burn token |

  A client given a fragment of the wrong kind for the page or function it is on refuses before deriving or sending anything. Future suites allocate a new pair of kind bytes. The blob carries no version and no flags.

### 2.3 Derivations

```
lookup     = HKDF(seed, salt = ∅, info = "shhnote/lookup/v1")      → 32 bytes
KEK_direct = HKDF(seed, salt = ∅, info = "shhnote/kek-direct/v1")  → 32 bytes
pass_key   = Argon2id(passphrase, salt, m, t, p)                   → 32 bytes
KEK_pass   = HKDF(seed ‖ pass_key, salt = ∅, info = "shhnote/kek-pass/v1") → 32 bytes
```

The three info strings are frozen; changing one is a version bump. `lookup` is sent to the server; the server stores only `SHA-256(lookup)` (D-3).

### 2.4 Content key and wrapping

- `EK`: 32 random bytes, fresh per secret, never derived from the seed.
- `wrapped_EK = AES-256-GCM(EK, key = KEK, iv = wrap_iv)` where `wrap_iv` is 12 random bytes and KEK is `KEK_direct` or `KEK_pass`.
- In the browser, use Web Crypto `deriveKey`/`wrapKey`/`unwrapKey` so KEK and EK are non-extractable keys and never exist as raw bytes in JavaScript. The seed, and for passphrase secrets the Argon2 output until it is consumed by `deriveKey`, are the only raw key material in JavaScript; both are overwritten when the page is left (best effort).

### 2.5 Payload container (inside the encryption)

```
payload  = [ manifest_len : u32 BE ] [ manifest : UTF-8 JSON ] [ file bytes, concatenated in manifest order ]
manifest = { "v": 1, "text": "…" | null, "files": [ { "name": "…", "type": "…", "size": n }, … ] }
```

- At least one of `text` / a file must be present.
- `size` is the exact byte length of each file; the client slices file bytes by cumulative offset.
- Manifest limit 1 MiB; text limit is a UI default (64 KiB) advertised by the API, not a protocol rule.
- File names are untrusted display data on the receiving side (render with `textContent`, sanitise before use as a download name).

### 2.6 Padding

```
padded = [ payload_len : u32 BE ] [ payload ] [ 0x00 fill to bucket ]
```

- `bucket` is the padded size chosen by the instance's padding policy (§6) for `payload_len + 4`.
- On decrypt, reject if `payload_len > bucket − 4`. Decryption never needs the policy.
- No compression anywhere, ever (compression before encryption leaks length).

### 2.7 Chunked content encryption

The padded plaintext is split into 64 KiB chunks (the last chunk is shorter only if the bucket is not a multiple of 64 KiB). Each chunk is encrypted with AES-256-GCM under `EK`:

```
nonce_i    = nonce_prefix(7) ‖ i : u32 BE ‖ last : u8      (12 bytes)
chunk_ct_i = AES-256-GCM(chunk_i, key = EK, iv = nonce_i)  (chunk + 16-byte tag)
```

- `i` counts from 0; `last` is `0x01` on the final chunk, else `0x00`.
- On decrypt, chunks must arrive in order; a chunk with `last = 1` before the expected end, or no `last` chunk, is a truncation and the payload is rejected.
- `nonce_prefix` is 7 random bytes per secret. EK is unique per secret, so nonces never repeat.
- This lets the client encrypt while reading a file and decrypt while downloading, with memory bounded by the chunk size.

### 2.8 Blob layout

```
Offset  Size  Field
0       16    salt           Argon2id salt (random fill in direct mode)
16      4     argon_m        KiB, u32 BE
20      4     argon_t        u32 BE
24      4     argon_p        u32 BE
28      12    wrap_iv
40      48    wrapped_EK
88      7     nonce_prefix
95      …     chunks         ciphertext chunks, each with its own 16-byte tag
```

Blob length = `95 + bucket + 16 × ceil(bucket / 65536)`. For a given bucket every blob has exactly this length, direct or passphrase, text or file, so the server's length check is exact and blobs of one bucket are indistinguishable.

Direct-mode blobs carry a random salt and the current default `argon_*` values. There is no mode byte, no passphrase hash, no version, no flags.

### 2.9 Argon2id parameters

| | Default | Client-enforced bounds |
|---|---|---|
| `m` | 64 MiB | 8 MiB – 256 MiB |
| `t` | 3 | 1 – 8 |
| `p` | 1 | 1 – 4 |

Parameters outside the bounds mean a corrupt or hostile blob; reject before running the KDF. A blob at the top of the bounds makes the recipient's browser hold 256 MiB for the hash, and the WebAssembly memory stays grown until the page is left; on a low-memory device the grow can fail, which surfaces as the WebAssembly-unavailable message rather than a corrupt secret. Accepted: the bounds are the recipient's protection and the sender chose the cost. `p = 1` is deliberate: browsers (Tor Browser in particular) have no shared-memory threads, and extra lanes only help an attacker with a GPU. Parameters are stored per blob, so raising the defaults later needs no version bump.

### 2.10 Decryption flow

1. Parse the fragment; check the version.
2. Send `lookup`; receive the blob (streamed).
3. Parse the 95-byte header; validate Argon2 parameters.
4. Trial-unwrap `wrapped_EK` with `KEK_direct`. Success → direct mode. Failure → prompt for passphrase, derive `KEK_pass`, unwrap; failure → wrong passphrase, retry locally.
5. Decrypt chunks in order into the padded plaintext; verify the `last` flag.
6. Read `payload_len`, parse the manifest, slice files.

Wrong-passphrase retries cost no server round-trip. A false mode detection or false passphrase accept has probability 2⁻¹²⁸.

A passphrase, when present, is a non-empty string; both implementations reject an empty passphrase at the API boundary. User interfaces treat an empty input as no passphrase before calling the library.

### 2.11 Burn token

- `burn_token`: 32 random bytes, generated at creation, independent of the seed.
- Burn link: `https://host/burn#0x02 ‖ burn_token(32)` (44 chars, same locale redirect). The kind byte makes a burn fragment distinguishable from a share fragment on sight; the `/burn` page and `burnSecret` reject a `0x01` fragment, and the `/s` page and `revealSecret` reject a `0x02` fragment, without contacting the server. Shown once; not recoverable.
- The client sends `SHA-256(burn_token)` at creation; the server stores only the hash and resolves burns by hashing the presented token and looking up a unique index (a keyed lookup, no comparison, nothing to time).

### 2.12 Credential rule

For every credential the server holds (`lookup`, `burn_token`, claim token, API keys): the server stores `SHA-256(value)`; the client sends the hash when **registering** it and the preimage when **exercising** it; the server hashes what it receives and looks the row up by the hash. A database dump therefore contains nothing that can read, consume, destroy, or administer anything.

### 2.13 Versioning

Allocate a new pair of kind bytes for any change to: an algorithm, an HKDF info string, the chunking scheme, the blob layout, or the container format. Do **not** bump for: Argon2 parameter changes (self-describing) or ladder changes (instance policy, D-6).

### 2.14 Conformance vectors

`vectors/v1.json` (generated by `vectors/generate.py`, independent of both implementations) holds test vectors consumed by the Rust and TypeScript test suites: seed, burn token, optional passphrase, manifest and file bytes, every fixed "random" input (EK, salt, IVs, nonce prefix), the expected `lookup`, `SHA-256(lookup)`, `SHA-256(burn_token)`, header bytes, and the full blob. Passphrase vectors may use reduced Argon2 cost (within bounds); at least one uses the defaults. Every vector includes the burn fragment as well as the share fragment, and the reject cases include a share fragment presented as a burn fragment and vice versa. The reject cases also cover chunks out of order, a `last` flag on a middle chunk, a missing last chunk, truncation inside a chunk and a final fragment shorter than a tag, a header shorter than 95 bytes, `manifest_len` over 1 MiB or past the payload, file sizes that disagree with the remaining bytes, negative or fractional sizes, invalid UTF-8, a wrong manifest `v`, zero files with null text, `payload_len` of 0 or above `bucket − 4` on multi-chunk blobs, Argon2 parameters outside the bounds, and the parsing cases both implementations must refuse identically: a UTF-8 BOM before the manifest, duplicate keys, non-integer numbers, lone surrogates, a missing `text` key, and `null` file entries.

---

## 3. What the server stores

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

**Expiry grid (D-18).** On write, `expires_at = ceil((now + ttl) / g) × g` where `g` is 300 s for `ttl < 3600`, 3600 s for `ttl < 3 × 86400`, and 86400 s otherwise. The recipient is told nothing about remaining time (§5.2), so nothing visible changes; the creator receives at least the TTL asked for. The grid is part of the schema contract: a refactor that stores the exact second reintroduces a per-secret timestamp.

No `created_at`, no IPs, no counters, no foreign keys to anything, and in SQLite no rowid, so a dump cannot order secrets by creation (Principle 5, 8). Daily counters (`stats_daily`: created, viewed, burned, expired, removed, **reports** per UTC day), settings, and API keys live in their own tables and are never joined to `secrets`. There is no reports table (D-19). Lifetime totals are the sum of the daily rows; the number of active secrets is counted live. One table per migration.

---

## 4. API

All identifiers travel in POST bodies (or multipart fields), never in URLs. Base path is `/api/v1` on the site origin or `/v1` on the `api.` subdomain (D-11); CORS headers are sent for the site origin and for every entry in `allowed_origins` (D-26), on both routing modes. Credentials are never allowed; `Authorization` is an allowed request header so `user` keys work from another origin.

| Endpoint | Body | Success | Notes |
|---|---|---|---|
| `GET /health` | – | `200 {"status":"ok","version":…,"configured":…}` or `503 {"status":"degraded",…}` | Readiness: the database answers; `version` is the server version (D-27); `configured` is the setup state (D-29). `GET /` is liveness only. Never rate-limited, `no-store`. |
| `GET /config` | – | JSON: `fragment_version`, `padding` policy, `inline_max`, `max_blob_bytes`, `claim_window_secs`, TTL bounds, default and presets, `text_max_bytes`, `files_enabled`, `regions`, `server_version` (the crate version, a string), `web_mode` (`full` \| `api`) | Instance policy for clients and integrators. Nothing per-secret. |
| `POST /secrets` | multipart: `meta` JSON `{lookup_key, burn_key, lifetime, ttl_seconds}` then `blob` | `201`, empty | `meta` precedes `blob` so the server can validate before streaming; `meta` is read in bounded chunks and refused past 4 KiB. Blob length must match a ladder entry exactly. A `lookup_key` that already exists returns `201` and writes nothing (D-21). |
| `POST /secrets/reveal` | `{lookup, claim_token?}` | `200` blob stream; header `X-Shh-Claim-Token` on a single-view secret, nothing else on a TTL secret | Single-view: one conditional UPDATE claims the row; with `claim_token`, re-download within the window (§5). TTL: pure read. |
| `POST /secrets/confirm` | `{lookup, claim_token}` | `204` | Destroys the secret and increments `viewed`. |
| `POST /secrets/burn` | `{burn_token}` | `204` | Creator only (D-2). Increments `burned`. |
| `POST /reports` | `{lookup}` | `200`, fixed body | Automatic takedown; increments `reports`, and `removed` when a secret was destroyed (D-19). Uniform response. |

Every negative outcome on an endpoint that takes a secret credential returns the same `404` with the same body, after the same work. This includes bodies the framework would otherwise reject (malformed JSON, wrong types, missing fields, missing `Content-Type`): the handler takes the raw body, substitutes fresh random bytes for anything unparseable, and runs the full path. `/reports` always returns its fixed `200` and always performs the same statement sequence (counter upserts of `+0` or `+1`). Reveal and blob responses carry `Cache-Control: no-store`. `Retry-After` on a `429` is a constant that does not depend on the threshold.

Rate limiting is per endpoint and per client: a token bucket keyed by `HMAC-SHA256(salt, ip)` (IPv6 by /64), where the salt rotates every `salt_rotation_secs` and rotation clears every bucket, so nothing before a rotation can be linked to anything after. Only the socket peer is trusted unless it is listed in `SHH_TRUSTED_PROXIES`, in which case the nearest untrusted `X-Forwarded-For` hop is used. Peer addresses are canonicalised (IPv4-mapped IPv6 is treated as IPv4) before bucketing or proxy matching. All `X-Forwarded-For` header lines are joined before the walk from the right. When the bucket table is full, individual subjects are evicted; the table is never cleared except by salt rotation. The limit is answered with a generic `429` and a `Retry-After` that reveals no threshold. Requests may carry `Authorization: Bearer <api key>`; a `user` key switches rate limiting from the IP-derived key to `SHA-256(api key)` with the limits multiplied by `rate_user_multiplier`. Admin endpoints live under `/{locale}/admin` (pages, §8) and `/api/v1/admin/*` (JSON, `admin` scope). API keys never appear in `secrets` rows or in any join.

The §11 security headers are applied to every response, API and drain responses included.

---

## 5. Lifecycle (D-1)

The interstitial `/s` page is static and fetches nothing until the user acts; the reveal button responds only to a trusted pointer or keyboard activation (§5.1 residual). The scheduler runs every 60 s. Every terminal transition increments its counter and deletes the row (inline) or moves it to `pending_delete` (external) in one transaction; `pending_delete` rows are never served.

### 5.1 Single-view

1. **Claim.** Reveal runs one conditional `UPDATE` (`status = 'active'`, `lifetime = 'single_view'`, not expired → `status = 'claimed'`), storing `SHA-256(claim_token)` and `claim_expires_at = now + window` (default 15 minutes), rounded up to the next minute (D-18). Exactly one concurrent request wins. For an external blob the object is opened before the claim is committed; a missing object yields the uniform negative and leaves the row untouched. The response streams the blob with the raw claim token in a header. **The secret is consumed at this point**; the `viewed` counter increments when the row is destroyed (confirm or window expiry), since the day is the same either way.
2. **Re-download.** `POST /secrets/reveal {lookup, claim_token}` while the row is `claimed` and the window is open returns the blob again. Only the holder of the claim token can do this; everyone else gets the uniform negative. This is what makes a dropped download or a slow link cost nothing.
3. **Confirm.** `POST /secrets/confirm {lookup, claim_token}` destroys the row now (`viewed`).
4. **Window expiry.** The scheduler destroys `claimed` rows whose window has passed (`viewed`, since the bytes were served). Nothing ever reverts to `active`.

The window is per claimant, so its length does not delay anyone else; 15 minutes covers a large file over Tor and a slowly typed passphrase.

**Accepted residual:** a single-view secret whose reveal response was lost before any bytes reached the client, or that was revealed by an automated link scanner, is destroyed unread; the recipient sees the uniform negative and the sender resends. A recipient who cannot produce the passphrase has no second attempt beyond local retries. These are accepted so that an intercepted or scanned link is always visible as "already viewed" to the intended recipient. A browser driven by automation (a scanner that injects real input events, an extension with input access) can reveal a secret as a user would; the recipient then sees the uniform negative. Page scripts cannot: the reveal requires a trusted pointer or keyboard activation of the button (`click` with `isTrusted` and `detail > 0`, or a trusted key activation), not merely a trusted `submit`.

### 5.2 TTL

A pure read: `status = 'active'`, `lifetime = 'ttl'`, not expired. No claim, no write, no counter. The response says nothing about the remaining lifetime, and neither does the reveal page: a recipient is told only that a single-view secret is now destroyed, so everyone learns to keep what they were sent on the first read. That a TTL secret can be opened again is discovered, not announced.

### 5.3 Burn, report, expiry

Burn and report match `status = 'active'` only; a claimed secret is already consumed and its claimant may still be downloading. Expiry is enforced by the query predicate immediately and by the scheduler durably.

---

## 6. Storage tiers and padding (D-6)

### 6.1 Tiers

- Inline (database) is on by default; the `inline_enabled` setting turns it off so that every blob goes to the external tier (ignored, with a startup warning, when `SHH_STORAGE` is `inline`). `files_enabled` off hides the file input and makes the API refuse any blob above the padded size of the largest possible text secret (`2 × text_max_bytes + 1 KiB`, then padded) with `400 files_disabled`; size is the only lever the server has, since it cannot tell files from text. `SHH_STORAGE` selects `inline`, `local`, or `s3` for payloads above the inline ceiling (`SHH_INLINE_MAX`, default 2 MiB, applies to the padded size). Local and S3 are mutually exclusive.
- External payloads are proxied through the server in both directions. No presigned or direct object-store URLs.
- Blobs are stored as received; the server never parses beyond length.
- Tier guards: `SHH_LOCAL_MAX_TOTAL_BYTES` (disk ceiling) and `SHH_S3_MAX_TOTAL_BYTES` (cost breaker). The only hard, non-circumventable limits. They count every object the tier holds, parked deletes included, **and every byte currently being spooled (D-20)**; the check is made under one reservation so concurrent creates cannot jointly exceed the ceiling, and a create that would cross it is refused as soon as that is known, including mid-stream, with `507 storage_full`, while inline-sized secrets keep working.
- Receiving: a blob is read in chunks; while it fits the inline tier it stays in memory, and the moment it outgrows it the bytes go to a spool file (under the local root, or `SHH_SPOOL_PATH` for S3). The length, ladder and `files_disabled` checks run against the declared length before the first blob byte is spooled; the spool is capped at the declared length. The spool is moved into place (local, same filesystem, atomic rename) or streamed to S3 with a known length only after the whole blob has arrived and its length checked. The row is written last, so an object without a row is garbage, never a secret; if the row cannot be written the object is deleted again. A spool that is not finished is removed when the request ends.
- At startup the server lists the tier and deletes objects no row references. Spool files are `0600` in a `0700` directory; the blob directory is fsynced after rename. Object names are exactly 22 base64url characters.
- Serving: external objects are streamed through the server with `Content-Length` set from the bucket, `Cache-Control: no-store`.
- Object keys are `blobs/<16 random bytes, base64url>`, generated by the server; a key read back from the database is validated against that shape before it touches the filesystem or S3.
- S3 is spoken with a hand-written SigV4 client (path-style with `SHH_S3_ENDPOINT`, virtual-hosted on AWS without it; `UNSIGNED-PAYLOAD` for uploads, which is why the endpoint should be HTTPS in production). An `http://` endpoint is refused in production unless it is a loopback or private address. At startup the server reads the bucket's versioning state and refuses to start when it is enabled; services that do not implement that call get a warning instead.
- The S3 client applies connect, request and body timeouts; scrubbing runs in its own task with a bounded batch per tick.
- **Accepted residuals.** External-tier objects carry a modification time the server cannot fully control (S3 `LastModified`; local `ctime`), so an operator with object-store access learns when each large secret was created. Destruction is logical: ciphertext (never plaintext) may persist in SQLite WAL, Postgres dead tuples, filesystem free blocks and backups until overwritten. The server sets `journal_size_limit = 0` and truncates the WAL after each sweep; backups should use `VACUUM INTO` or `.backup`, not file copies. On Postgres a deleted row's bytes stay in the heap page (and in `pg_wal`, and in TOAST for large blobs) until `VACUUM` reuses the space, and `xmin`/`ctid` order rows by creation; operators who need the residue bounded run with aggressive autovacuum, short WAL retention and disk encryption (see the deployment guide).

### 6.2 Padding policy

The padded size is chosen by an instance setting, served by `GET /config`. The server accepts a blob only if its length corresponds to a valid padded size under the current policy. Decryption reads `payload_len` and never needs the policy, so the policy can change at any time without affecting stored secrets.

Settings: `padding_mode` (`padme` | `buckets`), `padding_min` (smallest padded size), `padding_ladder` (buckets mode only).

**`padme` (default).** Deterministic padding from Nikitin et al., *PURBs* (2019): for `L = max(payload_len + 4, padding_min)`,

```
E = floor(log2 L)            bits in L
S = floor(log2 E) + 1        bits kept
z = E − S
bucket = (L + 2^z − 1) & ~(2^z − 1)
```

Overhead is at most 12% and falls for larger inputs; the leakage is O(log log) bits. Around 1 MiB sizes are multiples of 32 KiB, around 64 MiB multiples of 2 MiB, around 1 GiB multiples of 32 MiB. Validation: a length `n ≥ padding_min` is valid iff `padme(n) == n`.

**`buckets`.** A fixed ladder; `bucket` is the smallest entry ≥ `L`. Reference ladder: `1 MiB, 2 MiB` inline, then `4, 16, 64 MiB`, then ×2 up to `SHH_EXTERNAL_MAX_OBJECT`. Coarser anonymity sets at the cost of up to 4× bloat.

**Rejected: random padding** (a random 5–20% added per secret). It hides only the exact size while leaking a tight range (enough to confirm a known file), gives every blob a unique length that fingerprints it across backups and captures, and is defeated by a second sample of the same content. Padmé gives comparable overhead with shared sizes and a proof.

Default `padding_min` is 64 KiB: a trivial upload per text secret, and every file under 64 KiB looks like text. `padding_min` is a floor: the instance may raise it but not set it below 64 KiB (D-6). In `buckets` mode the ladder must be strictly increasing and must not exceed `SHH_EXTERNAL_MAX_OBJECT`.

---

## 7. Configuration

### 7.1 Environment (`SHH_` prefix; read once at startup, validated before binding)

| Variable | Purpose |
|---|---|
| `SHH_ENV`, `SHH_DEBUG` | `local` / `production`; debug refused in production |
| `SHH_URL` | public base URL (scheme + host only) |
| `SHH_API_ROUTING` | `path` / `subdomain` (local always `path`) |
| `SHH_WEB` | `full` (default) / `api` (D-24) |
| `SHH_ADMIN_ROUTING` | `path` (default) / `subdomain` (D-25); `local` always `path` |
| `SHH_SECRET_KEY` | signs admin sessions and CSRF tokens |
| `SHH_HOST`, `SHH_PORT` | bind address |
| `SHH_LOG_LEVEL` | default `error`; no request or IP logging |
| `SHH_LOCALES` | Languages to offer, comma-separated. Unset: all built in (`en`, `de`) |
| `SHH_DEFAULT_LOCALE` | Landing language for visitors whose browser asks for none of the offered ones; must be offered. Unset: the first of `SHH_LOCALES` |
| `SHH_TRUSTED_PROXIES` | Addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For` is honoured; never `0.0.0.0`, `::` or a `/0`; prefixes shorter than /8 (v4) or /32 (v6), mapped and transition ranges, and non-network base addresses are rejected |
| `SHH_DB` | `sqlite` / `postgres` |
| `SHH_SQLITE_PATH`, `SHH_PG_*` | connection details |
| `SHH_STORAGE` | `inline` / `local` / `s3` |
| `SHH_INLINE_MAX` | largest padded size stored in the database (default 2 MiB, at most 64 MiB) |
| `SHH_LOCAL_PATH`, `SHH_LOCAL_MAX_TOTAL_BYTES` | local tier |
| `SHH_S3_BUCKET`, `SHH_S3_REGION`, `SHH_S3_ENDPOINT`, `SHH_S3_ACCESS_KEY_ID`, `SHH_S3_SECRET_ACCESS_KEY`, `SHH_S3_MAX_TOTAL_BYTES` | S3 tier; bucket versioning must be off |
| `SHH_SPOOL_PATH` | S3 tier only: a dedicated directory where uploads wait before going to the bucket (default `storage/spool`); only `*.part` files are removed at start |
| `SHH_EXTERNAL_MAX_OBJECT` | per-object cap for the external tier (at most 4 GiB) |
| `SHH_MAX_UPLOADS` | concurrent-upload cap (default 64) |
| `SHH_ADMIN_TOKEN` | bootstrap credential (D-9) |

In `api` mode the locale redirect and every public page return `404`; `/static/*` stays so a frontend without a build step can load `shh.js`, `shh-ui.js` and `argon2.wasm` from the instance.

Unknown `SHH_*` variables and variables for a disabled storage tier fail startup with the variable named. There is no server-side encryption key: the server encrypts nothing. The server applies header, idle and request timeouts and the concurrent-upload cap.

### 7.2 Database settings (code defaults; database holds overrides only)

Site name, contact and security emails, source-code link, TTL presets and default TTL (≤ 14 days), padding mode / minimum / ladder (§6.2), file secrets on/off (hides the input and caps the accepted size at a text-only secret), inline tier on/off, text size hint, rate-limit thresholds for anonymous and for `user`-key requests, salt-rotation interval, claim window, daily-stats retention (default 365 days; older days are folded into their year's 1 January row so totals are never lost; -1 never folds), regions list (D-12), whether creation requires a `user` key.

Every setting is range-checked as a whole: `padding_min ≥ 65536`, ladder monotone, `claim_window_secs` in `60..=86400`, `rate_user_multiplier ≥ 1`, every preset within `[min_ttl, max_ttl]`, `max_ttl ≤ 14 d` (refused, not clamped), `daily_retention_days ≥ 1` or `-1`, region and source URLs `https://` only (`http://` when `SHH_ENV` is `local`). `allowed_origins` is a list of `https://` origins (scheme + host, optional port; `http://` only when `SHH_ENV` is `local`), validated as origins, no wildcards, no paths. Arithmetic on settings is checked or saturating.

---

## 8. Admin and API keys

- **Bootstrap.** If `SHH_ADMIN_TOKEN` is set and no API key with `admin` scope exists, the token logs in to the admin panel. Once an admin key exists the token is ignored and a startup warning says so, so forgetting to unset it is harmless. A bootstrap session is bound to the hash of the token that created it and is invalid once any admin key exists; `reset-admin` does not revive earlier bootstrap sessions. Recovery: `shhnote reset-admin` deletes all admin keys so the token works again. Three more subcommands serve deployments: `shhnote init` generates `SHH_SECRET_KEY` and `SHH_ADMIN_TOKEN` and prints them as `KEY=value` lines, or with `--env <path>` writes them into that file (creating it, filling an empty key in place, appending a missing one, never overwriting a set value); `shhnote check` loads the configuration and pings the database; `shhnote health` asks the running server's `/health` endpoint (for container health checks without curl).
- **API keys.** 32 random bytes, shown once, stored as `SHA-256(key)` with a name, scopes, `created_at`, and `last_used_on` (UTC date, written at most once per day, D-23; keys are operator credentials, not secrets, so timestamps are allowed). Scopes: `admin` (panel and admin API) and `user` (raised create/reveal limits; required for creation only if the instance says so). Rate limiting for a keyed request uses `SHA-256(key)`; nothing records which key created which secret.
- **Sessions.** Logging in with an admin key (or the bootstrap token) sets a stateless session cookie, `HttpOnly; SameSite=Strict` (`Secure` in production), signed with HMAC-SHA-256 under `SHH_SECRET_KEY` and valid for 12 hours. It names only the key's hash, and every admin request re-checks that the key still exists with `admin` scope, so deleting a key ends its sessions immediately and bootstrap sessions end the moment an admin key is created; keys carry a `sessions_valid_after` timestamp so an operator can also end a key's sessions without deleting it. Forms carry a CSRF token derived from the session; a request without it gets 403. Logout requires the CSRF token. Login attempts are rate-limited per client (`rate_login_per_hour`).
- **Panel.** The panel is served at `/{locale}/admin` or on the `admin.` subdomain (D-25). In `subdomain` mode the path form is `404`. The session cookie is scoped to the host that serves the panel. It holds settings, aggregate stats (totals summed from the daily rows, the live active count, and the last 30 days), the daily report counts (part of stats), API keys. No per-secret data exists to show. Every admin response carries `Cache-Control: no-store`. Settings save and key creation respond with a redirect; the new key is shown once on the redirected page via a one-time server-side nonce (the login page when the key is the first admin key, since minting it ends the bootstrap session).
- **Settings form.** Every setting is submitted as a string (`Settings::as_strings`), validated as a whole, and only values that differ from the code defaults are written to the `settings` table; a value equal to the default deletes its row. Saving swaps the in-memory settings atomically, so limits, padding policy and the like apply to the next request without a restart.
- **Admin API.** `/api/v1/admin/{stats,settings,reports,keys,keys/delete}` mirror the panel as JSON, authenticated with `Authorization: Bearer <admin key>` (or the bootstrap token while no admin key exists, so a first key can be provisioned non-interactively). Settings are patched partially, validated as a whole, stored as overrides only and applied live. Failed authentications share the login rate limit; responses are `no-store`. Credentials are compared in constant time or looked up by hash; the login bucket is consulted before the lookup.
- **Keyed API requests.** `Authorization: Bearer <key>` with a `user` key moves rate limiting to the key's own bucket (`rate_user_multiplier` times the anonymous limits) and satisfies `require_api_key_for_create`; an unknown or `admin` key is treated as anonymous. Keys never affect what is stored about a secret.

---

## 9. Multi-region (D-12)

Settings hold a list of `{code, name, url}` sibling instances. When non-empty, the create page shows a quiet region selector directly below the create form (a one-line "Region: Europe" disclosure menu, not a banner), so users know they can choose without it competing with the form. The entry whose `url` matches `SHH_URL` is shown as the current one; choosing another navigates to that instance's URL. Instances share nothing; a link's host is its region. No cross-instance data of any kind.

---

## 10. Client (D-13, D-14)

- `client/` holds TypeScript sources in three layers: `crypto/` (fragment with kinds, HKDF, envelope, chunking, container, padding, blob parse/assemble, Argon2 bounds, streaming decode; no fetch, no DOM), `lib/` (the `Api` client, `createSecret`/`revealSecret`/`burnSecret` with claim-token retry and body-length cap, the Argon2 loader with prefetch and the WebAssembly-unavailable error, `sanitiseFileName`, `isUserActivation`, wipe helpers; no DOM), and `ui/` (the reference page controllers `wireCreate`, `wireReveal`, `wireBurn`, `wireReport`, `wireDropzone`, `wirePasswordToggles`, `wireCopy`, `wireTheme`; DOM, bound by `data-shh-*` attributes, strings injected, no CSS).
- Package: `@shhnote/client` on npm with entry points `/crypto`, the root (`crypto` + `lib`) and `/ui`, plus `argon2.wasm` as a package asset. Versioned independently of the server; compatibility is by `fragment_version` in `/config`.
- Served bundles: `app.js` (the built-in pages, entry `src/main.ts`), `shh.js` (the package root), `shh-ui.js` (the `/ui` entry), all built by `scripts/build-client.sh` into `crates/shhnote-server/static/` and embedded. `typescript`, `esbuild` and `@types/node` remain the only npm dependencies, dev-time only; nothing from npm ships to browsers. Tests run on Node's native type stripping, so the source avoids syntax that needs a compiler (parameter properties, enums, namespaces, decorators).
- Argon2id, key handling, CSP and the reveal rules are unchanged (D-14, D-22, §5): `crates/shhnote-argon2-wasm` compiles the Rust `argon2` crate to `wasm32-unknown-unknown` with a C-ABI export (`scripts/build-wasm.sh`, ~40 KB); the module is fetched same-origin, on every create and reveal. One implementation serves both sides; the vector suite is the tripwire. If WebAssembly is unavailable (Tor Browser at Safer), the client says so instead of reporting a corrupt secret.
- A frontend built on the package is expected to meet the frontend conformance checklist (`docs/frontend-conformance.md`): static interstitial, no request before a trusted activation, the CSP, no external origins, `argon2.wasm` prefetched, fragment scrubbed, download names sanitised, a clear failure when WebAssembly is unavailable. The built-in frontend and `shhnote.com` both meet it; the `/ui` controllers carry the per-page guards so a frontend that uses them meets the per-page items by construction.
- The content key is created as a Web Crypto key and wrapped with `wrapKey`, which requires it to be extractable; nothing ever calls `exportKey` on it. The KEK is derived with `deriveKey` and is never extractable; on the receiving side the content key comes out of `unwrapKey` non-extractable. The seed, and for passphrase secrets the Argon2 output until it is consumed by `deriveKey`, are the only raw key material in JavaScript; both are overwritten when the page is left (best effort).
- Wrong-kind fragments (§2.2) are refused before any derivation.
- The client streams: it reads response headers before the body, keeps the claim token through any body or passphrase error, retries with it while the window is open, and refuses a body longer than the largest valid blob. Decryption runs chunk by chunk and files are assembled incrementally.
- Download names are normalised (NFC), stripped of control, bidi and path characters, capped in length, and rendered with `<bdi>`. Blob URLs are always `application/octet-stream`.
- Required CSP: `script-src 'self' 'wasm-unsafe-eval'`; no inline scripts or styles anywhere.
- The reveal page fetches nothing until a trusted user gesture; `history.replaceState` scrubs the fragment after reveal and burn; decrypted material is overwritten when the page is left (best effort — JavaScript cannot guarantee memory wiping, and the threat model says so).

---

## 11. Web layer

Routes under `/{locale}/`: `/` (create), `/s` (reveal interstitial, static), `/burn` (static until confirmed), `/report` (paste a link; the client derives the lookup value from its fragment and posts it, the page answers the same way whatever happened), `/how-it-works` (a short numbered explanation), `/about`, `/contact`, `/terms`, `/privacy`, `/security`, `/acceptable-use`, `/docs` (the public API only, Markdown with `{{site_url}}` and `{{api_url}}` placeholders; the admin API is documented in `docs/` in the repository), `/admin/*` (D-25). Paths without a locale redirect by `Accept-Language`; fragments survive the redirect. In `SHH_WEB=api` mode no public page is served. Every built-in page footer shows the server version (D-27) and, when set, `project_url` and `source_url`.

Headers on every response, including API, redirect, error and drain responses: CSP as above, HSTS (production), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`. All assets self-hosted; zero external-origin requests. No inline `style=` attributes (the CSP already blocks them). Startup prints nothing but through the log macros.

The visual layer lives in `templates/` (Askama) and `static/app.css`: a CSS-variable token system with four themes (light, dark, and a high-contrast variant of each, chosen per visitor and stored locally), semantic markup, self-hosted fonts, no inline scripts or styles. Copy rules that follow from the principles: fragment-only URLs (`/s#…`, `/burn#…`), no pricing or upgrade elements, no view-count or exact-size wording, no expiry information on the interstitial or on the reveal page (§5.2), and lifecycle wording that matches §5 ("revealed once, then gone"). Every page refers to the instance as "this site"; the site name and contact addresses come from settings; nothing names the hosted instance or its operator.

---

## 12. Principles

Two anchors resolve every conflict: **minimal attack surface** (fewer features, dependencies, code paths, and stored facts) and **privacy-maximal** (the server learns as little as physically possible; where awareness is unavoidable it is one-way, time-limited, unlinkable, or aggregate).

1. **The server never has access to secret contents.** All encryption and decryption happen client-side. No plaintext, key, seed, or passphrase ever reaches the server. No opt-in exception, ever.
2. **Every key and identifier is derived client-side.** The server generates nothing except the ephemeral claim token, which is a session credential, not an identifier.
3. **The fragment is the only carrier of secret identity.** Nothing identifying in URL paths or query strings; every API identifier travels in a request body.
4. **No user-identifying information is stored or logged.** No IPs, user agents, fingerprints, analytics, or third-party scripts. Rate limiting uses an HMAC of the IP under a rotating salt.
5. **No per-secret metadata leaks or is retained.** Uniform negative responses on every endpoint that takes a secret credential. No creation or access timestamps, no view counters, no terminal-status rows. Only aggregate counters, at most per day, never joined to secrets. (Per-day rather than per-hour: a bucket reveals volume, not a secret, but coarser is better on a low-traffic instance, and sequential backups already expose daily volume.)
6. **Secrets are destroyed, not flagged.** A terminal transition and its counter update happen in one transaction; the only non-active states are `claimed` and `pending_delete`, both time-bounded. A consumed secret is never served to anyone but its claimant.
7. **User-facing limits are best-effort; operator cost is hard-bounded.** Rate limits and size limits deter, they do not guarantee. Disk and object-storage ceilings are absolute because they bind the instance, not a user.
8. **v1 is identity-free.** No accounts. Any future account layer is additive, PII-free, and never joinable to secret rows. No foreign key from `secrets` to anything, ever.
9. **Works on every device and over Tor.** No CAPTCHAs, no fingerprinting, no reliance on APIs absent from privacy browsers. Client crypto cost is tuned to the weakest supported device.
10. **No external requests from the client.** Fonts, styles, scripts, and images are same-origin. No framework runtime.
11. **Minimal, auditable dependencies.** A single binary; a small, vetted crate set; three npm dev-dependencies and none at runtime. AGPL-3.0. The crypto module is isolated, DOM-free, and proven against shared vectors.
12. **Secure by default; usable once the operator has set a site name and a contact address.** A zero-configuration deployment is production-safe and, until those two are set and an admin key exists (D-29), serves only its admin panel. Relaxing a default is always an explicit step away from the baseline. The built-in website is a reference, not a product: an operator may replace it entirely with their own frontend against the API without losing any property above.
13. **Every feature must hold or reduce attack surface.** Reactive, content-agnostic takedown on report is the only moderation lever compatible with zero knowledge, and it is load-bearing once files are hosted.

---

## 13. Rejected by principle

Recorded so they are not re-proposed as new.

- **Per-secret `created_at` or access timestamps.** A correlation handle; daily aggregate counters answer the operational question.
- **Claim-then-revert single-view retrieval.** Lets an interceptor or scanner read a secret without the intended recipient ever learning it (replaced by D-1).
- **Terminal-status tombstones kept "for audit".** Retained access history; transactional counters make them unnecessary.
- **Raw credentials at rest** (lookup values, burn tokens, claim tokens, API keys). A dump must yield nothing usable.
- **Version or flags bytes in the blob.** The version lives in the fragment; a flags field invites mode indicators that would reveal passphrase use.
- **View-count caps.** A per-secret counter is retained history and the UX it needs leaks metadata. Exactly two lifetimes exist: single-view and TTL.
- **Server-side encryption, even as an option.**
- **Random padding.** Leaks a tight size range, fingerprints blobs by unique length, and fails under repeated samples (see §6.2).
- **Presigned or direct object-store URLs.** An external origin for the client and an identifier in a URL.
- **Compression before encryption.** Length leaks content.
- **Anonymous accounts as abuse control.** No Sybil resistance; gates nothing.
- **Reporter email or removal notifications.** A PII store and an existence oracle delivered by mail.
- **Proactive content scanning.** Impossible by design and not claimed.
- **CAPTCHAs or fingerprinting for rate limiting.** Break Tor and privacy browsers.
- **Per-report ledger rows.** A row keyed by a secret's hash with a time and an outcome is a tombstone whatever its retention; reports are a daily count (D-19).
- **Timestamps on API-key use finer than a day.** Joinable with the expiry grid (D-23).
- **Fragments of different roles sharing one shape.** A burn fragment must be distinguishable from a share fragment before it is sent (D-2).
- **Distinguishable duplicate-create responses.** An existence oracle (D-21).
