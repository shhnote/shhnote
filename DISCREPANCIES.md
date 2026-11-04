# Documentation vs. code discrepancies

Audit of the docs, READMEs, SPEC, deploy guides, website content and project skills against
the code, as of commit `9c074c3` (2026-11-03). Nothing in the code or docs was changed.

**Status (2026-11-04):** every item below was worked through in revision 3
(`docs/security-review/spec-revision-3.md`, commits `ece4f56` to `8e2e11e`). Each one ends
with **Resolved** and the commit(s) that fixed it, or **Accepted** with the reason it stays.
Line numbers in the findings refer to `9c074c3`, not to the current tree. What revision 3
found and fixed beyond this audit is listed at the end.

How it was checked:

- The `@shhnote/client` findings (C1–C12) come from building the package into a scratch
  directory, listing the `npm pack` contents, importing each built entry in Node, running
  `npm test` (31/31 pass) and running the README example against a throwaway local server.
- The other findings come from reading both the doc and the code. H1–H3 and the cookie,
  deletion and admin-route claims were re-checked by hand. H2 (Docker `init` permissions)
  was reasoned from the code; Docker was not run.

Severity: **high** means a wrong API or protocol contract, a false security or privacy
claim, or a broken first-run step. **Medium** means a wrong name, default or behaviour a
user would run into. **Low** means wording, incompleteness or a stale reference.

---

## `@shhnote/client` package

### Verified correct

- **Tarball contents:** `npm pack` of a fresh `build:package` contains what the README
  claims:
  - `dist/` for all three entries (`.`, `/crypto`, `/ui`), with `.d.ts` files;
  - `argon2.wasm` (36.7 KB; SPEC says ~40 KB);
  - `LICENSE`, `README.md` and `package.json`.
  - `src/main.ts` and `test/` are correctly left out.
- **Exports:** every name listed in `client/README.md` and SPEC §10 is exported from the
  entry it is claimed for.
- **README example:** works as written. It creates a single-view secret and reveals
  `"the password is hunter2"`. The passphrase path with `Argon2.load(bytes)` and
  `burnSecret` also works.
- **Served bundles:** `/static/shh.js`, `/static/shh-ui.js` and `/static/argon2.wasm` are
  served (the last as `application/wasm`).
- **Translation keys:** `UiKey` in `client/src/ui/i18n.ts` matches `UI_KEYS` in
  `crates/shhnote-server/src/web.rs`.

### Discrepancies

| # | Sev | Claim | Reality | Status |
|---|---|---|---|---|
| C1 | **High** | `crates/shhnote-server/content/en/docs.md:112` (and `de/docs.md:112`): `const api = { apiBase: "{{api_url}}" };`. `client/src/client.ts:11`: base is `"https://example.com/api"` or `"https://api.example.com"`. | The base must include `/v1` (`api.rs:145` nests the routes under `/v1`; `Api` appends `/config`, `/secrets` directly). The rendered docs page shows `apiBase: "http://localhost:3917/api"`, and running `createSecret` with that base returned **404 `no_such_endpoint`**. The README, the tests and `base.html:17` correctly use `…/api/v1`. | Resolved: `ece4f56` (`docs.md`), `87e1cde` (`client.ts` comment). |
| C2 | Medium | `client/README.md` and SPEC §10: the package is "versioned independently of the server". | `scripts/bump-version.sh:9-10`: "the server and the client package are versioned in lockstep". `.github/workflows/release.yml:28` refuses a tag unless the Cargo and npm versions match. | Resolved: `c9a3302` (SPEC D-13, `client/README.md`), `b9bca8c` (`release.yml`). |
| C3 | Medium | `client/README.md`: "compatibility is by `fragment_version` in `GET /config`". | No code in the package reads `fragment_version`. `createSecret` fetches `/config` and ignores it; so does `wireCreate`. Checking it is left to the integrator, and that isn't documented. | Resolved: `0101b70` (`createSecret`/`revealSecret`), `ce082c8` (the `/ui` controllers). |
| C4 | Medium | `docs/frontend-conformance.md:41-42` (item 5, **by construction**): "Reload between attempts: the next attempt sends `claim_token`." | The claim token is only a JS variable (`client/src/ui/reveal.ts:43`); nothing writes it to session or local storage. After a reload it is gone, and the already-claimed single-view secret returns 404. | Resolved: `2289ba6` (claim token in `sessionStorage` for its window). |
| C5 | Medium | `client/README.md`: the `/ui` controllers have "no CSS, no markup of their own". | `reveal.ts` builds the file cards itself, with the built-in stylesheet's classes (`file-card`, `file-card__*`, `btn btn--ghost btn--sm`) and a `▣` icon. `dropzone.ts` builds `<li>`/`<span>`/`<button>` items and toggles an `is-dragging` class. | Resolved: `86a58b2` (templates, `data-shh-*` hooks only), `0dc080f` (`wireTabs`). |
| C6 | Medium | `/ui` is presented as usable by any frontend; `frontend-conformance.md` item 14 says to pass the wasm URL to `loadArgon2`/`prefetchArgon2`. | `wireCreate`/`wireReveal` hard-code `/static/argon2.wasm?v=…` (`client/src/ui/dom.ts`, `argon2Url`), so the URL can't be changed. They also need `data-shh-api`, `data-shh-max-blob-bytes` and `data-shh-asset-version` on an ancestor or `<body>`. None of that markup contract (attributes, `data-shh-state` sections, required children) is documented. | Resolved: `b20931e` (options with `data-shh-*` fallback), `0a9f1fb` (markup contract), `0dc080f` (`wireBurn`/`wireReport`). |
| C7 | Low | `client/src/client.ts` comment: "Any failure after a single-view secret was claimed … carries the claim token". | If `api.confirm()` fails after a successful decrypt, the `ApiError` thrown carries no `claimToken`, and the decrypted payload is discarded. | Resolved: `553429c`. |
| C8 | Low | SPEC §10: the seed (and Argon2 output) "are overwritten when the page is left". | Only the reveal page has a `pagehide` handler. `wireCreate` wipes nothing: `randomness.seed`, the burn token and the plaintext file bytes stay in memory. | Resolved: `553429c`. |
| C9 | Low | `frontend-conformance.md:27-30` (item 3): the fragment is scrubbed "after a reveal or a burn". | The burn page scrubs on success and on 404. The reveal page scrubs only on success; on a 404 the seed stays in the URL and history (`reveal.ts:103-104`). | Resolved: `553429c`. |
| C10 | Low | `client/README.md`: `revealSecret` has "claim-token retry, body-length cap". | Without `maxBlobBytes` the cap is `DEFAULT_MAX_BLOB_BYTES` (4 GiB), not the instance's `max_blob_bytes`; the README example passes none. Retrying is manual: the caller passes `claimToken` back itself. | Resolved: `abf5009` (cap from `/config`). Accepted: retrying stays the caller's job (the token is on the error, `client/README.md` says so); the `/ui` reveal page retries itself. |
| C11 | Low | The `InstanceConfig` type (`client/src/lib/api.ts`). | It lacks `regions`, `server_version` and `web_mode`, which `/config` returns. | Resolved: `87e1cde`. |
| C12 | Low | SPEC §10 places `createSecret`/`revealSecret`/`burnSecret` in `lib/`. | They live in `client/src/client.ts`. | Resolved: `c9a3302`. |

---

## High

### H1. Wrong `lookup_key` / `burn_key` values in the public API docs

- **Doc:** `crates/shhnote-server/content/en/docs.md:52-59` (and `de/docs.md:52-59`):
  `"lookup_key": "<base64url of the lookup value>"`,
  `"burn_key": "<base64url of the burn token>"`, "The server stores only their SHA-256."
- **Code:** `api.rs:329-331` decodes both keys and stores them as received; it never hashes
  them. Reveal and report hash the presented `lookup` (`api.rs:564`, `:709`), and burn hashes
  `burn_token` (`:681`).
- **What clients must actually send:** `SHA-256(lookup)` and `SHA-256(burn_token)`. That is
  what SPEC §3 (`SPEC.md:190-191`) and the bundled client (`client/src/crypto/secret.ts:116-117`)
  do.
- **Impact:** a third-party client that follows the docs stores raw lookup values, which
  breaks D-3, and none of its secrets can ever be revealed.
- **Resolved:** `ece4f56`, with a content test that fails if the hashing is described
  without `SHA-256`.

### H2. The Docker `init` step will fail on a Linux host

- **Docs:** `README.md:23`, `docs/deploy/docker.md:19` and `deploy/docker/.env.example:22`
  all run:
  `docker run --rm -v "$PWD/.env:/env" ghcr.io/shhnote/shhnote init --env /env`.
- **Code:** `Dockerfile:43` runs the image as `USER 65532:65532`, and `init.rs:68` rewrites
  the file in place with `fs::write`.
- **Why it fails:** the `.env` fetched with `curl -o` belongs to the host user and is
  mode 0644. UID 65532 can read it but not write it, so the first step of the quick start
  should fail with permission denied. (Not run under Docker.)
- **Resolved:** `dd464d2` (quick start prints to stdout, `--env` writes through a temp file).
  Confirmed with the image's user (UID 65532) before and after: the old form fails with
  "Permission denied", the new one works.

### H3. The README development steps are in the wrong order

- **Doc:** `README.md:42-43` runs `cargo run -p shhnote-server -- init --env .env` before
  `scripts/build-client.sh`.
- **Code:** `build.rs` refuses to compile until `shh.js`, `shh-ui.js`, `argon2.wasm` and
  `.stamp` exist, and a fresh clone has none of them. So the `init` step fails to build.
- **Resolved:** `7a6defa`.

---

## Medium

- **Single-view secrets are not deleted on open.**
  - Claims: `content/en/privacy.md:25`, `security.md:4`, `terms.md:11` and the how-it-works
    string `how-s-3-body` (`locales/en/main.ftl:157`).
  - Code: a reveal only marks the row `claimed` and keeps the blob (`shhnote-store/src/secrets.rs:139-147`).
    The blob is destroyed when the client sends confirm, or by the sweep once
    `claim_window_secs` ends (default 15 min).
  - Consequence: after a wrong passphrase, an abandoned prompt, or an API client that never
    confirms, the ciphertext stays for about 15 minutes.
  - **Resolved:** `8d86076` (the pages describe the claim and the window). The window
    itself is by design (SPEC §5): **accepted**.
- **Opening a TTL secret does not remove it.**
  - Claim: `home-step-3-body` (`main.ftl:67`): "When it is opened or expires, the secret is
    removed from the server for good."
  - Code: reading a TTL secret writes nothing (`secrets.rs:199-221`); it is removed only at
    expiry.
  - **Resolved:** `8d86076`.
- **The reference create form ignores the TTL settings.**
  - Code: the expiry `<select>` is hard-coded (`templates/home.html:113-123`), and
    `create.ts` never reads `ttl_presets`, `default_ttl_secs` or `max_ttl_secs`.
  - Claim it conflicts with: `docs.md:35` advertises `ttl_presets` for UIs.
  - Consequence: once an admin changes those settings, the site offers values the API rejects
    with `invalid_ttl`.
  - **Resolved:** `81d7a84`.
- **SPEC lists an admin `reports` endpoint that doesn't exist.**
  - SPEC.md:343: "`/api/v1/admin/{stats,settings,reports,keys,keys/delete}` mirror the
    panel".
  - `admin_api.rs:25-33` has no `/reports` route; report counts are a field of `/stats`.
  - The panel's "end a key's sessions" action (`admin.rs:51`) has no admin API equivalent.
  - **Resolved:** `9f8519e` (endpoint removed from SPEC; ending sessions documented as
    panel-only).
- **Wrong field name in the admin API docs.** `docs/admin-api.md:10` says `last_used_at`;
  the API returns `last_used_on` (`admin_api.rs:278`, as in SPEC D-23). Neither the doc nor
  SPEC says these are unix-second integers.
  **Resolved:** `9f8519e`.
- **The ladder isn't checked against `SHH_EXTERNAL_MAX_OBJECT`.** SPEC.md:292 says the ladder
  "must not exceed" it; `settings.rs:383-396` checks only order and the 64 KiB floor. Ladder
  entries above the limit are accepted, and uploads of those sizes later fail with 413.
  **Resolved:** `e3f37ee` (refused on save, ignored with a warning at startup), documented
  in `8c306a9`.
- **The padded-length check runs after spooling.** SPEC.md:263 says the length, ladder and
  `files_disabled` checks all run "before the first blob byte is spooled". The padded-size
  check (`api.rs:412-415`) runs only after the whole blob has arrived.
  **Resolved:** `087070d`; SPEC §4/§6.1 define the declared length in `8c306a9`.
- **The "listening" line never prints with the shipped settings.**
  - Docs: `docs/deploy/docker.md:32` (`"listening on http://0.0.0.0:3000"`) and
    `operations.md:87` say to watch for it.
  - Code: `main.rs:147` logs it at info level as `listening on 0.0.0.0:3000`, with no
    `http://`.
  - Every deploy example sets `SHH_LOG_LEVEL=warn`, so the line never appears.
  - **Resolved:** `772c8cb` (the guides check `shhnote health` / `docker compose ps` and
    quote the exact line and its level).
- **The Fly and bare-metal guides leave the site at 503.**
  - Docs: `docs/deploy/fly.md:19` and `bare-metal.md` say to create an admin key and remove
    the token, and stop there.
  - Code: the setup gate (`app.rs:103-121`, `api.rs` `is_configured`) also requires
    `site_name` and `contact_email`.
  - `docker.md` and `README.md` do mention this.
  - **Resolved:** `772c8cb`.

---

## Low

### Website content and privacy wording

All of these apply to the `de/` pages too; their facts match `en/`.

- **"No cookies":** stated in `privacy.md:31`, the `footer-notice` string (`main.ftl:24`) and
  `README.md:6` ("No accounts, no cookies"). The admin panel sets the `shh_admin` cookie
  (`admin.rs:159`), and the theme choice goes in `localStorage` (`client/src/ui/chrome.ts`).
  True for ordinary visitors only.
  **Resolved:** `7a6defa` (README), `8c306a9` (privacy page and footer).
- **"We count how many reports arrive each day, nothing else":** stated in
  `acceptable-use.md:26` and the `report-done-body` string. `report()` also bumps a daily
  `removed` counter (`secrets.rs:243-247`).
  **Resolved:** `8d86076`.
- **"The expiry time is rounded, so it can't be turned back into the creation time"**
  (`privacy.md:17`): with the public TTL presets and the 5 min / 1 h / 1 day grid
  (`core/src/expiry.rs`), creation time can be recovered to within that grid. The "What we
  store" list also leaves out `claim_expires_at` on claimed rows.
  **Resolved:** `8d86076` (the page names the grid), `8c306a9` (`claim_expires_at`). Recovering
  the creation time to within the grid is **accepted** (D-18).
- **"It's gone from the server. Nothing about it is kept."** (`burn-done-body`): externally
  stored blobs are parked as `pending_delete`, with both hashes, `bucket` and `expires_at`,
  until the scrubber removes them.
  **Resolved:** `8d86076`.
- **"The recipient then sees that it was already opened"** (`security.md:11`): the page
  deliberately shows the same "no secret found" message for every case.
  **Resolved:** `8d86076`.
- **"run by the operator named on the contact page"** (`about-body-3`): the contact page
  shows only email addresses, and no operator-name setting exists.
  **Resolved:** `8d86076` (the phrase is dropped).
- **Spec links:** "Specification" links (`how-spec`, `docs.md`) go to the repository root,
  not to `SPEC.md`.
  **Resolved:** `8d86076` (`{{spec_url}}`, built from `source_url`).
- **`SECURITY.md:79`** still contains "[security contact — fill in before publishing]".
  **Resolved:** `8d86076` (the line is gone; GitHub private reporting is the channel).
- **`SECURITY.md:69`** says every instance has a `/security` page. The route is
  `/{locale}/security`; bare `/security` redirects only with `SHH_WEB=full` and is 404 with
  `SHH_WEB=api`.
  **Resolved:** `8d86076`.

### API docs and SPEC wording

- **Incomplete examples:** the `/health` example (`docs.md:19`) leaves out `version` and
  `configured`; the `/config` example (`docs.md:25-40`) leaves out `server_version` and
  `web_mode`.
  **Resolved:** `ece4f56`.
- **Error code lists:**
  - `docs.md:63` leaves out `invalid_multipart` (400), `too_busy` (503), `request_timeout`
    (408) and `not_configured` (503).
  - `docs/admin-api.md` leaves out `invalid_json`, `invalid_key` and `no_such_key`, and
    doesn't name the `/api/v1` (or `api.` host `/v1`) base.
  - **Resolved:** `ece4f56` (`docs.md`), `9f8519e` (`admin-api.md`).
- **"`GET /` is liveness only"** (SPEC.md:214, `docs.md:19`): `GET /api/v1/` sits behind the
  setup gate (503 until configured) and returns `{"name","version"}`.
  **Resolved:** `c9a3302`.
- **Admin 429s:** SPEC.md:224 promises 429 with `Retry-After`. The admin API's 429
  (`admin_api.rs:39-43`) and the panel login's 429 (`admin.rs:273-274`) send no `Retry-After`.
  **Resolved:** `444f141`; SPEC wording in `8c306a9`.
- **`padding_min`:** in `buckets` mode it is silently reset to the default
  (`settings.rs:232-241`, `276-278`).
  **Resolved:** `e3f37ee`; the ladder is kept the same way in padme mode since `425b86e`.
- **Region URLs:** SPEC says `https://` only, but an empty region URL is accepted
  (`settings.rs:479`, reusing `web_url`).
  **Resolved:** `e3f37ee`.
- **Stray files stop startup:** a file in the blob directory that doesn't have the
  22-character name shape (e.g. `.DS_Store`) makes the orphan sweep return an error, and the
  server exits (`storage.rs:243-258`, `144`; `main.rs:119-121`). SPEC.md:264 says such objects
  are deleted.
  **Resolved:** `c96d0ca` (code), `c9a3302` (SPEC); on S3 too, tested in `8e2e11e`.
- **Spool directory mode:** SPEC.md:264 promises a `0700` spool directory, but the mode is
  set only when the server creates it. An existing `SHH_SPOOL_PATH` keeps its mode.
  **Resolved:** `2704680` (also the local `blobs/` and `tmp/`); documented in `8c306a9`.
- **S3 versioning warning:** SPEC.md:267 calls it a warning, but it is logged with
  `log_error!` (`storage.rs:537-549`).
  **Resolved:** `c9a3302` (SPEC now says it is logged at error level and the server starts).
- **Undocumented migrations:** `shhnote check` and `reset-admin` also run migrations
  (via `Store::connect`). SPEC.md:338 doesn't say so.
  **Resolved:** `c9a3302`.
- **SPEC §3 vs the migrations:** "One table per migration" doesn't hold (`0005` is an
  `ALTER TABLE`), and the `admin_state` table (`0006`) isn't mentioned.
  **Resolved:** `c9a3302`, `8c306a9` (forward-only, one concern each, one table per new
  migration).
- **"Active" counts:** they include `claimed` rows (`stats.rs:45-48`). This is deliberate,
  but SPEC words it as "active".
  **Resolved:** `c9a3302`.
- **"Match a ladder entry exactly"** (SPEC.md:216): padme mode has no ladder; the rule is
  "a valid padded size".
  **Resolved:** `c9a3302`.
- **Conformance item 17:** "API responses carry `Cache-Control: no-store`". Only blob
  responses, `/health`, the not-configured 503 and admin responses do; `/config`, `/reports`,
  204s and JSON errors don't.
  **Resolved:** `444f141` (every API response is `no-store`), `0a9f1fb` (item 17 reworded);
  the drain's 503 too since `fc5ca29`.
- **Conformance item 16:** "The instance sets them on everything it serves". HSTS is sent
  only when `SHH_ENV=production`.
  **Resolved:** `0a9f1fb`.

### Deploy docs and operations

- **`operations.md:37`** lists `SHH_ENV` as required; `config.rs:350` defaults it to
  `production`.
  **Resolved:** `772c8cb`.
- **`operations.md:72`:**
  - It says the token is ignored once you sign in with the key; in fact it stops working as
    soon as any admin key exists.
  - It says a warning is logged while the token is still set; in fact it is logged once, at
    startup (`main.rs:96-100`).
  - **Resolved:** `772c8cb`.
- **`operations.md:67`** says `shhnote health` asks `/api/v1/health`. Under subdomain routing
  it asks `/v1/health` with `Host: api.<host>` (`health.rs:13-14`).
  **Resolved:** `772c8cb`; the Fly example's health check notes it in `8c306a9`.
- **`own-frontend.md:66`:** shape 2 tells you to set `allowed_origins` to the `SHH_URL`
  origin, which `app.rs:203` already allows.
  **Resolved:** `9ad2f0d`.
- **`own-frontend.md` intro:** it offers the instance's `/static/shh*.js` bundles as an
  alternative. In shape 2 (split origins) they can't be loaded cross-origin (module scripts
  need CORS, and the CSP is `script-src 'self'`), so they would have to be copied.
  **Resolved:** `9ad2f0d`.
- **Stale 0.2 references:** `CHANGELOG.md:4` refers to "the security review that preceded
  0.2.0", but there is no 0.2.0 entry. `deploy/docker/docker-compose.yml:9` suggests pinning
  `:0.2`, a tag that was never published.
  **Resolved:** `772c8cb` (0.3.0 review reference, `:0.3` pin).
- **Unverified:** `docker.md:64` runs `docker compose --profile postgres up -d` while `.env`
  sets `COMPOSE_PROFILES=caddy`. If the flag replaces the variable, Caddy doesn't start.
  `docker.md:67`'s `COMPOSE_PROFILES=caddy,postgres` is the safe form.
  **Resolved:** `772c8cb` (the guide and the compose comment use only the safe form). How
  the flag and the variable combine was not tested.

### Repository, scripts, CLAUDE.md and skills

- **`static/app.js` is committed.** `.gitignore:31`, `build.rs:10` ("never committed") and
  CLAUDE.md all say it is generated and gitignored, yet it is tracked (last touched in
  `9d062f7`). It is currently identical to a fresh build.
  **Resolved:** `b9bca8c` (untracked).
- **`.dockerignore:15-17`** excludes `app.js`, `shh.js` and `argon2.wasm`, but not
  `shh-ui.js` or `.stamp`. Harmless, since the image build regenerates them.
  **Resolved:** `b9bca8c`.
- **`scripts/build-client.sh:2`** says "the two JavaScript bundles"; it builds three.
  **Resolved:** `b9bca8c`.
- **`.github/workflows/release.yml`:**
  - The comment at lines 110-112 describes the per-platform image build but sits above the
    npm `publish` job.
  - Line 116, "The client is versioned on its own", contradicts the lockstep check (see C2).
  - Lines 119-120, "Disabled until the first version is published… then restore the
    condition below", are stale: commit `9c074c3` already restored it.
  - **Resolved:** `b9bca8c`.
- **CLAUDE.md:**
  - The Commands section lists `check`, `health` and `reset-admin`, but not `init`.
  - "behind one storage trait": no trait exists. `Blobs` is a struct over a private
    `enum Tier` (`storage.rs:30-35`).
  - **Resolved:** `2ddb3f8`.
- **`.claude/skills/file-uploads/SKILL.md:36,43`** describes "One storage trait with put /
  get-stream / delete / exists". There is no trait and no `exists` method.
  **Resolved:** `2ddb3f8`.
- **`.claude/skills/i18n/SKILL.md`:**
  - Line 16 uses `/de/s/<id>` and `/s/<id>` as examples. The reveal route is `/s`, and the id
    travels only in the fragment.
  - Line 11 lists "how it works" as Markdown content; it is a template
    (`templates/how_it_works.html`).
  - **Resolved:** `2ddb3f8`.
- **`.claude/skills/web-page/SKILL.md`:**
  - Line 32 names the strings block `data-i18n`; the attribute is `data-shh-i18n`.
  - Line 31 mentions `<details>` for FAQs, which were removed (`CHANGELOG.md:44`).
  - **Resolved:** `2ddb3f8`.
- **`.claude/skills/database/SKILL.md:14`** suggests `sqlx migrate add -r`, which makes
  `.up.sql`/`.down.sql` pairs. The repo uses single forward-only files.
  **Resolved:** `2ddb3f8`, `8c306a9`.

### Code comments that contradict the code

- **`api.rs:699`:** "A malformed identifier is not notice, so it gets no ledger row". The
  handler swaps in random bytes, and `report()` counts it anyway.
  **Resolved:** `b9bca8c`.
- **`client/src/ui/report.ts:8`:** the server "keeps a ledger row either way". The store
  keeps only daily counters, with no per-report row (D-19).
  **Resolved:** `b9bca8c`.
- **`reveal.ts`:** "the ciphertext is never held whole". That holds for direct mode only;
  the passphrase path collects the whole body in memory (`collect(rest)`).
  **Resolved:** `b9bca8c`.

---

## Found during revision 3

Not in the audit above; fixed in the same revision.

- **CLAUDE.md placeholder list** lacked `{{spec_url}}` and `{{security_policy_url}}`, added
  for the spec links. **Resolved:** `2ddb3f8`.
- **Conformance item 15** had the origins backwards: it is the frontend's origin that goes in
  the instance's `allowed_origins`. **Resolved:** `8c306a9`.
- **Fly health check** (`fly.toml.example`) asks `/api/v1/health`, which misses under
  subdomain routing. **Resolved:** `8c306a9` (a comment says what to set). Fly's `headers`
  field was not checked against Fly's current docs.
- **`padding_ladder` was dropped** by any save while Padmé was in use. **Resolved:** `425b86e`.
- **The drain's "shutting down" 503** had no `Cache-Control: no-store`. **Resolved:** `fc5ca29`.
- **`wireBurn` and `wireReport`** took no options, the `/ui` helpers the reference pages use
  were not exported, and `wireTabs` set an `is-ready` class. **Resolved:** `0dc080f`.
- **The `/ui` controllers did not check `fragment_version`**; the reveal page also revealed
  without `/config` by falling back to 4 GiB. **Resolved:** `ce082c8`.
- **Admin durations were typed as seconds**, the presets as a comma-separated string.
  **Resolved:** `e13bb3f` (dropdowns in words, presets as checkboxes; the admin API still
  takes seconds).
- **The S3 orphan sweep and paged listing had no test without a real bucket.**
  **Resolved:** `8e2e11e` (an in-memory fake bucket).

Still open: `wirePasswordToggles` sets `data-shown`, the one controller hook outside the
`data-shh-*` namespace. Harmless; left for a later release.
