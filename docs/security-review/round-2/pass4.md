# Pass 4 — Web layer, admin and authentication — findings (round 2)

Reviewed: `crates/shhnote-server/src/{app.rs,web.rs,admin.rs,admin_api.rs,api.rs (router, config, health, setup state, error shape),i18n.rs,content.rs,init.rs,health.rs,drain.rs,serve.rs,main.rs,ratelimit.rs (Peer, exhausted, check, limit)}`, `crates/shhnote-core/src/{config.rs,settings.rs}`, `crates/shhnote-store/src/api_keys.rs` (session revocation), every template in `templates/` (incl. `admin/`, `partials/`, `setup.html`), `locales/en/main.ftl` (setup and admin strings), `content/{en,de}/*.md` placeholder use, `deploy/docker/Caddyfile` (admin block), `client/src/{main.ts,client.ts,index.ts}`, `client/src/lib/{api.ts,activation.ts}`, `client/src/ui/{dom.ts,i18n.ts,reveal.ts,create.ts,burn.ts,report.ts,chrome.ts,claims.ts,tabs.ts,dropzone.ts}`; 2026-11-04.

Tooling run: `cargo 1.99.1`, `rustc 1.99.1`, axum 0.8.9, askama 0.16.1, dotenvy 0.15.7; Node v24.22.1 (no browser in this environment). Baseline: `/tmp/claude-1000/-mnt-d-code-projects-shhnote/e31c6633-f63c-4a55-997c-c95a7bf96064/scratchpad/baseline-tests.log`, third run (`cargo test --workspace --no-fail-fast`, 15:34–15:35 UTC) green on every crate including `spec_web` (16 passed), `spec_admin` (23 passed) and `spec_adversarial` (15 passed; its one failure in the second run was SQLite "disk is full" on the shared tmpfs, environmental); `npm test` 64/64 and `npm run typecheck` from the first run. My own:
- `cargo test -p shhnote-server --test review_r2_pass4 -- --test-threads=1 --nocapture` (11 passed, 3 `finding_*` fail by design; header table below is its output)
- `cargo clippy -p shhnote-server --test review_r2_pass4 -- -D warnings` clean; `rustfmt` applied
- `cd client && node --test test/review_r2_pass4.test.ts` (10/10), `npm run typecheck` clean

Test files written (left in place):
- `crates/shhnote-server/tests/review_r2_pass4.rs` — `review_*` tests pass and print what they observed; `finding_*` tests fail while their finding is open.
- `client/test/review_r2_pass4.test.ts`

## Findings

### F-4-1: S-39 regression — a bootstrap session comes back when the last admin key is deleted through the panel or the admin API
Severity: Low
Location: crates/shhnote-server/src/admin.rs:179-183 (`authenticate`: a bootstrap session is valid iff the token hash matches, `bootstrap_allowed` (no admin key right now) and `issued_at > bootstrap_sessions_valid_after`); crates/shhnote-store/src/api_keys.rs:100-106 (`delete_api_key` deletes the row and nothing else) vs api_keys.rs:140-152 (`delete_admin_keys`, used only by `reset-admin`, is the only writer of `admin_state.bootstrap_sessions_valid_after`); admin.rs:856-875 (`keys_delete`), admin_api.rs:370-379 (`keys_delete`)
Violates: SPEC §8 "A bootstrap session is bound to the hash of the token that created it and is invalid once any admin key exists; `reset-admin` does not revive earlier bootstrap sessions"; D-9 ("the token is retired"); CHANGELOG S-39.
What: The round-1 fix for S-39 records a revocation instant only in `delete_admin_keys` (`reset-admin`). A bootstrap cookie issued before the first admin key is refused while an admin key exists, but once the last admin key is deleted through the panel's "Delete" button or `POST /api/v1/admin/keys/delete`, `bootstrap_allowed` is true again, `bootstrap_sessions_valid_after` is still 0, and the old cookie is accepted for the rest of its 12 hours. An operator who keeps `SHH_ADMIN_TOKEN` set (the spec says forgetting it is harmless) and rotates keys by deleting the old one revives whoever captured the earlier bootstrap cookie. Needs a captured cookie younger than 12 h plus the deletion, so Low, as S-39 was.
Reproduction: `review_r2_pass4::finding_s39_bootstrap_session_revives_when_last_admin_key_is_deleted_in_panel_or_api`: bootstrap login → mint first admin key (old cookie now 303) → delete that key via the panel, and in a second instance via the admin API → `GET /en/admin` with the old cookie: `200 OK` both ways (expected 303). `review_session_csrf_login_regressions` prints the same (`old bootstrap cookie after the last admin key was deleted through the panel: 200 OK`).
Fix: Record `bootstrap_sessions_valid_after = now` whenever an admin-scoped key is deleted (in `delete_api_key` inside one transaction when the deleted key had `admin` scope, or in both `keys_delete` handlers when `admin_key_count()` reaches 0). Simplest and strictly stronger: bump it on every admin-key deletion. No spec change.

### F-4-2: `{{site_name}}` is substituted into the rendered content pages without HTML escaping
Severity: Low
Location: crates/shhnote-server/src/web.rs:630-647 (`doc_page`: `.replace("{{site_name}}", &settings.site_name)` on the already-rendered HTML; the same for `{{contact_email}}`/`{{security_email}}`/`{{project_url}}`/…); crates/shhnote-core/src/settings.rs:168-171 (`site_name` is stored verbatim, no validation); content/{en,de}/{terms,privacy,acceptable-use}.md (`{{site_name}}` in body text)
Violates: web-page skill ("Askama escapes HTML by default. Only use `|safe` for our own Markdown content from `content.rs`, never for anything from a user"); SPEC §11 ("no inline scripts or styles"); Principle 12 (secure by default); D-28/D-16 (the binary carries no instance-specific content: an admin may name the site, not inject markup into the policy pages)
What: Round 1 verified that the site name is escaped everywhere it is rendered through Askama. Revision 2 (step 10a) added `{{site_name}}` placeholders to the Markdown policy pages, and `doc_page` fills them by string replacement into HTML that is then emitted with `|safe`. Whatever an admin (or anyone holding an admin key, or whoever can write `settings.site_name` in the database) puts in the site name lands raw in `/{locale}/terms`, `/privacy` and `/acceptable-use`. The CSP blocks inline script and style, but not markup: `<meta http-equiv="refresh" content="0;url=https://evil.example">` inside `<body>` is honoured by browsers and is not a CSP-governed navigation, so the policy pages can be turned into a redirect; arbitrary phishing markup and `<a href="https://…">` links work too; a plain `&` in a name (`Tom & Jerry`) produces invalid HTML. `contact_email` and `security_email` are shaped by `email()` (no `"<>`, no whitespace) and the URLs by `web_url()` (`https://` prefix only, so `https://x/"><b>` would survive, but Askama is not involved there either), so today only `site_name` is a vector; the replacement itself is the bug.
Reproduction: `review_r2_pass4::finding_site_name_is_injected_unescaped_into_content_pages`: PATCH `site_name` to `Acme <b data-x="1">bold</b><meta http-equiv="refresh" content="0;url=https://evil.example">`; `GET /en/terms`, `/en/privacy`, `/en/acceptable-use`, `/de/terms` contain the raw `<b data-x="1">` and `<meta http-equiv="refresh"`; `/en` and `/en/admin/login` (Askama) show it escaped. `review_templates_escape_settings_and_version` confirms every Askama-rendered site: title, logo, region names/URLs, footer links and the `data-shh-i18n` block are escaped.
Fix: HTML-escape every substituted setting before `.replace` (askama's `escape` filter / a four-character escaper), or substitute the placeholders into the Markdown source before `pulldown-cmark` renders it so they become text nodes (then the `%7B%7B…%7D%7D` link variants are also unnecessary for text placeholders). Either way, keep `web_url`/`email` validation as the second line. No spec change.

### F-4-3: With `SHH_ADMIN_ROUTING=subdomain` the setup page's "Open the admin panel" link points at the main host, where it is dead
Severity: Low
Location: crates/shhnote-server/templates/setup.html:19 (`href="{{ ctx.admin_href("/login") }}"`); crates/shhnote-server/src/web.rs:128-131 (`admin_prefix` is `""` in subdomain mode) and web.rs:315-317 (`admin_href` → `/{locale}{prefix}{path}`, a path-relative link); app.rs:140-145 (the setup page is rendered for every host except the admin host)
Violates: D-29 ("a setup page for pages (naming the three requirements and linking the admin login …)"); SPEC §8 ("the panel is served … on the `admin.` subdomain (D-25). In `subdomain` mode the path form is `404`")
What: `admin_href` is written for links rendered on the panel's own host. The setup page is rendered on the main host (`example.com`), so its login link becomes `/en/login` on `example.com`, which the gate answers with the setup page again (503) and, once configured, with 404. The operator's first contact with a subdomain-routed instance is a page whose only call to action loops. Not a leak, but the one navigation D-29 promises is broken in one of the two supported modes.
Reproduction: `review_r2_pass4::finding_setup_page_login_link_is_dead_in_admin_subdomain_mode`: unconfigured instance, `SHH_URL=https://example.com`, admin subdomain; `GET example.com/en/s` → 503 with `href="/en/login"`; `GET example.com/en/login` → 503 (setup page). The walk tables below show the same (`F/adm main`, configured=false: every `/en/admin*` path is 503).
Fix: In subdomain mode render the panel link as an absolute URL built from `config.url`'s scheme and the configured admin host (`https://admin.example.com/{locale}/login`), on the setup page at least (a `Ctx::admin_url()` next to `admin_href`). No spec change.

### F-4-4: `shhnote init --env` treats `KEY = value` and `export KEY=value` as unset, appends a second definition, and the server then uses the new one
Severity: Low
Location: crates/shhnote-server/src/init.rs:54-55 (`line.trim_start().starts_with(&prefix)` with `prefix = "KEY="`), init.rs:63-65 (append when not found); crates/shhnote-core/src/config.rs:658-666 (`dotenvy::dotenv_iter` collected into a `HashMap`, so the later line wins)
Violates: SPEC §8 ("`--env <path>` … never overwriting a set value"); CLAUDE.md ("Never read or print values from `.env`" is honoured; the promise about not overwriting is not)
What: dotenvy accepts `SHH_SECRET_KEY = value` and `export SHH_SECRET_KEY=value`; `init` only recognises the exact `SHH_SECRET_KEY=` prefix. For either spelling it reports "appended" and adds a fresh line at the end, and because the server collects the file into a map, the appended value is the one in force. Running `init --env` a second time on a hand-edited file therefore silently rotates `SHH_SECRET_KEY` (every admin session and CSRF token dies) or `SHH_ADMIN_TOKEN` (the operator's token stops working; the new one is never shown, since the report prints no values). Operator-only, recoverable, hence Low.
Reproduction: `review_r2_pass4::review_init_env_edge_cases` (output in its log): a file with `SHH_SECRET_KEY = keep-…` and `export SHH_ADMIN_TOKEN=also-keep-…` → report says `appended` for both, file then holds two definitions of each. Second part: `.env` with `SHH_ADMIN_TOKEN = short` (invalid, 5 chars) → `init --env .env` appends a valid token → `shhnote check` prints `ok`, which it could only do if the appended line won (the original would fail the 32-character check).
Fix: Recognise what dotenvy recognises (optional `export `, whitespace around `=`, quoted values) when deciding "set", and refuse with an error when a key already appears in a form `init` cannot judge or more than once, instead of appending. No spec change.

## Suspicions

- **CORS preflight cache outlives an origin's removal.** `app.rs:234-237` sends `Access-Control-Max-Age: 86400`. After an operator removes an origin from `allowed_origins`, a browser that cached the preflight (Firefox honours up to 24 h, Chromium 2 h) still sends the actual `POST /secrets/reveal` with `Content-Type: application/json`; the response lacks `Access-Control-Allow-Origin` so the page cannot read it, but the server has already claimed the single-view secret. Needs a browser to confirm; a short `Max-Age` (minutes) or omitting it would close it. Low either way.
- **A forged `Host` reaches the admin router.** `review_admin_subdomain_host_matching_and_cookie_scope` shows a request to the listener with `Host: admin.example.com` (and an absolute-form request target naming the admin host) reaches the panel's login page whatever the proxy would have done. This is how host-based routing works and `deploy/docker/Caddyfile:12-18` keeps the `admin.` block, with its `remote_ip` allow-list, as a commented example. Clear if operators are told that the allow-list must be in a proxy that *also* rewrites or rejects unknown `Host` values and that the listener must not be reachable directly; `docs/deploy/reverse-proxies.md:7` says the first half. Not reproducible as a server bug.
- **`api` mode serves an HTML page while unconfigured.** D-24 says every public route in `api` mode is 404; D-29 makes the gate answer first, so an unconfigured `SHH_WEB=api` instance serves the HTML setup page (reference layout, links to pages that will 404) on `/`, `/s`, `/en/…` (walk table, `A/p/loc`, configured=false). Harmless and temporary; worth a sentence in D-29 or a JSON/plain 503 in `api` mode. Not a finding.
- **A database outage at startup looks like "not set up".** `api.rs:269-274` treats a failed `admin_key_count()` as "no key", so a configured instance whose database is unreachable at (re)start answers every public request with the setup page until the database comes back (`/health` says `degraded` and `configured:false` meanwhile). No leak, but the message is wrong; distinguishing `Err` from `Ok(0)` would fix it. Not reproduced with a real outage.

## Checked and clean

### Item 1 — headers on every route × mode

`review_header_walk_every_mode` fetched 86 requests (every page in both locales, every static asset, the locale and trailing-slash redirects, HEAD/OPTIONS/POST on pages, the admin pages and logout/login POSTs, every API endpoint including a malformed JSON body, the admin API with and without Bearer, `/api`, `/api/v2/…`) against 8 router configurations (`full`/`api` × admin `path`/`subdomain` × the host asked, plus the API subdomain host), each configured and unconfigured: 1 376 responses. **Every one carries CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy, and HSTS in production** (the test asserts it; zero missing). The drain's 503 is covered by `spec_web::spec_headers_shutdown_answer_is_no_store` (baseline green). CSP is unchanged from round 1 (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'[ <api origin>]; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`); no inline script, style or `on…=` on any page (`spec_web::spec_no_inline_styles_or_scripts_on_any_page`, green).

Full table for `SHH_ENV=production`, `SHH_WEB=full`, path routing, configured (`y` = header present; HSTS column `n/a` on local):

| request | status | CSP | HSTS | XFO | XCTO | RP | PP | Cache-Control |
|---|---|---|---|---|---|---|---|---|
| `GET example.com/en` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/s` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/en/burn` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/en/report` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/how-it-works` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/about` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/contact` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/terms` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/privacy` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/security` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/acceptable-use` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/docs` | 200 | y | y | y | y | y | y | - |
| `GET example.com/en/admin` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/en/admin/login` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/en/admin/settings` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/en/admin/keys` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/en/nope` | 404 | y | y | y | y | y | y | - |
| `GET example.com/de` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/s` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/de/burn` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/de/report` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/how-it-works` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/about` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/contact` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/terms` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/privacy` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/security` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/acceptable-use` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/docs` | 200 | y | y | y | y | y | y | - |
| `GET example.com/de/admin` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/de/admin/login` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/de/admin/settings` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/de/admin/keys` | 303 | y | y | y | y | y | y | no-store |
| `GET example.com/de/nope` | 404 | y | y | y | y | y | y | - |
| `GET example.com/` | 307 | y | y | y | y | y | y | - |
| `GET example.com/s` | 307 | y | y | y | y | y | y | - |
| `GET example.com/burn` | 307 | y | y | y | y | y | y | - |
| `GET example.com/report` | 307 | y | y | y | y | y | y | - |
| `GET example.com/en/` | 308 | y | y | y | y | y | y | no-store |
| `GET example.com/static/app.css?v=x` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/app.js` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/shh.js` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/shh-ui.js` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/argon2.wasm` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/fonts/geist.woff2` | 200 | y | y | y | y | y | y | public, max-age=31536000, immutable |
| `GET example.com/static/nope.js` | 404 | y | y | y | y | y | y | - |
| `GET example.com/static/../Cargo.toml` | 404 | y | y | y | y | y | y | - |
| `GET example.com/fr/s` | 307 | y | y | y | y | y | y | - |
| `HEAD example.com/en/s` | 200 | y | y | y | y | y | y | no-store |
| `OPTIONS example.com/en/s` | 405 | y | y | y | y | y | y | - |
| `POST example.com/en/terms` | 405 | y | y | y | y | y | y | - |
| `POST example.com/en/admin/logout` | 303 | y | y | y | y | y | y | no-store |
| `POST example.com/en/admin/login` | 401 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/config` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/health` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/secrets` | 405 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/secrets` | 400 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/secrets/reveal` | 404 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/secrets/reveal` | 404 | y | y | y | y | y | y | no-store |
| `OPTIONS example.com/api/v1/secrets/reveal` | 204 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/secrets/confirm` | 404 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/secrets/burn` | 404 | y | y | y | y | y | y | no-store |
| `POST example.com/api/v1/reports` | 200 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/admin/stats` | 401 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/admin/settings` | 401 | y | y | y | y | y | y | no-store |
| `PATCH example.com/api/v1/admin/settings` | 401 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/nope` | 404 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v1/` | 308 | y | y | y | y | y | y | no-store |
| `GET example.com/api/v2/config` | 404 | y | y | y | y | y | y | no-store |
| `GET example.com/api` | 404 | y | y | y | y | y | y | no-store |


Status codes for the same requests in every mode (every row had the full header set; `Cache-Control` was `no-store` on every API, admin, `/s`, `/burn`, 308 and 503 response, `public, max-age=31536000, immutable` on assets, absent on other pages and the 307 locale redirect). Columns: `F`/`A` = `SHH_WEB` full/api; `p` = admin path routing; `adm main`/`adm admin` = admin subdomain mode asked on the main / the admin host; `api host` = API subdomain mode asked on `api.example.com` (its rows use `/v1…` paths). Empty = not applicable.


#### configured=true

| request | F/p/loc | F/p/prod | F/adm main | F/adm admin | F/api host | A/p/loc | A/adm main | A/adm admin |
|---|---|---|---|---|---|---|---|---|
| `GET /en` | 200 | 200 | 200 | 303 | 404 | 404 | 404 | 303 |
| `GET /en/s` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/burn` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/report` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/how-it-works` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/about` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/contact` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/terms` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/privacy` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/security` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/acceptable-use` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/docs` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /en/admin` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /en/admin/login` | 200 | 200 | 404 | 404 | 404 | 200 | 404 | 404 |
| `GET /en/admin/settings` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /en/admin/keys` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /en/nope` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /de` | 200 | 200 | 200 | 303 | 404 | 404 | 404 | 303 |
| `GET /de/s` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/burn` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/report` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/how-it-works` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/about` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/contact` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/terms` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/privacy` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/security` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/acceptable-use` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/docs` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `GET /de/admin` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /de/admin/login` | 200 | 200 | 404 | 404 | 404 | 200 | 404 | 404 |
| `GET /de/admin/settings` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /de/admin/keys` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `GET /de/nope` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /` | 307 | 307 | 307 | 307 | 404 | 404 | 404 | 307 |
| `GET /s` | 307 | 307 | 307 | 307 | 404 | 404 | 404 | 307 |
| `GET /burn` | 307 | 307 | 307 | 307 | 404 | 404 | 404 | 307 |
| `GET /report` | 307 | 307 | 307 | 307 | 404 | 404 | 404 | 307 |
| `GET /en/` | 308 | 308 | 308 | 308 | 308 | 308 | 308 | 308 |
| `GET /static/app.css?v=x` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/app.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/shh.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/shh-ui.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/argon2.wasm` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/fonts/geist.woff2` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/nope.js` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /static/../Cargo.toml` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /fr/s` | 307 | 307 | 307 | 307 | 404 | 404 | 404 | 307 |
| `HEAD /en/s` | 200 | 200 | 200 | 404 | 404 | 404 | 404 | 404 |
| `OPTIONS /en/s` | 405 | 405 | 405 | 404 | 204 | 404 | 404 | 404 |
| `POST /en/terms` | 405 | 405 | 405 | 404 | 404 | 404 | 404 | 404 |
| `POST /en/admin/logout` | 303 | 303 | 404 | 404 | 404 | 303 | 404 | 404 |
| `POST /en/admin/login` | 401 | 401 | 404 | 404 | 404 | 401 | 404 | 404 |
| `GET /api/v1` | 200 | 200 | 200 | 307 |  | 200 | 200 | 307 |
| `GET /api/v1/config` | 200 | 200 | 200 | 307 |  | 200 | 200 | 307 |
| `GET /api/v1/health` | 200 | 200 | 200 | 307 |  | 200 | 200 | 307 |
| `GET /api/v1/secrets` | 405 | 405 | 405 | 307 |  | 405 | 405 | 307 |
| `POST /api/v1/secrets` | 400 | 400 | 400 | 307 |  | 400 | 400 | 307 |
| `POST /api/v1/secrets/reveal` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `OPTIONS /api/v1/secrets/reveal` | 204 | 204 | 204 | 307 |  | 204 | 204 | 307 |
| `POST /api/v1/secrets/confirm` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `POST /api/v1/secrets/burn` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `POST /api/v1/reports` | 200 | 200 | 200 | 307 |  | 200 | 200 | 307 |
| `GET /api/v1/admin/stats` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `GET /api/v1/admin/settings` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `PATCH /api/v1/admin/settings` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `GET /api/v1/nope` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `GET /api/v1/` | 308 | 308 | 308 | 308 |  | 308 | 308 | 308 |
| `GET /api/v2/config` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `GET /api` | 404 | 404 | 404 | 307 |  | 404 | 404 | 307 |
| `GET /v1` |  |  |  |  | 200 |  |  |  |
| `GET /v1/config` |  |  |  |  | 200 |  |  |  |
| `GET /v1/health` |  |  |  |  | 200 |  |  |  |
| `GET /v1/secrets` |  |  |  |  | 405 |  |  |  |
| `POST /v1/secrets` |  |  |  |  | 400 |  |  |  |
| `POST /v1/secrets/reveal` |  |  |  |  | 404 |  |  |  |
| `OPTIONS /v1/secrets/reveal` |  |  |  |  | 204 |  |  |  |
| `POST /v1/secrets/confirm` |  |  |  |  | 404 |  |  |  |
| `POST /v1/secrets/burn` |  |  |  |  | 404 |  |  |  |
| `POST /v1/reports` |  |  |  |  | 200 |  |  |  |
| `GET /v1/admin/stats` |  |  |  |  | 401 |  |  |  |
| `GET /v1/admin/settings` |  |  |  |  | 401 |  |  |  |
| `PATCH /v1/admin/settings` |  |  |  |  | 401 |  |  |  |
| `GET /v1/nope` |  |  |  |  | 404 |  |  |  |
| `GET /v1/` |  |  |  |  | 308 |  |  |  |
| `GET /v2/config` |  |  |  |  | 404 |  |  |  |

#### configured=false

| request | F/p/loc | F/p/prod | F/adm main | F/adm admin | F/api host | A/p/loc | A/adm main | A/adm admin |
|---|---|---|---|---|---|---|---|---|
| `GET /en` | 503 | 503 | 503 | 303 | 503 | 503 | 503 | 303 |
| `GET /en/s` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/burn` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/report` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/how-it-works` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/about` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/contact` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/terms` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/privacy` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/security` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/acceptable-use` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/docs` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /en/admin` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /en/admin/login` | 200 | 200 | 503 | 404 | 404 | 200 | 503 | 404 |
| `GET /en/admin/settings` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /en/admin/keys` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /en/nope` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de` | 503 | 503 | 503 | 303 | 503 | 503 | 503 | 303 |
| `GET /de/s` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/burn` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/report` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/how-it-works` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/about` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/contact` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/terms` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/privacy` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/security` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/acceptable-use` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/docs` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /de/admin` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /de/admin/login` | 200 | 200 | 503 | 404 | 404 | 200 | 503 | 404 |
| `GET /de/admin/settings` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /de/admin/keys` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `GET /de/nope` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `GET /` | 503 | 503 | 503 | 307 | 503 | 503 | 503 | 307 |
| `GET /s` | 503 | 503 | 503 | 307 | 503 | 503 | 503 | 307 |
| `GET /burn` | 503 | 503 | 503 | 307 | 503 | 503 | 503 | 307 |
| `GET /report` | 503 | 503 | 503 | 307 | 503 | 503 | 503 | 307 |
| `GET /en/` | 503 | 503 | 503 | 308 | 503 | 503 | 503 | 308 |
| `GET /static/app.css?v=x` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/app.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/shh.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/shh-ui.js` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/argon2.wasm` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/fonts/geist.woff2` | 200 | 200 | 200 | 200 | 404 | 200 | 200 | 200 |
| `GET /static/nope.js` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /static/../Cargo.toml` | 404 | 404 | 404 | 404 | 404 | 404 | 404 | 404 |
| `GET /fr/s` | 503 | 503 | 503 | 307 | 503 | 503 | 503 | 307 |
| `HEAD /en/s` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `OPTIONS /en/s` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `POST /en/terms` | 503 | 503 | 503 | 404 | 503 | 503 | 503 | 404 |
| `POST /en/admin/logout` | 303 | 303 | 503 | 404 | 404 | 303 | 503 | 404 |
| `POST /en/admin/login` | 401 | 401 | 503 | 404 | 404 | 401 | 503 | 404 |
| `GET /api/v1` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /api/v1/config` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /api/v1/health` | 200 | 200 | 200 | 307 |  | 200 | 200 | 307 |
| `GET /api/v1/secrets` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `POST /api/v1/secrets` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `POST /api/v1/secrets/reveal` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `OPTIONS /api/v1/secrets/reveal` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `POST /api/v1/secrets/confirm` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `POST /api/v1/secrets/burn` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `POST /api/v1/reports` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /api/v1/admin/stats` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `GET /api/v1/admin/settings` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `PATCH /api/v1/admin/settings` | 401 | 401 | 401 | 307 |  | 401 | 401 | 307 |
| `GET /api/v1/nope` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /api/v1/` | 503 | 503 | 503 | 308 |  | 503 | 503 | 308 |
| `GET /api/v2/config` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /api` | 503 | 503 | 503 | 307 |  | 503 | 503 | 307 |
| `GET /v1` |  |  |  |  | 503 |  |  |  |
| `GET /v1/config` |  |  |  |  | 503 |  |  |  |
| `GET /v1/health` |  |  |  |  | 200 |  |  |  |
| `GET /v1/secrets` |  |  |  |  | 503 |  |  |  |
| `POST /v1/secrets` |  |  |  |  | 503 |  |  |  |
| `POST /v1/secrets/reveal` |  |  |  |  | 503 |  |  |  |
| `OPTIONS /v1/secrets/reveal` |  |  |  |  | 503 |  |  |  |
| `POST /v1/secrets/confirm` |  |  |  |  | 503 |  |  |  |
| `POST /v1/secrets/burn` |  |  |  |  | 503 |  |  |  |
| `POST /v1/reports` |  |  |  |  | 503 |  |  |  |
| `GET /v1/admin/stats` |  |  |  |  | 401 |  |  |  |
| `GET /v1/admin/settings` |  |  |  |  | 401 |  |  |  |
| `PATCH /v1/admin/settings` |  |  |  |  | 401 |  |  |  |
| `GET /v1/nope` |  |  |  |  | 503 |  |  |  |
| `GET /v1/` |  |  |  |  | 503 |  |  |  |
| `GET /v2/config` |  |  |  |  | 503 |  |  |  |

What the table shows beyond the headers: in `api` mode no public page, no locale redirect and no `/` exist (404, bare `not found`, full header set); the admin host serves only the panel, `/static/*` and the locale redirect (`/api/v1/config` on it is a 307 to `/en/api/v1/config`, which is 404); the main host in admin-subdomain mode answers 404 for every `/{locale}/admin*` path; the API host answers 404 for pages and assets; unconfigured, exactly `/api/v1/health` (and `/v1/health`), the admin panel on its host, `/api/v1/admin/*` (401 without a key) and `/static/*` are open and everything else is 503.

### First-run setup gate (D-29)

- `review_setup_gate_closed_routes_in_every_mode`: in all four mode combinations, for GET/HEAD/POST/OPTIONS/PUT, every public page path (incl. `/`, `/s`, `/en/`, `/fr/s`, `/API/v1/config`) is 503 with the full header set and `Cache-Control: no-store`, the body is the setup page with no `<form>` and no mention of `SHH_ADMIN_TOKEN` or the token value; every API path (`/v1`, `/v1/`, `/v1/config`, `/v1/secrets/reveal`, `/v1/nope`, `/`, `/v2/x`, `/v1/health/x`, `/health`) is 503 `{"error":{"code":"not_configured",…}}` with `no-store` and the headers. `/v1/health` is 200 with `"configured":false`; `/v1/health/` is the usual 308. The admin login page renders on its host without the token. The admin API answers 401 (so a key can be provisioned non-interactively). `/static/*` is served on every host.
- Paths under an open prefix that match nothing (`/en/admin/../s`, `/en/admin/nope`, `/static/../en/s`, `/static/../Cargo.toml`): axum never normalises `..`, so these reach the router and get a 404 (the HTML error page in `full`/path mode, a bare 404 elsewhere). Nothing beyond the error page's static text is reachable; no public page can be reached through an open prefix.
- The admin host in subdomain mode is entirely open while unconfigured (by D-29): `/` → 307 `/en` → 303 `/en/login`; `/en/s`, `/en/admin` → 404; nothing public.
- The setup page renders `base.html` with the site name falling back to "shhnote", the footer version and the default source link: nothing instance-specific. Its `Vary: Accept-Language` is set. The 503 JSON is a constant.
- Re-arm: `review_setup_gate_rearm_after_restart` — deleting the last admin key leaves the running process configured (`Setup` is a sticky `AtomicBool`); a fresh router over the same database (what a restart does) is unconfigured again and answers 503. This matches D-29 ("derived while unmet and remembered once met"; "deleting the last admin key is the operator's own lockout"). Worth knowing for operators: `reset-admin` followed by a restart takes the public site down until a key exists again.
- `review_setup_cannot_be_cleared_by_panel_form` and `spec_admin::spec_setup_state_is_derived_and_sticky`: `site_name`/`contact_email` cannot be emptied or blanked (`""`, `"   "`, `null`) through the form or the API; a save that fails for another field changes nothing (whole-settings validation, `save_settings` writes only after `errors.is_empty()`).
- `security_email` falls back to `contact_email` at read time only; the stored value stays empty.

### `SHH_WEB=api` (D-24)

See the table. `review_header_walk_every_mode` and `spec_web::spec_api_mode_serves_no_pages`: 404 bodies are `not found` (text), not the HTML error page; headers present; `/config` reports `"web_mode":"api"`; `/en/admin/login` works; assets and `/health` work; trailing-slash 308 still runs (it is outside routing); HEAD/OPTIONS on page paths are 404.

### `SHH_ADMIN_ROUTING=subdomain` (D-25)

`review_admin_subdomain_host_matching_and_cookie_scope`:
- Host matching is case-insensitive and ignores the port (`ADMIN.Example.COM`, `admin.example.com:8443` select the panel); a trailing dot, a prefix/suffix (`xadmin.`, `.evil`), the main host, the API host and an empty Host do not (404 for `/en/login` and for `/en/admin/login`). HTTP/2-style absolute request targets are read from the URI, else `Host`.
- `Set-Cookie` on the admin host: `shh_admin=…; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200; Secure`, **no `Domain`**: host-only, so it is never sent to `example.com`. The same cookie presented on the main host hits no admin route (404), and the admin API refuses cookies outright (401 with `no-store`). A login POST on the main host is 404 and sets no cookie. The CSRF token is bound to the session nonce (HMAC), so it is only usable with the host-only cookie; a logout POST on the wrong host is 404.
- The admin host serves no API (`/api/v1/*`, `/v1/*` → 307 locale redirect → 404) and no public page; it serves `/static/*` and the login/dashboard flow. Admin templates link `/en/settings` etc. (subdomain form), never `/en/admin/…` (`spec_web::spec_admin_subdomain_routing`).
- Admin nav links use `admin_href` consistently; only the setup page (F-4-3) renders such a link on the wrong host.

### `allowed_origins` and CORS (D-26)

`review_cors_edges` and `spec_admin::spec_cors_allowed_origins`:
- Preflight `OPTIONS /api/v1/secrets/reveal` with `Origin: https://app.example`, `Access-Control-Request-Method: POST`, `Access-Control-Request-Headers: authorization, content-type` → 204 with `Access-Control-Allow-Origin: https://app.example`, `Allow-Methods: GET, POST, PATCH, OPTIONS`, `Allow-Headers: content-type, authorization`, `Expose-Headers: x-shh-claim-token, retry-after`, `Max-Age: 86400`, `Vary: Origin`, `no-store`, the full security header set. **`Access-Control-Allow-Credentials` never appears**, and the client sends `credentials: "omit"`.
- No CORS headers at all (only `Vary: Origin`) for: `Origin: null`, an origin with a trailing slash or a path, an unlisted origin, an unlisted port (`https://app.example:443`), a different scheme, `https://app.example.evil`, `https://example.com:443` (the site origin is matched as the literal `SHH_URL` origin). Matching is case-insensitive (`https://App.Example`, `https://EXAMPLE.com`); the site origin is allowed by default on both routing modes.
- The settings validator refuses paths, wildcards, `*`, a bare host, `javascript:`, userinfo, a non-numeric port, and `http://` outside `SHH_ENV=local` (`settings.rs` unit tests, green); a PATCH mixing a good `site_name` with a bad origin list is 422 and changes nothing.
- Website routes, the admin panel and `/static/*` never carry CORS headers (OPTIONS on a page is 405/404 with no ACAO). The CORS layer wraps the whole API router, admin API included: a listed origin may call `/api/v1/admin/*` with a Bearer key (preflight 204 + ACAO, real request 200 + ACAO). Since credentials are never allowed and admin keys live nowhere a page script could read them, this adds no reachable surface; it is consistent with §4 ("CORS headers are sent for the API"). Noted for the spec/synthesis: if the admin API should be same-origin only, exclude `/admin` from the layer.
- The OPTIONS short-circuit answers 204 for any path on the API router, without an Origin too, before the rate limiter and the gate's 503 inside it (the gate runs first, so an unconfigured instance answers 503 to preflights as well).

### Admin panel: duration dropdowns, preset checkboxes, padding preservation

`review_settings_form_crafted_durations_and_padding_preservation` posts the form directly (what a crafted POST can do): `claim_window_secs` 59 / 86401 / -1 / `1e3`, `max_ttl_secs` 14 d + 1, `min_ttl_secs` 59, a preset over 14 d or non-numeric, a default below the minimum, `min > default`, `salt_rotation_secs` 0, `padding_min` 65535, `buckets` with an empty ladder, a ladder above `SHH_INLINE_MAX` → all 422, the live settings untouched. Values in range but not in the dropdown (61 s) are accepted (SPEC §7.2 only bounds them) and offered back as a selected choice so the next save keeps them; duplicate presets are stored as given (`[61, 900, 900]`, harmless: the client dedups). A repeated scalar field is joined with a comma and refused; a doubled `csrf` field is 403. `padding_min` survives a save in buckets mode and `padding_ladder` a save in padme mode, through the panel in both directions. Unchecked checkboxes are "false"/empty list. The form's defaults column renders durations in words (`duration_label`), any value.

### Version (D-27), `/config`, footer, templates

`review_templates_escape_settings_and_version` and `spec_web::spec_server_version_is_public`: the version is the Cargo constant in `/config` (`server_version`), `/health` (`version`), the footer and the docs page; nothing admin-controlled is adjacent. With hostile `site_name`, region name/URL, `source_url` and `project_url` set, every Askama-rendered occurrence (title, logo, region menu, footer links, about/how-it-works links, contact page) is escaped (`&#60;…&#62;`, `&#34;`), the `data-shh-i18n` block contains no `<` and parses as JSON with only the `UI_KEYS` strings (none of which take a setting as an argument), `data-shh-api`/`data-shh-max-blob-bytes`/`data-shh-asset-version` come from config, the `<template data-shh-template>` elements are static. `/config` returns the region name verbatim inside JSON, which is correct for JSON. The exception is the Markdown placeholder path (F-4-2).

### Round-1 regression check

- **S-18** (admin `no-store`): every `/{locale}/admin*` response and every admin API response in the walk, 401/429 included, carries `Cache-Control: no-store` (layer on `admin::routes()` and on the admin API; plus the API-wide layer). Holds.
- **S-25** (headers on every response): 1 376 responses across 8 modes × configured/unconfigured, all with the five headers, HSTS in production, including 404s in `api` mode, the 307/308 redirects, the setup 503s and the drain 503. Holds.
- **S-26** (framework rejections take the uniform path): `POST /api/v1/secrets/reveal` with body `not json` → 404 JSON, same as a well-formed miss, in every mode. Holds.
- **S-27** (constant `Retry-After`): login 429 on the panel and the admin API say `60` (`review_login_limit_shared_and_checked_first`, `spec_web::spec_headers_admin_429s_carry_retry_after`). Holds.
- **S-29** (`unhex`): rejects non-hex, non-ASCII, wrong length before slicing (unit test in `admin.rs`; `spec_admin::spec_admin_key_delete_does_not_panic_on_non_ascii`). Holds.
- **S-37** (constant-time bootstrap compare on the API): `admin_api.rs:68-70` uses `constant_time_eq`. Holds.
- **S-38** (no inline styles): `spec_no_inline_styles_or_scripts_on_any_page` green; `setup.html` and the reworked admin templates use classes only. Holds.
- **S-39** (bootstrap sessions bound and ended): bound to the token hash (`spec_bootstrap_cookie_dies_with_token_rotation`), dead once a key exists, not revived by `reset-admin` (`spec_bootstrap_session_does_not_come_back`). **Regressed on one path**: revived by deleting the last admin key through the panel/API (F-4-1).
- **S-40** (CSRF on logout, end-sessions): `review_session_csrf_login_regressions` — settings, key create, key delete, end sessions and logout all 403 without or with a wrong token, 303-to-login without a cookie, and a token from another session is refused; "end sessions" kills the session, keeps the key working on the API, and a login in the same second is refused too (strict `>`, fail closed). Holds.
- **S-41** (login bucket before the lookup): web login refuses the right credential once limited (after 20 failures); the admin API with the right key from the same client is 429 too (shared `Endpoint::Login` bucket, `exhausted()` consulted first, charged only on failure). Holds.
- **S-42** (URL/email validation): `javascript:` region/source/project URLs and `a@b.c"><x` emails refused (core unit tests green); rendered links escaped. Holds.
- **S-43** (POST/redirect/GET, one-time key display): key creation redirects to `?new=<nonce>`; the key is shown once, only to the session whose nonce is bound to the parked key (another session gets the page without it), a second GET shows nothing; the first admin key goes to the login page since the bootstrap session has just ended; settings save redirects to `?saved`. Holds (`spec_admin::spec_key_create_resubmit_mints_nothing` too).
- **S-10** (settings ranges): the panel form path re-tested above; the API path by `spec_admin::spec_settings_patch_rejects_values_that_break_the_instance`. Holds.
- **S-1** (`/config` leak): the handler serialises from the `Arc` snapshot (`api.rs:217-240`); no `Box::leak`. Holds by reading; the memory test lives in `spec_memory` (baseline green).

### Session, CSRF, login (items 2–4, re-run after the rework)

- Session payload = `bootstrap(1) ‖ key_hash(32) ‖ issued_at(8) ‖ expires(8) ‖ nonce(16)`, HMAC-SHA-256 under `SHH_SECRET_KEY`, MAC checked in constant time before any field is read; tampered expiry, flipped flag, junk, and a cookie from another key are refused (`spec_admin::spec_tampered_and_foreign_cookies_are_rejected`). Expiry enforced server-side; 12 h; `HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`, `Secure` in production, no `Domain`.
- Every admin request re-checks the key (`find_api_key` + scope + `sessions_valid_after`) or, for bootstrap, the token hash + zero admin keys + `bootstrap_sessions_valid_after`. Deleting a key ends its sessions at once.
- CSRF = `HMAC(secret, "csrf" ‖ nonce)`, constant-time compared, required on all five POST routes; the admin JSON API takes only `Authorization: Bearer` (case-sensitive scheme, trimmed token, empty token refused) and ignores cookies, so it has no CSRF surface. A `user` key is refused on it; an admin key on a user route is anonymous (`spec_admin::spec_bearer_parsing_and_scopes`).
- Login: unknown credential and a valid `user` key give byte-identical 401 bodies; `touch_api_key` runs only on success; bootstrap compare constant-time; `Peer` falls back to 127.0.0.1 only for requests without `ConnectInfo` (tests), the server always inserts it (`serve.rs:49`).
- Fresh-key parking: 16 random bytes nonce, 60 s expiry, pruned on every park/take, bound to the session nonce; `Mutex` over a `Vec` only admins can grow.

### Other surfaces in scope

- **Locale redirect**: builds `/{locale}{path}[?query]` from a known-locale-stripped path; `/static/*` under it is a bare 404; `Vary: Accept-Language`; `spec_web::spec_assets_redirects_and_accept_language` (hostile `Accept-Language`, `//evil`, `\evil`) green. Trailing-slash 308 collapses leading `/` and `\`, keeps the query, is `no-store`.
- **`shhnote init`** (beyond F-4-4): values are 32 random bytes base64url (43 chars, above the 32 minimum), printed as `KEY=value` to stdout only in the no-argument form; `--env` writes a new file `0600` via `create_new` temp file + `rename` in the target's directory, preserves mode and (best effort) owner of an existing file, follows a symlink to its target, removes the temp file on failure and leaves the old file untouched (unit tests `rewrites_through_a_temp_file`, `a_failed_write_leaves_the_file_alone`, `spec_init::spec_init_subcommand`, all green); the report never prints values. The `Filled` branch slices at the ASCII prefix length after confirming the prefix, so no char-boundary panic.
- **Drain 503**: inside the header layer, `Connection: close`, `no-store` (`spec_headers_shutdown_answer_is_no_store`).
- **Client pieces in templates**: `data-shh-page` roots, `data-shh-form`, `data-shh-state` sections hidden by default, `<template data-shh-template="file-card"|"dropzone-item">` with `data-shh-*` hooks only; the controllers fill them with `textContent`/`replaceChildren` on cloned nodes and wrap file names in `<bdi>` (`reveal.ts:270-284`, `dropzone.ts:49-68`); `wireCopy` only toggles `data-shh-copied`. Reviewed: no `innerHTML` anywhere under `client/src/`.
- **Reveal page**: no request before a trusted pointer `click` with `detail > 0` or a trusted Enter/Space `keydown` on the button, with `navigator.userActivation.isActive` where the API exists; `submit` is always prevented (`activation.ts`, `reveal.ts:87-96`; `review_r2_pass4.test.ts` covers `button.click()`, `requestSubmit()`, untrusted events, `isActive=false`). `/config` is fetched only after the press, `fragment_version` checked before the reveal request, a missing config means "try again" without claiming, an unsupported version disables the button without claiming. The fragment is scrubbed on success and on 404. On `pagehide` the seed, buffered ciphertext and payload are wiped and the DOM cleared.
- **Claim token in `sessionStorage`** (SPEC §10): key `shh-claim:<base64url SHA-256(lookup)>`, value `{claimToken, expiresAt}`; stored with the maximal window first and shortened once `/config` answers; read before any request, deleted on confirm, expiry and 404; `prune()` removes only its own expired entries and ignores foreign or malformed ones; a storage that throws is tolerated (client review tests). Nothing else is written to storage; the theme choice goes to `localStorage` only.
- **`createT` / `data-shh-i18n`**: parsed with `JSON.parse`, used as a plain map (`strings[key] ?? key`), `{name}` substitution does not re-scan the inserted value; a `__proto__` key in the block does not pollute (client review test). The block is emitted with `<` escaped, so no translation can close the `<script>`.
- **`getConfig`**: cached per normalised base and per fetch implementation; a failed fetch is evicted; `Api` always sends `credentials: "omit"`, `cache: "no-store"`.
- **`ttlChoices`/`fillTtl`**: presets outside `[min_ttl, max_ttl]` are dropped; the select is filled from `/config` so the reference form cannot offer a value the API refuses.
- **Markdown renderer**: unchanged from round 1 (pulldown-cmark, tables + smart punctuation, raw HTML allowed, first-party content only); the placeholder substitution is the new element (F-4-2).
- **`last_used_on`** on the keys page and admin API is a date (`format_date`), never a time (D-23); shown only to admins.
