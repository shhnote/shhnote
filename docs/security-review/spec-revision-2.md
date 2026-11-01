# SPEC.md revision 2 — frontend split, web modes, client package

Status: draft for application. Follows the "Working procedure" in
`spec-revision.md`: one step at a time, stop, propose a commit message, wait
for "next". Same rules on scope, checks and "Noticed" lists.

Decisions taken (2026-11-01):
- The built-in website becomes a minimal reference frontend. The current
  design and its extra content move to a separate public repository
  (`shhnote/shhnote.com`, an Astro static site) that consumes the same client
  package. Nothing instance-specific ships in the binary.
- The client ships as one npm package, `@shhnote/client`, with three entry
  points: `/crypto` (pure protocol), the root (protocol + API client +
  frontend-safety helpers, no DOM), and `/ui` (the reference page
  controllers, DOM). The instance keeps serving `/static/shh.js` and
  `/static/shh-ui.js` for frontends without a build step.
- The server gains `SHH_WEB=full|api`, `SHH_ADMIN_ROUTING=path|subdomain`,
  an `allowed_origins` setting, and reports its version in `GET /config` and
  the footer.
- The default `how-it-works` page keeps the simple numbered explanation only.
- A first-run setup gate on the whole site and API (step 12) and a `shhnote init` subcommand (step 12b).

**Before step 8 deletes the current design**, make sure it is preserved for
the port: step 7 tags the last commit that carries it. The `.com` repository
starts from that tag.

---

## §1 Decisions

**D-13, rewrite:**
> Client code is TypeScript, published as one npm package `@shhnote/client`
> with three entry points, and also served by every instance as two bundles
> plus one WASM file. `@shhnote/client/crypto` is the pure protocol (no
> fetch, no DOM) and the unit the conformance vectors test; the package root
> adds the API client, streaming reveal and the frontend-safety helpers (no
> DOM); `@shhnote/client/ui` holds the reference page controllers (DOM). A
> third-party client takes the layer it needs.

**D-16, amend:** keep the list; add after it: "The built-in website is a
minimal reference frontend. Operators who want a different site run their
own frontend against the API (`SHH_WEB=api`) using the client package; the
binary carries no instance-specific content and no content overlay."

**Add:**

| ID | Decision | Why |
|---|---|---|
| D-24 | `SHH_WEB` selects `full` (website, API, admin, static) or `api` (API, admin and `/static/*` only; every other public route is `404`). | An operator with their own frontend should not expose a second one. |
| D-25 | The admin panel is routed like the API: `SHH_ADMIN_ROUTING=path` (`/{locale}/admin`) or `subdomain` (`admin.<host>/{locale}/`). | Operators choose where the panel is reachable; a subdomain is easy to firewall. |
| D-26 | `allowed_origins` is a settings list of origins the API answers to with CORS headers. Empty (the default) means the site origin only, as before. | A frontend on another origin needs it; nothing else does. |
| D-27 | The server version is public: in `GET /config`, in the footer of every built-in page, and in `/health`. | Open-source software with tagged releases; a visitor can see what an instance runs. |
| D-28 | The reference frontend is minimal: the create form, the reveal, burn and report pages, the policy pages, a short how-it-works, the public API docs, and the admin panel. Every page is written for "this site", with `{{site_name}}` and contact placeholders. | The binary is the same for every operator; nothing in it should read as one operator's marketing. |

## §4 API

- `GET /config` gains `server_version` (the crate version, a string) and
  `web_mode` (`full` | `api`).
- `GET /health` gains `version`.
- Replace "the subdomain variant sends CORS headers allowing the site origin
  only" with: "CORS headers are sent for the site origin and for every entry
  in `allowed_origins` (D-26), on both routing modes. Credentials are never
  allowed; `Authorization` is an allowed request header so `user` keys work
  from another origin."

## §7.1 Environment

Add rows:

| Variable | Purpose |
|---|---|
| `SHH_WEB` | `full` (default) / `api` (D-24) |
| `SHH_ADMIN_ROUTING` | `path` (default) / `subdomain` (D-25); `local` always `path` |

Note under the table: in `api` mode the locale redirect and every public
page return `404`; `/static/*` stays so a frontend without a build step can
load `shh.js`, `shh-ui.js` and `argon2.wasm` from the instance.

## §7.2 Database settings

Add `allowed_origins`: a list of `https://` origins (scheme + host, optional
port; `http://` only when `SHH_ENV` is `local`), validated as origins, no
wildcards, no paths.

## §8 Admin

Add: "The panel is served at `/{locale}/admin` or on the `admin.` subdomain
(D-25). In `subdomain` mode the path form is `404`. The session cookie is
scoped to the host that serves the panel."

## §10 Client

Rewrite the section:

> - `client/` holds TypeScript sources in three layers: `crypto/` (fragment
>   with kinds, HKDF, envelope, chunking, container, padding, blob
>   parse/assemble, Argon2 bounds, streaming decode; no fetch, no DOM),
>   `lib/` (the `Api` client, `createSecret`/`revealSecret`/`burnSecret`
>   with claim-token retry and body-length cap, the Argon2 loader with
>   prefetch and the WebAssembly-unavailable error, `sanitiseFileName`,
>   `isUserActivation`, wipe helpers; no DOM), and `ui/` (the reference
>   page controllers `wireCreate`, `wireReveal`, `wireBurn`, `wireReport`,
>   `wireDropzone`, `wirePasswordToggles`, `wireCopy`, `wireTheme`; DOM,
>   bound by `data-shh-*` attributes, strings injected, no CSS).
> - Package: `@shhnote/client` on npm with entry points `/crypto`, the root
>   (`crypto` + `lib`) and `/ui`, plus `argon2.wasm` as a package asset.
>   Versioned independently of the server; compatibility is by
>   `fragment_version` in `/config`.
> - Served bundles: `app.js` (the built-in pages, entry `src/main.ts`),
>   `shh.js` (the package root), `shh-ui.js` (the `/ui` entry), all built by
>   `scripts/build-client.sh` into `crates/shhnote-server/static/` and
>   embedded. `typescript`, `esbuild` and `@types/node` remain the only npm
>   dependencies, dev-time only.
> - Argon2id, key handling, CSP and the reveal rules are unchanged (D-14,
>   D-22, §5).
> - A frontend built on the package is expected to meet the frontend
>   conformance checklist (`docs/frontend-conformance.md`): static
>   interstitial, no request before a trusted activation, the CSP, no
>   external origins, `argon2.wasm` prefetched, fragment scrubbed, download
>   names sanitised, a clear failure when WebAssembly is unavailable. The
>   built-in frontend and `shhnote.com` both meet it; the `/ui` controllers
>   carry the per-page guards so a frontend that uses them meets the
>   per-page items by construction.

## §11 Web layer

- Route list: `/how-it-works` stays (short numbered explanation); remove any
  FAQ or detailed security pages from the list; `/docs` documents the public
  API only (the admin API is documented in `docs/` in the repo).
- Add: "Every built-in page footer shows the server version (D-27) and, when
  set, `project_url` and `source_url`."
- Copy rules: every page refers to the instance as "this site"; the site name
  and contact addresses come from settings; nothing names the hosted
  instance or its operator.
- Add: "In `SHH_WEB=api` mode no public page is served."

## §12 Principles

Principle 12, add a sentence: "The built-in website is a reference, not a
product: an operator may replace it entirely with their own frontend against
the API without losing any property above."

---

## Steps

| # | step | checks |
|---|---|---|
| 1 | Apply the `SPEC.md` edits above. | none |
| 2 | Client restructure, no behaviour change: create `client/src/lib/`; move `Api` out of `ui/api.ts` into `lib/api.ts`; move `argon2-loader.ts`, `filename.ts` into `lib/`; add `lib/activation.ts` (`isUserActivation(event)`: trusted `click` with `detail > 0`, trusted keyboard activation, `navigator.userActivation.isActive` when available; extracted from `wireReveal`) and `lib/wipe.ts` (extracted from `reveal.ts`); `ui/` imports from `lib/`. Add `src/crypto/index.ts` and `src/ui/index.ts`; `src/index.ts` becomes `crypto` + `lib`. | `npm test`, `npm run typecheck`, `cargo test -p shhnote-server` |
| 3 | `ui/` controllers take injected strings and a root element (`wireReveal(root, { t })`); `main.ts` passes the existing `i18n.t`. Bind by `data-shh-*` attributes instead of selectors; update templates accordingly. No visual change. | `npm test`, `cargo test` (template tests), manual click-through of create/reveal/burn/report |
| 4 | Build: `build-client.sh` emits `shh-ui.js` alongside `app.js` and `shh.js`; server serves `/static/shh-ui.js`; `build.rs` checks it. | `cargo test -p shhnote-server` |
| 5 | Package: `client/package.json` with `name: @shhnote/client`, `exports` map (`.`, `./crypto`, `./ui`, `./argon2.wasm`), `files`, `types`; a `scripts/pack-client.sh` that builds and runs `npm pack`; a `publish` job in `release.yml` using npm trusted publishing (OIDC, no token secret) on `v*` tags, after `ci`. Document in `README.md` under "Use the client in your own frontend". | `npm pack` produces a tarball that imports from a scratch project (`node -e "import('@shhnote/client/crypto')"` against the tarball) |
| 6 | Server: `SHH_WEB` (D-24). In `api` mode mount only the API router, admin, `/static/*`, `/health`; every other route `404` with the standard headers; `shhnote check` prints the mode. `GET /config` gains `web_mode`. | `cargo test`: a new `spec_api_mode_serves_no_pages` |
| 7 | Server: `SHH_ADMIN_ROUTING` (D-25), mirroring `SHH_API_ROUTING`; host matching, cookie host scope, `404` for the unselected form; Caddyfiles in `deploy/` gain the `admin.` matcher as an optional block; docs. **Tag `pre-minimal-frontend` on this commit**: the last one carrying the current design, for the `.com` port. | `cargo test`: `spec_admin_subdomain_routing` |
| 8 | Settings: `allowed_origins` (D-26) with validation; CORS middleware on the API router answering the site origin plus the list; preflight for `POST` with `Authorization` and `Content-Type`. | `cargo test`: `spec_cors_allowed_origins` |
| 9 | Version (D-27): `server_version` in `/config`, `version` in `/health`, `{{version}}` placeholder in content, footer line in `base.html`. | `cargo test` |
| 10a | Minimal frontend, content: remove the homepage extras, the FAQ and the detailed security breakdown; `how-it-works` becomes the simple numbered explanation; every remaining page says "this site", uses `{{site_name}}` and the contact placeholders; `docs.md` covers the public API only. Both locales. | `cargo test` (content/template tests); read every page once in both locales |
| 10b | Minimal frontend, theme: a neutral stylesheet with the same token names, the four themes, self-hosted fonts, phone-width layout; no inline styles. Templates lose decorative markup they no longer need. | `cargo test`; manual check in Firefox, Chromium, Tor Browser at Safer |
| 10c | Review tests and screenshots in `docs/` updated; `README.md` screenshots replaced. | `cargo clippy --all-targets`, `cargo fmt --check` |
| 11 | `docs/frontend-conformance.md`: the checklist from §10, one line each with how to verify it; `docs/deploy/own-frontend.md`: the two shapes (same-origin behind Caddy with `/api/*`, `/{locale}/admin*`, `/static/*` proxied; split origins with `api.` and `admin.` plus `allowed_origins`), and the Cloudflare proxied-DNS notes (features to turn off, Onion Routing on, origin firewalled to Cloudflare ranges, Authenticated Origin Pulls, `CF-Connecting-IP` via Caddy, and the sentence for the privacy page about a third party in the metadata path). | none |
| 12 | **First-run setup gate (decided 2026-11-01).** Setup is a derived state, never stored: an admin-scoped key exists, `site_name` is non-empty, and `contact_email` is non-empty. `site_name` loses its default (empty); `security_email` falls back to `contact_email` when blank, at the settings layer, so one address serves everywhere. While setup is unmet: `/health` answers normally with `configured: false`; `/{locale}/admin*` and `/static/*` are served; every other route, public pages and API alike, answers `503` — a setup page for HTML, `{"error":"not_configured"}` for JSON — with the full header set, `Cache-Control: no-store`, and never a word about whether a bootstrap token is set. The setup page names the three requirements and links to the admin login. Settings validation already refuses to clear a required field, so the gate cannot re-arm after first configuration. Add D-29 to §1 and amend Principle 12: "secure by default; usable once the operator has set a site name and a contact address". | `cargo test`: `spec_setup_gate` (gated routes, open routes, gate lifts after config) |
| 12b | `shhnote init`: generates `SHH_SECRET_KEY` and `SHH_ADMIN_TOKEN`; prints them as `KEY=value` lines, or with `--env <path>` writes them into that file (creates it, appends to an existing one only the keys it lacks, never overwrites a set value). `deploy/docker`, `deploy/systemd` and `docs/deploy/` use it as the first command. Add to §8 next to `check`, `health`, `reset-admin`. | `cargo test`: `spec_init_subcommand`; `shhnote init --env` against an existing file |
| 13 | Bump the workspace and client package to `0.2.0`; `CHANGELOG.md` entry for the release (user-visible: default theme, `SHH_WEB`, admin routing, client package). | `cargo test`, `npm test`; tag `v0.2.0-rc.1` after the human commits |
