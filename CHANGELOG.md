# Changelog

User-visible changes, newest first. The protocol is specified in `SPEC.md`; the security
review that preceded 0.2.0, with every finding and fix, has its own record in
`docs/security-review/CHANGELOG.md`.

## 0.2.0 — unreleased

The built-in website becomes a minimal reference frontend, the client becomes a package, and
an instance says who runs it before it serves anything.

### Added
- `@shhnote/client` on npm, with three entry points: `/crypto` (the protocol, no network, no
  DOM), the root (adds the API client, `createSecret`/`revealSecret`/`burnSecret` with
  claim-token retry and a body cap, and the frontend-safety helpers) and `/ui` (the reference
  page controllers, bound by `data-shh-*` attributes with injected strings). Every instance
  also serves the root and `/ui` entries as `/static/shh.js` and `/static/shh-ui.js`.
- `SHH_WEB=api`: serve the API, the admin panel and `/static/*` only, for operators who run
  their own frontend (`docs/deploy/own-frontend.md`, `docs/frontend-conformance.md`).
- `SHH_ADMIN_ROUTING=subdomain`: the admin panel on `admin.<host>/<locale>/` instead of
  `/<locale>/admin`, with a host-only session cookie.
- `allowed_origins` setting: other origins whose frontends may call the API from a browser;
  CORS is sent on both routing modes for the site origin plus the list.
- The server version on `GET /config` (`server_version`), `GET /health` (`version`), every
  page footer and the `{{version}}` content placeholder; `GET /config` also reports
  `web_mode`.
- First-run setup gate: until an admin key exists and the site has a name and a contact
  address, every public page and API call answers 503 with a setup page (or
  `not_configured` for the API); `/health` reports `configured`. The two settings cannot be
  cleared once set.
- `shhnote init`: generates `SHH_SECRET_KEY` and `SHH_ADMIN_TOKEN`, printed or written into
  an env file (`--env <path>`) without overwriting a set value. The deployment guides use it
  as the first command.
- `project_url` setting, shown in the footer and available to content pages as
  `{{project_url}}` (falling back to `source_url`); `{{site_name}}`, `{{contact_email}}`,
  `{{security_email}}` placeholders for the policy pages.
- Admin panel: "End sessions" on a key; `reset-admin` and a changed bootstrap token end
  earlier bootstrap sessions; settings save and key creation redirect, the new key is shown
  once.

### Changed
- The built-in website is a reference frontend: the create form, the reveal, burn and report
  pages, the policy pages, a short how-it-works and the public API docs. The marketing
  sections, the technical breakdown and the FAQs are gone; every page speaks of "this site"
  and takes the site name and contact addresses from settings. The admin API documentation
  moved to `docs/admin-api.md`.
- A neutral default theme: same four themes and token names, plain colours, self-hosted
  Inter, no decorative markup. A frontend with its own look builds on the client package.
- `site_name` has no default; `security_email` falls back to `contact_email`.
- An empty passphrase is refused by both libraries (`empty_passphrase`); omitting it is the
  only way to mean no passphrase.
- A TTL secret's reveal says nothing about its remaining time; single-view secrets keep
  their "destroyed" message.
- Dependencies trimmed (axum, tokio, sqlx features); crate metadata, `deny.toml`,
  `rust-toolchain.toml`; the release pipeline pins actions and images, builds reproducible
  archives and publishes provenance.

### Fixed
- Everything in the security review: see `docs/security-review/CHANGELOG.md`, where each
  finding is mapped to its commit.

## 0.1.0 — release candidates only (2026-10-29 to 2026-10-31)

The first version: end-to-end encrypted single-view or time-limited secrets, text and files,
optional passphrase, Padmé padding, uniform negatives, reports, rate limiting without stored
addresses, SQLite or Postgres, inline, local-disk or S3 blobs, an admin panel and admin API,
English and German. Tagged as `v0.1.0-rc.4` to `rc.6`; never released as `0.1.0`, since the
security review and this revision followed directly.
