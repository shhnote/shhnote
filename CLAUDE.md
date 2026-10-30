# shhnote

`SPEC.md` is the authoritative description of the product and its protocol. Read it before changing anything that touches secrets, storage, the API or configuration; where code and spec disagree, the code is wrong. Conformance vectors in `vectors/` pin the protocol byte for byte.

Rust Cargo workspace. Crates live in `crates/` and are picked up automatically as workspace members.

- `crates/shhnote-core`: the protocol and shared logic, no web or database dependencies. `secret.rs` (encrypt/decrypt), `kdf.rs`, `fragment.rs`, `padding.rs`, `container.rs`, `blob.rs`, `chunks.rs` implement `SPEC.md` §2 and must keep passing `tests/vectors.rs`, which replays `vectors/v1.json`. Environment settings are loaded and checked in `config.rs`.
- `crates/shhnote-store`: persistence over sqlx's `Any` driver, one SQL text for SQLite and Postgres, with per-engine migrations in `migrations/sqlite/` and `migrations/postgres/`. Every secret operation from `SPEC.md` §5 is a method on `Store`, with narrow status predicates marked `// SECURITY:`.
- `crates/shhnote-argon2-wasm`: the Argon2id module for browsers, a thin C-ABI wrapper around the same `argon2` crate the core uses. Built by `scripts/build-wasm.sh` (never by `cargo build`); it must not depend on `shhnote-core`, whose dependencies don't build for wasm.
- `client/`: the TypeScript client. `src/crypto/` implements `SPEC.md` §2 with Web Crypto and the WASM module, has no DOM dependencies, and must keep passing `test/vectors.test.ts` (the same `vectors/v1.json` the Rust tests use). `src/ui/` holds the page flows (create, reveal, burn, dropzone, tabs); `src/main.ts` is the page bundle entry and `src/index.ts` the library entry. Only dev-dependencies (`typescript`, `esbuild`, `@types/node`); nothing from npm ships to browsers.
- `crates/shhnote-server`: axum web server. Static assets are embedded and served under `/static/<name>?v=<hash>`; the hash covers all of them, so change nothing about caching, just rebuild. `src/lib.rs` exposes the modules so `tests/api.rs` can drive the real router; `src/main.rs` only wires config, store, settings and the scheduler. `src/app.rs` combines the API (`src/api.rs`, SPEC §4) and website (`src/web.rs`) routers; `src/storage.rs` is the external blob tier (local disk and a hand-written SigV4 S3 client, see the `file-uploads` skill), `src/ratelimit.rs` is the per-endpoint limiter and `src/admin.rs` the admin panel under `/{lang}/admin` (SPEC §8: bootstrap token until the first admin key, signed cookie sessions, CSRF tokens, `shhnote reset-admin` for lockouts (the binary is named `shhnote`)). Askama templates are in `templates/` (see the `web-page` skill for the component vocabulary and the four-theme token system), translations in `locales/`, Markdown for the legal pages in `content/`, and CSS in `static/`.

The API is served at `/api` or on an `api.` subdomain, depending on `SHH_API_ROUTING` (local development always uses `/api`). Versions are always path-based (`/v1`), so API routes must never assume the `/api` prefix; links to the API are built from `config.api_url`. Secret identifiers travel only in request bodies and the URL fragment, never in paths or query strings.

## Stack

A public JSON API and a website, served from the same server.

- Web: axum. Templates: Askama.
- Database: sqlx, supporting both SQLite and PostgreSQL.
- Translations: Fluent (`.ftl` files via fluent-bundle) for UI text, per-language Markdown for long pages. Every page is under a language prefix (`/en/...`, `/de/...`).
- Blob storage: encrypted blobs inline in the database up to `SHH_INLINE_MAX`, larger ones on local disk or S3 (`SHH_STORAGE`), behind one storage trait. The server never sees plaintext, file names or exact sizes.

## Configuration

Settings live in one of two places.

**Environment variables** (`SHH_` prefix; `.env` in development), read once at startup and listed in `SPEC.md` §7.1. A setting goes here if it is needed before the database is available, is a credential, or is tied to the deployment. Unknown `SHH_*` variables and variables for a disabled storage tier fail startup. The server encrypts nothing itself, so there is no server-side encryption key.

`.env.example` lists every variable with a safe placeholder; keep it and the `KNOWN` list in `config.rs` in sync when adding one. Never read or print values from `.env`, since it holds credentials. Never store secrets in the database.

**Database settings** for everything else: site name, languages, registration, upload rules within the `.env` limits, feature toggles and the like.
- Every database setting is declared once in code with its type and default. That declaration is the only place a new setting is added.
- The database stores only values an admin has changed. A missing row means the default is used, so new settings never need a migration or seeder.
- Don't repeat defaults where a setting is used; always read the setting through the shared settings type.
- Settings are loaded into memory at startup and refreshed when an admin changes one, not queried per request. Code reads them through `SettingsCell::load()`, which returns a snapshot; never hold one across a save.
- `Settings::as_strings()` is the form and storage representation; the admin panel stores only entries that differ from the defaults.
- An invalid or unknown value in the database is logged and ignored, falling back to the default instead of failing startup.

Deployment artifacts live in `deploy/` (Docker Compose with Caddy, systemd unit, Fly config) and `docs/deploy/` (guides); the `Dockerfile` at the root builds both the image and the release binaries, and `.github/workflows/` runs the tests and publishes releases on `v*` tags.

Project skills in `.claude/skills/` hold the conventions for each area: `api-endpoint`, `web-page`, `database`, `i18n`, `file-uploads`.

## Commands

- Build: `scripts/build-client.sh` first (WASM module + JS bundles into `crates/shhnote-server/static/`, gitignored and embedded by `include_bytes!`; `build.rs` refuses to compile without them), then `cargo build`.
- Run server: `cargo run -p shhnote-server`. Subcommands: `check` (config + database ping), `health` (probes a running server), `reset-admin`. SIGTERM drains in-flight requests.
- Test: `cargo test` (SQLite always; set `SHH_TEST_PG_URL=postgres://…` to also run the store tests on Postgres, which clears that database's tables)
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --all`
- Client: `scripts/build-wasm.sh` (Argon2 module, needed by the tests), then in `client/`: `npm test` (runs the `.ts` tests directly on Node 24, no build step), `npm run typecheck`. `scripts/build-client.sh` does all of it plus the bundles.

## Rules

- Never commit, push, or create branches on your own. Leave changes uncommitted unless explicitly asked.
- Write modern, pragmatic Rust: current edition idioms, simple code over clever abstractions, no premature generics or traits.
- This is a privacy- and security-focused project, so keep dependencies to a minimum. Before adding a crate, check whether the standard library or an existing dependency already covers it, and say why the new one is worth it. Prefer small, well-maintained crates, and turn off default features that aren't needed. Ask before adding any crate that pulls in a large dependency tree.
- Use the latest stable versions of crates. Add dependencies with `cargo add` rather than guessing version numbers.
- Declare shared dependency versions in the root `Cargo.toml` under `[workspace.dependencies]`, and reference them from crates with `dep.workspace = true`.
- Do not write package- or module-level comments (`//!` or file header comments).
- Keep comments short and plain, so a Rust beginner can follow them. Explain why, not what the code obviously does. The same applies to TypeScript.
- TypeScript must stay runnable by Node's type stripping: no parameter properties, enums, namespaces or decorators; imports use explicit `.ts` extensions.
- Diagnostics in the server go through `crate::log_error!`, `log_warn!` and `log_info!` (honouring `SHH_LOG_LEVEL`), never `eprintln!`; nothing request- or user-specific is ever logged.
- Run `cargo fmt` and `cargo clippy` after changes and fix any warnings.
