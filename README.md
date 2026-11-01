# shhnote

Zero-knowledge secret sharing: hand someone a password, a key or a file with a link that opens once, or expires, and then is gone. Everything is encrypted in the browser before it is uploaded; the server stores an opaque, padded blob and the hash of its identifier. It cannot read a secret, tell a file from a note, or say who created or opened what, and it keeps no logs that could.

- Text and files, single-view or time-limited (up to 14 days), optional passphrase
- No accounts, no cookies, no third-party requests; the share link carries the key in its fragment, which never reaches the server
- Padded blobs (Padmé) so sizes reveal nothing; uniform "not found" answers so probing reveals nothing
- Reports remove a secret without anyone seeing it; aggregate daily counters are the only statistics
- Admin panel and JSON admin API, rate limiting without storing addresses, multi-language UI
- One static binary; SQLite or PostgreSQL; blobs inline, on disk or on S3
- AGPL-3.0; the protocol is specified in [`SPEC.md`](SPEC.md) and pinned by test vectors

## Quick start (Docker)

You need a host with Docker, and a domain name pointing at it.

```sh
mkdir shhnote && cd shhnote
curl -fsSLO https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/Caddyfile
curl -fsSL https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/.env.example -o .env
# edit .env: DOMAIN, SHH_URL, SHH_SECRET_KEY, SHH_ADMIN_TOKEN
docker compose up -d
```

Caddy fetches the TLS certificate; the site is up at your domain and the admin panel at `/en/admin` (sign in with the bootstrap token, create an admin key, remove the token). Details and the other ways to run it:

- [Docker](docs/deploy/docker.md): compose with Caddy, with your own proxy, with Postgres
- [Bare metal](docs/deploy/bare-metal.md): release binary, systemd, an existing proxy and database
- [Fly.io](docs/deploy/fly.md): one app per region
- [Reverse proxies](docs/deploy/reverse-proxies.md) and [operations](docs/deploy/operations.md): configuration reference, backups, upgrades, storage tiers

## Development

Rust (stable, with the `wasm32-unknown-unknown` target) and Node 24.

```sh
cp .env.example .env            # SQLite and local addresses; set SHH_SECRET_KEY to any 32+ characters
scripts/build-client.sh         # Argon2 WASM module and the JavaScript bundles
cargo run -p shhnote-server     # http://localhost:3000
cargo test --workspace          # add SHH_TEST_PG_URL=postgres://… to cover Postgres too
```

The layout: `crates/shhnote-core` (protocol), `crates/shhnote-store` (database), `crates/shhnote-server` (API and website), `crates/shhnote-argon2-wasm` (Argon2id for browsers), `client/` (TypeScript: crypto library and page scripts). `vectors/v1.json` holds the conformance vectors both implementations must pass.

## API and clients

Everything the website does goes through the JSON API, documented on every instance at `/en/docs`. The `shh.js` module served at `/static/shh.js` implements the protocol for scripts and other clients; it runs in browsers and in Node.

## Use the client in your own frontend

The browser side is published as [`@shhnote/client`](https://www.npmjs.com/package/@shhnote/client), with three entry points: `@shhnote/client/crypto` (the protocol, no network, no DOM), `@shhnote/client` (adds the API client, `createSecret`/`revealSecret`/`burnSecret` and the frontend-safety helpers, still no DOM) and `@shhnote/client/ui` (the reference page controllers, which bind to `data-shh-*` attributes and take their strings from you). `@shhnote/client/argon2.wasm` is the Argon2id module to serve from your own origin. Every instance also serves the root and `/ui` entries as `/static/shh.js` and `/static/shh-ui.js` for frontends without a build step. `scripts/pack-client.sh` builds the package; releases publish it. A frontend built on it should meet `docs/frontend-conformance.md`.

## Licence

AGPL-3.0-only. See [`LICENSE`](LICENSE).
