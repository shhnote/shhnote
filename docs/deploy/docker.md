# Deploying with Docker

The image `ghcr.io/shhnote/shhnote` is built from `scratch`: one static binary, no shell, running as an unprivileged user, with all state under `/data`. The compose file in `deploy/docker/` runs it together with Caddy for TLS; Postgres is an optional profile.

## One command, with Caddy

Prerequisites: Docker with Compose v2, a domain whose DNS points at the host, ports 80 and 443 reachable.

```sh
mkdir shhnote && cd shhnote
curl -fsSLO https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/Caddyfile
(umask 077; curl -fsSL https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/docker/.env.example -o .env)
```

Let the image generate the two secrets and append them to `.env`, then edit the rest of it:

```sh
docker run --rm ghcr.io/shhnote/shhnote init >> .env
chmod 600 .env
```

`init` only prints `KEY=value` lines; your shell does the writing, so the container (which
runs as an unprivileged user) never needs access to a file on the host. The file holds the
session key, the bootstrap token and, with the Postgres or S3 profile, those credentials too,
so keep it readable by you alone: the `umask` above creates it that way and the `chmod` makes
sure.

| Variable | Value |
|---|---|
| `DOMAIN` | the site's domain, for Caddy's certificate |
| `SHH_URL` | `https://` plus the same domain |
| `SHH_SECRET_KEY`, `SHH_ADMIN_TOKEN` | appended by `init` above |

Then:

```sh
docker compose up -d
docker compose ps                   # shhnote shows "healthy" within a minute
```

Open `https://<domain>/en/admin`, sign in with the bootstrap token, create an admin API key under "API keys", sign in with it, and set the site name and contact address under "Settings": until then every public page answers 503 with a setup page and every public API call `503 not_configured`; only the admin panel, the admin API, `/static/*` and the health endpoint (`/api/v1/health`, or `/v1/health` on the API host) work. Then delete the `SHH_ADMIN_TOKEN` line from `.env` (the token stops working anyway once an admin key exists). Settings such as lifetimes and rate limits live in the admin panel too, not in `.env`.

## With your own reverse proxy

If nginx, Traefik or another Caddy already runs on the host, leave Caddy out and publish the port locally:

```sh
# in .env
COMPOSE_PROFILES=
```

```sh
docker compose -f docker-compose.yml -f compose.own-proxy.yml up -d
```

The app listens on `127.0.0.1:3000`; point the proxy there and keep `SHH_TRUSTED_PROXIES=172.28.0.0/16` (the host reaches the container from the compose network's gateway, so that range covers it). See [reverse proxies](reverse-proxies.md) for what the proxy must and must not do.

## With Postgres

```sh
# in .env
SHH_DB=postgres
SHH_PG_HOST=postgres
SHH_PG_DATABASE=shhnote
SHH_PG_USERNAME=shhnote
SHH_PG_PASSWORD=<random>
```

and turn on the `postgres` profile next to Caddy, in the same file:

```sh
COMPOSE_PROFILES=caddy,postgres     # or just postgres with your own proxy
```

```sh
docker compose up -d
```

For a Postgres elsewhere, set `SHH_PG_HOST` to it and leave the profile out. Migrations run at startup.

## Files and blobs

Everything the app writes is under the `shhnote-data` volume at `/data`: the SQLite database (`storage/shhnote.db` plus its `-wal`/`-shm` files), local blobs (`storage/blobs`) and the upload spool. To store large secrets on disk instead of refusing them:

```sh
SHH_STORAGE=local
SHH_LOCAL_MAX_TOTAL_BYTES=10G     # hard ceiling for the blobs directory
```

For S3, see [operations](operations.md#storage-tiers).

## Everyday commands

```sh
docker compose pull && docker compose up -d       # upgrade (back up first, see operations.md); compose stops the old container before starting the new one, which the storage tier needs
docker compose exec shhnote /shhnote check        # config and database reachable
docker compose exec shhnote /shhnote health       # what the container's health check runs
docker compose exec shhnote /shhnote reset-admin  # locked out: delete admin keys, bootstrap token works again
docker compose stop                               # waits up to 45 s: a 30 s drain, then 5 s to close connections
```

The container has no shell; run the binary directly as above.

## Building the image yourself

```sh
docker build -t shhnote .                         # from a checkout
docker compose build                              # or through the compose file
```

The multi-stage build compiles the Argon2 WASM module, the client bundles and a static musl binary; it needs no toolchain on the host.
