# Deploying on bare metal

For a Linux host where a reverse proxy already runs and, if you want one, a Postgres server. The server is one static binary; it needs no files besides its environment file and its state directory.

## 1. Install the binary

Download the archive for your architecture from the [releases page](https://github.com/shhnote/shhnote/releases) (`x86_64` or `aarch64`, Linux, musl, no library dependencies) and verify it against `SHA256SUMS`:

```sh
tar -xzf shhnote-v*-x86_64-linux-musl.tar.gz
sudo install -m 0755 shhnote-v*/shhnote /usr/local/bin/shhnote
```

To build from source instead you need Rust stable with the `wasm32-unknown-unknown` target and Node 24: `scripts/build-client.sh && cargo build --release -p shhnote-server`, binary at `target/release/shhnote`.

## 2. Configure

```sh
sudo mkdir -p /etc/shhnote
sudo curl -fsSL https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/systemd/env.example -o /etc/shhnote/env
sudo chmod 0640 /etc/shhnote/env
sudo shhnote init --env /etc/shhnote/env     # fills in SHH_SECRET_KEY and SHH_ADMIN_TOKEN
sudo editor /etc/shhnote/env
```

Set `SHH_URL`; `init` has filled in the two secrets. The example binds `127.0.0.1:3000` and trusts `X-Forwarded-For` from `127.0.0.1` and `::1`, which is right for a proxy on the same host. Relative paths resolve under `/var/lib/shhnote`.

For Postgres, create a role and database, then:

```sh
SHH_DB=postgres
SHH_PG_HOST=127.0.0.1
SHH_PG_DATABASE=shhnote
SHH_PG_USERNAME=shhnote
SHH_PG_PASSWORD=…
```

```sql
CREATE ROLE shhnote LOGIN PASSWORD '…';
CREATE DATABASE shhnote OWNER shhnote;
```

Migrations run when the service starts; the role needs to own the database (or have `CREATE` on it) for that.

## 3. Run as a service

```sh
sudo curl -fsSL https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/systemd/shhnote.service -o /etc/systemd/system/shhnote.service
sudo systemctl daemon-reload
sudo systemctl enable --now shhnote
systemctl status shhnote
```

The unit runs with `DynamicUser`, a private `/var/lib/shhnote` state directory and a strict sandbox (read-only system, no capabilities, no new privileges). `ExecStartPre` runs `shhnote check`, so a broken environment file fails the start with a clear message in `journalctl -u shhnote`. Stopping waits up to 45 s (`TimeoutStopSec`): the server drains uploads in flight for up to 30 s, then takes up to 5 s more to close connections, and the unit leaves a margin on top.

## 4. Proxy

Caddy, with the file in `deploy/caddy/Caddyfile`:

```caddyfile
secrets.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:3000
}
```

The same file carries commented site blocks for the API host (`SHH_API_ROUTING=domain`: `api.<domain>`, or whatever `SHH_API_DOMAIN` names) and the panel host (`SHH_ADMIN_ROUTING=domain`: `admin.<domain>` or `SHH_ADMIN_DOMAIN`, with a `remote_ip` allow-list so only your own range reaches the panel). Other proxies: [reverse proxies](reverse-proxies.md). Then open `https://<domain>/en/admin`, sign in with the bootstrap token, create an admin API key, sign in with it, and set the site name and contact address under "Settings": until then every public page answers 503 with a setup page and every public API call `503 not_configured`; only the admin panel, the admin API, `/static/*` and `/health` work. Then remove `SHH_ADMIN_TOKEN` from the environment file (`systemctl restart shhnote` afterwards; the token stops working anyway once an admin key exists).

## Upgrades

```sh
sudo systemctl stop shhnote
# back up first: see operations.md
sudo install -m 0755 shhnote /usr/local/bin/shhnote
sudo systemctl start shhnote
```

Stop before you start, as above: one process owns the storage tier and its spool directory, and two running against the same directory or bucket would take each other's uploads in flight for leftovers (see operations.md).

Migrations are applied at startup and are forward-only; keep the backup until the new version has run for a while.

## Blobs on disk

```sh
SHH_STORAGE=local
SHH_LOCAL_MAX_TOTAL_BYTES=10G
```

Blobs go to `/var/lib/shhnote/storage/blobs`. The ceiling is the only hard limit: when it is reached, large secrets are refused and small ones keep working.
