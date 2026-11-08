# Deploying on bare metal

For a Linux host where a reverse proxy already runs and, if you want one, a Postgres server. The server is one static binary; it needs no files besides its environment file and its state directory.

## 1. Install the binary

Download the archive for your architecture from the [releases page](https://github.com/shhnote/shhnote/releases) (`x86_64` or `aarch64`, Linux, musl, no library dependencies) together with `SHA256SUMS`, and check it before unpacking:

```sh
version=v0.6.1   # the release you are installing
base=https://github.com/shhnote/shhnote/releases/download/$version
curl -fsSLO "$base/shhnote-$version-x86_64-linux-musl.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS   # must print "OK" for the archive
tar -xzf "shhnote-$version-x86_64-linux-musl.tar.gz"
sudo install -m 0755 "shhnote-$version/shhnote" /usr/local/bin/shhnote
shhnote --version
```

`SHA256SUMS` lists both architectures; `--ignore-missing` checks only the archive you downloaded.

To build from source instead you need Rust stable with the `wasm32-unknown-unknown` target and Node 24: `scripts/build-client.sh && cargo build --release -p shhnote-server`, binary at `target/release/shhnote`.

## 2. Configure

```sh
sudo mkdir -p /etc/shhnote
sudo curl -fsSL https://raw.githubusercontent.com/shhnote/shhnote/main/deploy/systemd/env.example -o /etc/shhnote/env
sudo chmod 0600 /etc/shhnote/env   # holds credentials; systemd reads it as root
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

With `DynamicUser` the state really lives in `/var/lib/private/shhnote`, and `/var/lib/shhnote` is a symlink to it. `/var/lib/private` is readable by root only, so `ls /var/lib/shhnote` as another user shows nothing; use `sudo`.

To run a command such as `check`, `health` or `reset-admin` by hand, run it as the service's user, with its environment and state directory:

```sh
sudo systemd-run --pty --wait --collect -p DynamicUser=yes -p StateDirectory=shhnote \
  -p WorkingDirectory=/var/lib/shhnote -p EnvironmentFile=/etc/shhnote/env \
  /usr/local/bin/shhnote check
```

Running it as plain root instead creates files that belong to root, and running it before the first start creates `/var/lib/shhnote` as an ordinary directory. That is harmless: systemd logs `Found pre-existing public StateDirectory= directory /var/lib/shhnote, migrating to /var/lib/private/shhnote` once and takes it over. You don't need to check by hand before the first start anyway, since the unit runs `check` before every start.

### Network access

The unit allows network traffic to and from this host only (`IPAddressDeny=any`, `IPAddressAllow=localhost`), which is enough for the proxy, SQLite and a Postgres on `127.0.0.1`. A Postgres or an object store on another machine needs its address allowed too, or the connection times out: the start fails with `S3 connect timed out` or a database timeout, not a permission error, and the unit restarts every 5 s. Allow it in a drop-in, so an updated unit file keeps the setting:

```sh
sudo systemctl edit shhnote
```

```ini
[Service]
# A host with a fixed address (or a range): your Postgres, a MinIO on the LAN.
IPAddressAllow=192.0.2.5
```

Cloudflare R2, AWS S3 and other hosted object stores have no fixed address: they answer from anycast or changing addresses, so there is nothing stable to allow. For them, allow all destinations; the rest of the sandbox stays in place:

```ini
[Service]
IPAddressAllow=any
```

`systemctl edit` writes `/etc/systemd/system/shhnote.service.d/override.conf` and reloads systemd; restart with `sudo systemctl restart shhnote`.

## 4. Proxy

Caddy, with the file in `deploy/caddy/Caddyfile`:

```caddyfile
secrets.example.com {
	encode zstd gzip
	reverse_proxy 127.0.0.1:3000
}
```

The same file carries commented site blocks for the API host (`SHH_API_ROUTING=domain`: `api.<domain>`, or whatever `SHH_API_DOMAIN` names) and the panel host (`SHH_ADMIN_ROUTING=domain`: `admin.<domain>` or `SHH_ADMIN_DOMAIN`, with a `remote_ip` allow-list so only your own range reaches the panel). Other proxies: [reverse proxies](reverse-proxies.md). Then open `https://<domain>/en/admin`, sign in with the bootstrap token, create an admin API key, sign in with it, and set the site name and contact address under "Settings": until then every public page answers 503 with a setup page and every public API call `503 not_configured`; only the admin panel, the admin API, `/static/*` and the health endpoint (`/api/v1/health`, or `/v1/health` on the API host) work; the health endpoint answers `"configured": false` until then. Then remove `SHH_ADMIN_TOKEN` from the environment file, by deleting the line or leaving the value empty (`systemctl restart shhnote` afterwards; the token stops working anyway once an admin key exists).

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

`SHH_LOCAL_PATH` (default `storage/blobs`, so `/var/lib/shhnote/storage/blobs`) is the tier's root: the blobs themselves are in its `blobs/` subdirectory, and uploads in progress are spooled in its `tmp/`. Point a backup or a quota at the root. The ceiling is the only hard limit: when it is reached, large secrets are refused and small ones keep working.

## Blobs in S3

```sh
SHH_STORAGE=s3
SHH_S3_BUCKET=…
SHH_S3_REGION=…
SHH_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com   # empty for AWS
SHH_S3_ACCESS_KEY_ID=…
SHH_S3_SECRET_ACCESS_KEY=…
SHH_S3_MAX_TOTAL_BYTES=50G
```

The unit blocks connections to other hosts, so allow the object store first ([network access](#network-access)); for R2 and AWS that means `IPAddressAllow=any`. The token permissions per provider, and what the server checks at startup, are in [operations](operations.md#storage-tiers).
