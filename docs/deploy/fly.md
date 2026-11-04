# Deploying on Fly.io

One Fly app is one shhnote instance: a machine, a volume for SQLite, Fly's edge for TLS. Several regions means several apps, each with its own data, linked only through the `regions` setting in their admin panels, which is exactly the isolation the design wants.

## Setup

```sh
git clone https://github.com/shhnote/shhnote && cd shhnote
cp deploy/fly/fly.toml.example fly.toml
# edit fly.toml: app name, primary_region, SHH_URL
fly launch --no-deploy --copy-config
fly volumes create shhnote_data --size 10 --region <primary_region>
fly secrets set $(docker run --rm ghcr.io/shhnote/shhnote init)   # or: $(shhnote init) with a local binary
fly deploy
```

`fly deploy` builds the Dockerfile remotely, so no local toolchain is needed. The health check hits `/api/v1/health`, which also checks the database. Stops send SIGTERM and wait 45 s (`kill_timeout`): the server drains for up to 30 s, then takes up to 5 s more to close connections, and the rest is margin.

Open `https://<app>.fly.dev/en/admin` (or your custom domain after `fly certs add`), sign in with the bootstrap token, create an admin API key, sign in with it, and set the site name and contact address under "Settings": until then every public page answers 503 with a setup page and every public API call `503 not_configured`; only the admin panel, the admin API, `/static/*` and `/health` work. Then `fly secrets unset SHH_ADMIN_TOKEN` (the token stops working anyway once an admin key exists).

## Notes

- **One machine.** SQLite lives on the volume, so the config pins `min_machines_running = max_machines_running = 1`. Don't scale horizontally; deploy another app for another region instead.
- **Postgres.** With Fly Postgres (`fly postgres create`, `fly postgres attach`), set `SHH_DB=postgres` and the `SHH_PG_*` variables from the connection string as secrets, and drop the `[mounts]` section if nothing else needs the volume. Local blob storage still needs the volume.
- **Trusted proxies.** Fly's proxy reaches the machine over the private 6PN network, and Fly's documentation does not name the source addresses it uses. Trust only your organisation's own 6PN prefix: the first three groups of `FLY_PRIVATE_IP` as a `/48` (`fly ssh console -C "printenv FLY_PRIVATE_IP"` on any machine with a shell in the same org, or `fly ips private`), so `fdaa:0:1234::/48` in the example becomes yours. Never `fdaa::/16`: that is every Fly customer, and the server refuses IPv6 ranges wider than `/32`. The IPv4 range `172.16.0.0/16` is kept for the proxy's legacy path. If rate limiting treats every visitor as one client (the admin login limit locking you out after a stranger's attempts is the visible symptom), the range is wrong; `fly logs` on the proxy side shows the addresses in play.
- **Volume ownership.** The image runs as user 65532 and the Dockerfile hands it `/data`, but Fly's documentation does not say who owns a freshly mounted volume. If the first deploy logs a permission error on `storage/shhnote.db`, the mount is root-owned: fix it once with a throwaway machine, `fly machine run --rm -v shhnote_data:/data alpine chown 65532:65532 /data` (the shhnote image itself has no shell), then redeploy.
- **Custom domain.** `fly certs add secrets.example.com`, point DNS as instructed, set `SHH_URL` accordingly and redeploy.
- **Backups.** `fly ssh console` has no shell in this image; use `fly volumes snapshots` for the volume, or Postgres backups. See [operations](operations.md#backups).
