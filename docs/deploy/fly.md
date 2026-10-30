# Deploying on Fly.io

One Fly app is one shhnote instance: a machine, a volume for SQLite, Fly's edge for TLS. Several regions means several apps, each with its own data, linked only through the `regions` setting in their admin panels, which is exactly the isolation the design wants.

## Setup

```sh
git clone https://github.com/zbcdo/shhnote && cd shhnote
cp deploy/fly/fly.toml.example fly.toml
# edit fly.toml: app name, primary_region, SHH_URL
fly launch --no-deploy --copy-config
fly volumes create shhnote_data --size 10 --region <primary_region>
fly secrets set SHH_SECRET_KEY="$(openssl rand -base64 48)" SHH_ADMIN_TOKEN="$(openssl rand -base64 48)"
fly deploy
```

`fly deploy` builds the Dockerfile remotely, so no local toolchain is needed. The health check hits `/api/v1/health`, which also checks the database. Stops send SIGTERM and wait 35 s (`kill_timeout`), long enough for the server's own 30 s drain.

Open `https://<app>.fly.dev/en/admin` (or your custom domain after `fly certs add`), sign in with the bootstrap token, create an admin key, then `fly secrets unset SHH_ADMIN_TOKEN`.

## Notes

- **One machine.** SQLite lives on the volume, so the config pins `min_machines_running = max_machines_running = 1`. Don't scale horizontally; deploy another app for another region instead.
- **Postgres.** With Fly Postgres (`fly postgres create`, `fly postgres attach`), set `SHH_DB=postgres` and the `SHH_PG_*` variables from the connection string as secrets, and drop the `[mounts]` section if nothing else needs the volume. Local blob storage still needs the volume.
- **Trusted proxies.** Fly's proxy connects from its private network; the example trusts `172.16.0.0/16` and `fdaa::/16`. If rate limiting seems to treat every visitor as one client, check the peer address in your own logs (`SHH_LOG_LEVEL=debug` prints nothing per request on purpose; use `fly logs` on the proxy side) and adjust the range.
- **Custom domain.** `fly certs add secrets.example.com`, point DNS as instructed, set `SHH_URL` accordingly and redeploy.
- **Backups.** `fly ssh console` has no shell in this image; use `fly volumes snapshots` for the volume, or Postgres backups. See [operations](operations.md#backups).
