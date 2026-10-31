# Operations

## Configuration reference

Deployment settings come from the environment (or a `.env` file in the working directory). Everything else, such as the site name, lifetimes, padding, rate limits and the region list, is set in the admin panel and stored in the database. An unknown `SHH_*` variable, or one for a storage tier that is not enabled, stops the server from starting.

| Variable | Needed | Meaning |
|---|---|---|
| `SHH_ENV` | yes | `production` or `local`. Production turns on HSTS and secure cookies and refuses `SHH_DEBUG`. |
| `SHH_URL` | yes | Public address, scheme and host only. |
| `SHH_SECRET_KEY` | yes | At least 32 random characters; signs admin sessions. Changing it logs every admin out. |
| `SHH_ADMIN_TOKEN` | at first | Bootstrap credential for the admin panel and admin API, at least 32 characters. Ignored once an admin API key exists; remove it then. |
| `SHH_HOST`, `SHH_PORT` | | Bind address, default `127.0.0.1:3000`. Containers set `0.0.0.0`. |
| `SHH_TRUSTED_PROXIES` | behind a proxy | Addresses or CIDR ranges whose `X-Forwarded-For` is honoured. |
| `SHH_API_ROUTING` | | `path` (API at `/api`, default) or `subdomain` (API at `api.<host>`). |
| `SHH_LOCALES`, `SHH_DEFAULT_LOCALE` | | Languages offered (default all: `en`, `de`) and where unmatched browsers land. |
| `SHH_LOG_LEVEL` | | `error` (default), `warn`, `info`, `debug`, `trace`. Nothing per request is logged at any level. |
| `SHH_DB` | yes | `sqlite` or `postgres`. |
| `SHH_SQLITE_PATH` | | Default `storage/shhnote.db`, relative to the working directory. |
| `SHH_PG_HOST`, `SHH_PG_PORT`, `SHH_PG_DATABASE`, `SHH_PG_USERNAME`, `SHH_PG_PASSWORD` | with postgres | Connection details. |
| `SHH_STORAGE` | | `inline` (default: blobs above the inline ceiling are refused), `local` or `s3`. |
| `SHH_INLINE_MAX` | | Largest padded blob kept in the database (default 2 MiB, minimum 64 KiB). |
| `SHH_EXTERNAL_MAX_OBJECT` | with local/s3 | Largest padded blob the external tier accepts (default 64 MiB). |
| `SHH_MAX_UPLOADS` | optional | Uploads in flight at once; further creates get `503 too_busy` until one finishes (default 64). Each slot can hold up to `SHH_INLINE_MAX` in memory. |
| `SHH_LOCAL_PATH`, `SHH_LOCAL_MAX_TOTAL_BYTES` | with local | Blob directory (default `storage/blobs`) and its hard ceiling (required). |
| `SHH_S3_BUCKET`, `SHH_S3_REGION`, `SHH_S3_ENDPOINT`, `SHH_S3_ACCESS_KEY_ID`, `SHH_S3_SECRET_ACCESS_KEY`, `SHH_S3_MAX_TOTAL_BYTES`, `SHH_SPOOL_PATH` | with s3 | Bucket, credentials, hard ceiling (required), and the spool directory uploads wait in (default `storage/spool`). |

`SPEC.md` §7 is the authoritative list.

## Commands

| Command | Does |
|---|---|
| `shhnote` | Runs the server. SIGTERM or Ctrl-C stops accepting requests, finishes the ones in flight (up to 30 s), then exits. |
| `shhnote check` | Loads the configuration and pings the database; exit code 0 when a start would succeed. |
| `shhnote health` | Asks the running server's `/api/v1/health`; used as the container health check. |
| `shhnote reset-admin` | Deletes every admin API key, so `SHH_ADMIN_TOKEN` works again. For lockouts. |

## First admin, and retiring the token

Sign in at `/en/admin` with `SHH_ADMIN_TOKEN`, create an admin API key (keep it in a password manager; it is shown once), sign out, sign in with the key. From that moment the token is ignored and the server logs a warning as long as it is still set: remove it. The admin JSON API under `/api/v1/admin` takes the same keys as `Authorization: Bearer`.

## Backups

What to back up is small: the database and, with the local tier, the blobs directory. Secrets are encrypted at rest by design, so a backup is as safe as the database itself, but it also contains the hashed identifiers that let a secret be served, so treat it as sensitive.

- **SQLite.** Either stop the service and copy `shhnote.db` together with `shhnote.db-wal` and `shhnote.db-shm`, or take an online copy: `sqlite3 storage/shhnote.db ".backup /path/shhnote-$(date +%F).db"`. Never copy only the `.db` file while the server runs; in WAL mode the newest writes are in the `-wal` file.
- **Postgres.** `pg_dump shhnote > shhnote-$(date +%F).sql`, or your usual base backups.
- **Local blobs.** Copy `storage/blobs`. A blob without its row is garbage; a row without its blob is a secret that cannot be opened. Back up the database and the blobs at the same time, ideally with the service stopped.
- **S3.** Bucket versioning must stay off (the server refuses to start otherwise), so a bucket backup is a replication job on your side. Note that restoring old objects revives secrets the owners believe destroyed; most instances should not back up the bucket at all.

Because secrets expire or self-destruct within days, restoring an old backup brings back secrets that should be gone. Restore only to recover from loss, and consider running the scheduler's sweep (it happens within a minute of starting) before letting traffic in.

## Upgrades

Back up, replace the binary or pull the image, start. Migrations are embedded and run at startup, forward-only. Watch `journalctl -u shhnote` or `docker compose logs` for the "listening" line; a failed migration leaves the service stopped and the backup is the way back.

## Storage tiers

- **inline**: every blob lives in the database row, up to `SHH_INLINE_MAX`; larger uploads are refused with `413`. Fine for passwords and small files.
- **local**: blobs above the inline ceiling go to disk under `SHH_LOCAL_PATH`, counted against `SHH_LOCAL_MAX_TOTAL_BYTES`. Deleted blobs are removed by the scheduler and the directory is self-contained; put it on the same filesystem as its `tmp` spool (it is, by default).
- **s3**: blobs go to a bucket via a built-in SigV4 client (AWS, MinIO, R2 and others via `SHH_S3_ENDPOINT`). Uploads are spooled in `SHH_SPOOL_PATH` first, so that directory needs room for a few concurrent uploads of `SHH_EXTERNAL_MAX_OBJECT`. The server checks at startup that bucket versioning is off and that the credentials work. Self-hosted endpoints must present a certificate the public roots trust; a private CA or an expired certificate fails the start with a clear message. Use plain `http://` for a MinIO on the same host, or front it with a trusted certificate.

Two admin settings interact with the tiers: "files enabled" off hides the file input and refuses anything larger than a text secret; "store small secrets in the database" off sends every blob to the external tier.

## What is logged

Nothing about requests, addresses or secrets, at any level. `error` and `warn` cover startup problems, database and storage failures and the scheduler. `info` adds start and stop lines. Rate limiting hashes addresses under a salt that rotates hourly and holds them in memory only.
