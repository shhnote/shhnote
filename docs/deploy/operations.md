# Operations

## Configuration reference

Deployment settings come from the environment (or a `.env` file in the working directory). Everything else, such as the site name, lifetimes, padding, rate limits and the region list, is set in the admin panel and stored in the database. An unknown `SHH_*` variable, or one for a storage tier that is not enabled, stops the server from starting.

| Variable | Needed | Meaning |
|---|---|---|
| `SHH_ENV` | | `production` (default) or `local`. Production turns on HSTS and secure cookies and refuses `SHH_DEBUG`. |
| `SHH_URL` | yes | Public address, scheme and host only. |
| `SHH_SECRET_KEY` | yes | At least 32 random characters; signs admin sessions. Changing it logs every admin out. |
| `SHH_ADMIN_TOKEN` | at first | Bootstrap credential for the admin panel and admin API, at least 32 characters. Stops working as soon as the first admin API key exists; remove it then. |
| `SHH_HOST`, `SHH_PORT` | | Bind address, default `127.0.0.1:3000`. Containers set `0.0.0.0`. |
| `SHH_TRUSTED_PROXIES` | behind a proxy | Addresses or CIDR ranges whose `X-Forwarded-For` is honoured. |
| `SHH_API_ROUTING` | | `path` (API at `/api`, default) or `domain` (API on its own host name: `api.<host>` of `SHH_URL`, or `SHH_API_DOMAIN`). |
| `SHH_API_DOMAIN` | with `domain` | The API host name, optional port, e.g. `api-eu.example.com`. Default `api.<host>`. Must differ from the site host. |
| `SHH_ADMIN_ROUTING` | | `path` (panel at `/<locale>/admin`, default) or `domain` (panel at `<host>/<locale>/` on its own host name; the path form is then 404). |
| `SHH_ADMIN_DOMAIN` | with `domain` | The panel host name, optional port. Default `admin.<host>`. Must differ from the site and API hosts. |
| `SHH_WEB` | | `full` (the built-in website, default) or `api` (API, admin panel and `/static/*` only; every other page is 404, for a frontend of your own). |
| `SHH_LOCALES`, `SHH_DEFAULT_LOCALE` | | Languages offered (default all: `en`, `de`) and where unmatched browsers land. |
| `SHH_LOG_LEVEL` | | `error` (default), `warn`, `info`, `debug`, `trace`. Nothing per request is logged at any level. |
| `SHH_DB` | yes | `sqlite` or `postgres`. |
| `SHH_SQLITE_PATH` | | Default `storage/shhnote.db`, relative to the working directory. |
| `SHH_PG_HOST`, `SHH_PG_PORT`, `SHH_PG_DATABASE`, `SHH_PG_USERNAME`, `SHH_PG_PASSWORD` | with postgres | Connection details. |
| `SHH_STORAGE` | | `inline` (default: blobs above the inline ceiling are refused), `local` or `s3`. The size variables below take a unit: `100B`, `64K`, `10M`, `1G` (powers of 1024); a bare number is refused. |
| `SHH_INLINE_MAX` | | Largest padded blob kept in the database (default 2 MiB, minimum 64 KiB). At most 64 MiB. |
| `SHH_EXTERNAL_MAX_OBJECT` | with local/s3 | Largest padded blob the external tier accepts (default 64 MiB, at most 4 GiB). |
| `SHH_MAX_UPLOADS` | optional | Uploads in flight at once; further creates get `503 too_busy` until one finishes (default 64). Each slot can hold up to `SHH_INLINE_MAX` in memory. |
| `SHH_LOCAL_PATH`, `SHH_LOCAL_MAX_TOTAL_BYTES` | with local | Blob directory (default `storage/blobs`) and its hard ceiling (required). |
| `SHH_S3_BUCKET`, `SHH_S3_REGION`, `SHH_S3_ENDPOINT`, `SHH_S3_ACCESS_KEY_ID`, `SHH_S3_SECRET_ACCESS_KEY`, `SHH_S3_MAX_TOTAL_BYTES`, `SHH_SPOOL_PATH` | with s3 | Bucket, credentials, hard ceiling (required), and the spool directory uploads wait in (default `storage/spool`). |

`SPEC.md` §7 is the authoritative list.

## Commands

| Command | Does |
|---|---|
| `shhnote` | Runs the server. SIGTERM or Ctrl-C answers new requests with 503, finishes the ones in flight (up to 30 s), closes idle connections and cuts stuck ones after a further 5 s, then exits. Give it a stop budget of 45 s (the shipped unit, compose and Fly files do). |
| `shhnote init` | Generates `SHH_SECRET_KEY` and `SHH_ADMIN_TOKEN` and prints them as `KEY=value` lines. `shhnote init --env <path>` writes them into that file instead: creates it (owner-readable only), fills an empty `KEY=` line in place, appends a missing key, and never overwrites a value that is set. The file is replaced whole through a temp file and a rename in its directory, keeping its permissions (and its owner and group when run as root), so it is never left half-written; the directory must be writable, and a bind-mounted single file cannot be updated this way (use the printing form there). Needs no configuration; the first command of every install. |
| `shhnote check` | Loads the configuration and pings the database; exit code 0 when a start would succeed. |
| `shhnote health` | Asks the running server's health endpoint (`/api/v1/health`, or `/v1/health` on the API host under domain routing); used as the container health check. |
| `shhnote reset-admin` | Deletes every admin API key, so `SHH_ADMIN_TOKEN` works again. For lockouts. |

## First admin, and retiring the token

Until setup is done the site serves only its admin panel and admin API (every other page and API call answers 503 with a setup page; `/health` says `configured: false`). Setup is three things: sign in at `/en/admin` with `SHH_ADMIN_TOKEN`, create an admin API key (keep it in a password manager; it is shown once), then sign in with the key and set the site name and the contact address under Settings. The token, and any session signed in with it, stops working as soon as the first admin key exists; if it is still set, the server logs a warning at startup. Remove it. The admin JSON API under `/api/v1/admin` (`<API domain>/v1/admin` under domain routing; see [admin API](../admin-api.md)) takes the same keys as `Authorization: Bearer`.

## Changing the public address

`SHH_URL` is read at startup and nothing derived from it is stored: secrets, blobs, keys and settings carry no host name, share links are built in the browser from the page's own origin, and admin cookies are scoped by the browser to the host that set them. Moving an instance from a temporary host name (say `new.example.com`) to its final one is therefore an edit of `SHH_URL`, the proxy and DNS, and a restart. Four things to check by hand:

- **Links already handed out** point at the old host. They keep working only while that name still reaches the instance, so keep it routed until those secrets have expired, or accept that they break. Under `domain` routing the old API host stops matching at once, so keep its name too, or pick a fixed `SHH_API_DOMAIN` from the start.
- **Settings that hold the old address**: the `regions` list, `allowed_origins`, and perhaps `source_url` or `project_url`. Change them in the panel.
- **Derived host names** under `domain` routing move with the site unless `SHH_API_DOMAIN` and `SHH_ADMIN_DOMAIN` pin them. `new.example.com` otherwise gets `api.new.example.com`; two instances such as `example.com` and `eu.example.com` get `api.example.com` and `api.eu.example.com`, where `api-eu.example.com` may be wanted. Setting the two variables gives each instance the names you choose, and keeps them when `SHH_URL` changes.
- **Admins sign in again**, since the session cookie belongs to the old host.

## Backups

What to back up is small: the database and, with the local tier, the blobs directory. Secrets are encrypted at rest by design, so a backup is as safe as the database itself, but it also contains the hashed identifiers that let a secret be served, so treat it as sensitive.

- **SQLite.** Use `sqlite3 storage/shhnote.db ".backup /path/shhnote-$(date +%F).db"` (or `VACUUM INTO`), never a copy of the files. A file copy taken while the server runs is inconsistent (the newest writes are in the `-wal` file), and the `-wal` file can still hold the ciphertext of secrets destroyed since the last checkpoint. The server truncates the WAL after every sweep (once a minute), so that window is short, but `.backup` sidesteps it entirely: it copies committed pages only, which `secure_delete` has already zeroed for destroyed rows. Filesystem snapshots are file copies in this sense.
- **Postgres.** `pg_dump shhnote > shhnote-$(date +%F).sql`, or your usual base backups. Postgres keeps a deleted row's bytes in its heap page until `VACUUM` reuses the space, and in `pg_wal` until the WAL is recycled; the `secrets` table turns over fast, so give it aggressive autovacuum (`ALTER TABLE secrets SET (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_cost_delay = 0)`), keep `wal_keep_size` and any replication slots small, and put the data directory on an encrypted disk. Row order (`ctid`, `xmin`) follows creation, so anyone with database access can see which secrets are newer; nothing finer than that.
- **Local blobs.** Copy `storage/blobs`. A blob without its row is garbage; a row without its blob is a secret that cannot be opened. Back up the database and the blobs at the same time, ideally with the service stopped.
- **S3.** Bucket versioning must stay off (the server refuses to start otherwise), so a bucket backup is a replication job on your side. Note that restoring old objects revives secrets the owners believe destroyed; most instances should not back up the bucket at all.

Because secrets expire or self-destruct within days, restoring an old backup brings back secrets that should be gone. Restore only to recover from loss, and consider running the scheduler's sweep (it happens within a minute of starting) before letting traffic in.

## Upgrades

Back up, stop, replace the binary or pull the image, start. Stop before you start: one server process owns an external tier (local disk or S3) and its spool directory, and a second process starting against the same tier would treat the first one's uploads in flight as leftovers. The server guards against that by leaving entries younger than the longest possible upload alone at startup, but a rolling or blue/green deploy that runs two processes against one tier is not supported; run the new process only once the old one has exited. Migrations are embedded and run at startup, forward-only. Then check that it answers: `shhnote health` exits 0 (`docker compose ps` shows the container as healthy). The start line, `info: listening on 0.0.0.0:3000` (with your bind address), is logged only at `SHH_LOG_LEVEL=info` or more; the examples set `warn`. A failed migration is logged as an error in `journalctl -u shhnote` or `docker compose logs`, leaves the service stopped, and the backup is the way back.

## Storage tiers

- **inline**: every blob lives in the database row, up to `SHH_INLINE_MAX`; larger uploads are refused with `413`. Fine for passwords and small files.
- **local**: blobs above the inline ceiling go to disk under `SHH_LOCAL_PATH`, counted against `SHH_LOCAL_MAX_TOTAL_BYTES`. Deleted blobs are removed by the scheduler and the directory is self-contained; put it on the same filesystem as its `tmp` spool (it is, by default).
- **s3**: blobs go to a bucket via a built-in SigV4 client (AWS, MinIO, R2 and others via `SHH_S3_ENDPOINT`). Uploads are spooled in `SHH_SPOOL_PATH` first, so that directory needs room for a few concurrent uploads of `SHH_EXTERNAL_MAX_OBJECT`. The server checks at startup that bucket versioning is off and that the credentials work. Self-hosted endpoints must present a certificate the public roots trust; a private CA or an expired certificate fails the start with a clear message. Use plain `http://` for a MinIO on the same host, or front it with a trusted certificate.

Three admin settings interact with the tiers: "files enabled" off hides the file input and refuses anything larger than a text secret; "store small secrets in the database" off sends every blob to the external tier; a padding ladder (buckets mode) must end at or below the largest blob the instance stores, `SHH_EXTERNAL_MAX_OBJECT` with an external tier or `SHH_INLINE_MAX` without. The panel refuses a ladder that is too large; if you lower the limit below a stored ladder, the server logs a warning at startup and pads with Padmé until you fix it.

The server keeps its blob and spool directories private: at startup it sets the local tier's `blobs/` and `tmp/` and the S3 spool directory to `0700` (owner only), logs a warning when it had to change one, and refuses to start, naming the directory, if it cannot.

## What is logged

Nothing about requests, addresses or secrets, at any level. `error` and `warn` cover startup problems, database and storage failures and the scheduler. `info` adds start and stop lines. Rate limiting hashes addresses under a salt that rotates hourly and holds them in memory only.
