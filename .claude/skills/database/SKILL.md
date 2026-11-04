---
name: database
description: Write migrations or queries for shhnote, which supports both SQLite and PostgreSQL through sqlx. Use when adding tables, changing the schema, or writing any SQL.
---

# Database work (SQLite and PostgreSQL)

Every schema change and query must work on both SQLite and PostgreSQL. A change that only works on one backend is a bug.

## Migrations

- Queries go through sqlx's `Any` driver with `$1` placeholders, so one SQL string serves both engines; dynamic SQL needs `AssertSqlSafe` and a comment saying why it is safe. No compile-time query macros.
- Each backend has its own folder at the repository root (not inside the crate): `migrations/sqlite/` and `migrations/postgres/`, one new table, or one change to an existing one, per file (never several tables in one), embedded into the binary by the `MIGRATIONS` list in `shhnote-store`; add each new file to that list.
- Every migration exists in both folders as `NNNN_<name>.sql`, with the next number and the same name in each. Write the files by hand: migrations are forward-only, so there are no `.up.sql`/`.down.sql` pairs (don't use `sqlx migrate add -r`). The two copies only differ where the SQL dialects differ.
- Never edit a migration once it has been committed. Add a new one instead.
- Pick types both backends handle the same way:
  - IDs: UUIDs or similar, stored as `TEXT` in SQLite and `UUID` in Postgres, generated in Rust, not by the database.
  - Timestamps: stored as UTC. Generate them in Rust rather than with database defaults, because the default functions differ.
  - Booleans: `INTEGER`/`BIGINT` 0/1 on both engines, read as `i64`, so the `Any` driver decodes them the same way.
  - JSON: avoid unless there is a strong reason, since the query support differs a lot.
  - Binary data (inline file contents): `BLOB` in SQLite and `BYTEA` in Postgres.

## Secrets table rules

- The `secrets` table holds only what `SPEC.md` §3 lists. No `created_at`, no access timestamps, no view counters, no IPs, no foreign keys to anything.
- Every credential is stored as a SHA-256 hash and looked up by that hash.
- Terminal transitions (viewed, burned, expired, removed) increment the aggregate counter and delete the row (or set `pending_delete` for external blobs) in one transaction. Status filters are the narrowest possible; mark each with a `// SECURITY:` comment saying why widening it would be a privilege escalation.
- `stats_daily` (which holds the daily report counts; there is no reports table, D-19), `settings`, `api_keys` and `admin_state` live in their own tables and are never joined to `secrets`. Counting is only ever per day, never finer; totals are sums, the active count is `COUNT(*)`, and there is no separate totals table to keep in step.

## Queries

- Aggregates must decode through the `Any` driver on both engines: Postgres turns `SUM(bigint)` into `NUMERIC`, which `Any` cannot read, so wrap sums in `CAST(... AS BIGINT)`. `COUNT(*)` is fine. SQLite-only test runs do not catch this; set `SHH_TEST_PG_URL` to be sure.

- Keep SQL in one data-access module, not scattered through handlers.
- Stick to SQL both backends support. Where they really differ (for example upserts or `RETURNING` edge cases), write a separate query for each backend in the same place, clearly side by side.
- Always bind values as parameters. Never build SQL by putting user input into a string.
- Use transactions for anything that writes more than one row or table.

## Testing

Run tests against both backends. SQLite can use a temporary file or in-memory database. Postgres needs a running server; read its URL from an environment variable and skip those tests with a clear message when it isn't set, rather than failing silently.
