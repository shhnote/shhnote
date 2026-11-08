---
name: file-uploads
description: Store, serve and delete encrypted secret blobs in shhnote-server, inline in the database or on local disk / S3. Use when touching blob upload, download, storage tiers, or the pending-delete scrubber.
---

# Blob storage

The server never sees a file. It receives one opaque encrypted blob per secret (`SPEC.md` §2.8) whose contents, file names, types and exact sizes are all inside the encryption. There is nothing to inspect, so do not add content checks, type allow-lists, magic-byte sniffing or filename handling; they are impossible here and would be a bug if they appeared.

## What the server does check

- **Length only.** A blob is accepted only if its length corresponds to a valid padded size under the instance's padding policy (§6.2): `len = 95 + bucket + 16 × ceil(bucket / 65536)` with `bucket` valid for the policy. Anything else gets the uniform negative.
- **Tier routing by size.** `bucket ≤ config.storage.inline_max` → database. Larger → the external tier if one is enabled and `bucket ≤ external_max_object`, else refused. Never hard-code sizes; read them from `config.storage`.
- **Tier ceilings.** Local: refuse large creates once `SHH_LOCAL_MAX_TOTAL_BYTES` would be exceeded; small secrets keep working. S3: the same with `SHH_S3_MAX_TOTAL_BYTES`. These are the only hard limits in the system.

## Receiving

- `POST /secrets` is multipart with `meta` before `blob`, so validate `meta` and decide the tier before reading the body.
- Inline blobs are read into memory (bounded by `blob_len(inline_max)`) and written in one insert; external blobs are spooled to disk as they arrive and moved into place, or sent to S3, only once complete and length-checked. Never hold a whole external blob in memory.
- Write external objects under a server-generated key (`blobs/<random>`), never anything derived from client input. Only mark the row `active` once the object is fully stored; on any failure delete the partial object.

## Serving

- Always proxy through the server, for both tiers. No presigned or direct object-store URLs: they are an external origin for the client and put an identifier in a URL.
- Stream external objects; `Cache-Control: no-store` on every blob response.
- Serve only `status = 'active'` rows, or `claimed` rows to the holder of the matching claim token (§5.1). Never a `pending_delete` row.

## Deleting

- Inline rows are hard-deleted in the terminal transaction.
- External rows move to `pending_delete` in the terminal transaction (counters included); the scheduler deletes the object, and only once that is confirmed deletes the row. Retry on every pass until it succeeds.
- S3 bucket versioning must be off, or "deleted" objects silently survive. Check it at startup where the API allows and refuse to start if it is on. A `403` on the check only warns (least-privilege tokens may not read it), and R2, which has no versioning, skips it; the startup listing is what checks the credentials.

## Code map

- `crates/shhnote-server/src/storage.rs`: `Blobs` (a struct over a private `Tier` enum of `Local` and `S3`, plus the in-memory ceiling ledger) with `spool`, `put`, `get`, `delete`, `new_key`, `reserve`, `max_total_bytes`, `collect_orphans`; `Blobs::open` runs the startup checks. `Spool` receives a blob chunk by chunk; `finish` turns it into a `Spooled` that removes its file on drop.
- `api.rs` `create`: `Sink::Memory` until the bytes outgrow `blob_len(inline_max)`, then `Sink::Spool`. Ceiling check via `Blobs::reserve` (the in-memory ledger, seeded once from `store.external_bytes()`; the `Reservation` is committed after the row insert and given back on every other path), `ApiError::StorageFull` is `507 storage_full`. `blob_response` streams external objects.
- `scheduler::scrub` deletes parked objects, then their rows; tests call it directly.
- Tests: `tests/api.rs` runs the tier flow on local disk always and on S3 when `SHH_TEST_S3_ENDPOINT`, `SHH_TEST_S3_BUCKET`, `SHH_TEST_S3_REGION`, `SHH_TEST_S3_ACCESS_KEY_ID` and `SHH_TEST_S3_SECRET_ACCESS_KEY` are set. Without a bucket, `tests/spec_resources.rs` still covers the S3 client: `fake_bucket` (in-memory, path-style, paged listings) for storing, listing and the orphan sweep, and `fake_s3` (answers or hangs) for the timeouts.

## Backends

- One `Blobs` type with spool / put / get (streamed) / delete, and no trait: a new backend is another `Tier` variant. Handlers never touch the filesystem or the S3 client directly.
- Local disk: root from `SHH_LOCAL_PATH`, never inside a folder served as static files.
- S3: hand-written SigV4 over the existing HTTP stack, not the AWS SDK (dependency policy in `CLAUDE.md`). Works against MinIO and R2 via `SHH_S3_ENDPOINT`.
- A feature works on every tier or it isn't done. Test inline and local always; S3 when its variables are set, skipping with a clear message otherwise.
