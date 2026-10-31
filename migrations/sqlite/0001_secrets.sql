-- Only what serving a secret requires (SPEC §3): no timestamps other than expiry,
-- no counters, no foreign keys. Every credential is stored as a SHA-256 hash.
-- WITHOUT ROWID: an implicit rowid would number secrets in creation order.
CREATE TABLE secrets (
    lookup_key       BLOB    NOT NULL PRIMARY KEY,
    burn_key         BLOB    NOT NULL UNIQUE,
    status           TEXT    NOT NULL,  -- active | claimed | pending_delete
    lifetime         TEXT    NOT NULL,  -- single_view | ttl
    bucket           INTEGER NOT NULL,
    blob             BLOB,              -- NULL when the blob is in the external tier
    external_ref     TEXT,              -- NULL when the blob is inline
    expires_at       INTEGER NOT NULL,
    claim_key        BLOB,              -- SHA-256 of the claim token while claimed
    claim_expires_at INTEGER
) WITHOUT ROWID;
CREATE INDEX secrets_sweep_expired ON secrets (status, expires_at);
CREATE INDEX secrets_sweep_claimed ON secrets (status, claim_expires_at);
