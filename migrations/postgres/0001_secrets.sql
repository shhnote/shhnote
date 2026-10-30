-- Only what serving a secret requires (SPEC §3): no timestamps other than expiry,
-- no counters, no foreign keys. Every credential is stored as a SHA-256 hash.
CREATE TABLE secrets (
    lookup_key       BYTEA    NOT NULL PRIMARY KEY,
    burn_key         BYTEA    NOT NULL UNIQUE,
    status           TEXT    NOT NULL,  -- active | claimed | pending_delete
    lifetime         TEXT    NOT NULL,  -- single_view | ttl
    bucket           BIGINT NOT NULL,
    blob             BYTEA,              -- NULL when the blob is in the external tier
    external_ref     TEXT,              -- NULL when the blob is inline
    expires_at       BIGINT NOT NULL,
    claim_key        BYTEA,              -- SHA-256 of the claim token while claimed
    claim_expires_at BIGINT
);
CREATE INDEX secrets_sweep_expired ON secrets (status, expires_at);
CREATE INDEX secrets_sweep_claimed ON secrets (status, claim_expires_at);
