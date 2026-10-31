-- Operator credentials. Timestamps are fine here: these are not secrets, but last use
-- is kept to the UTC day only (D-23) so it cannot be joined with the expiry grid.
CREATE TABLE api_keys (
    key_hash     BYTEA    NOT NULL PRIMARY KEY,
    name         TEXT    NOT NULL,
    scopes       TEXT    NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_on BIGINT            -- unix seconds at 00:00 UTC of the last use
);
