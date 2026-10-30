-- Operator credentials. Timestamps are fine here: these are not secrets.
CREATE TABLE api_keys (
    key_hash     BYTEA    NOT NULL PRIMARY KEY,
    name         TEXT    NOT NULL,
    scopes       TEXT    NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT
);
