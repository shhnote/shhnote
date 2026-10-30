-- Operator credentials. Timestamps are fine here: these are not secrets.
CREATE TABLE api_keys (
    key_hash     BLOB    NOT NULL PRIMARY KEY,
    name         TEXT    NOT NULL,
    scopes       TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
