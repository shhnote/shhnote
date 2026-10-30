-- Deduplicated takedown ledger. No reporter data, ever.
CREATE TABLE reports (
    lookup_key        BLOB    NOT NULL PRIMARY KEY,
    count             INTEGER NOT NULL,
    first_reported_at INTEGER NOT NULL,
    last_reported_at  INTEGER NOT NULL,
    matched           INTEGER NOT NULL  -- 0 or 1
);
