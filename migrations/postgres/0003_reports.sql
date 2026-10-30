-- Deduplicated takedown ledger. No reporter data, ever.
CREATE TABLE reports (
    lookup_key        BYTEA    NOT NULL PRIMARY KEY,
    count             BIGINT NOT NULL,
    first_reported_at BIGINT NOT NULL,
    last_reported_at  BIGINT NOT NULL,
    matched           BIGINT NOT NULL  -- 0 or 1
);
