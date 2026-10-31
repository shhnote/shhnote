-- Transition counters per UTC day, volume only. Lifetime totals are the sum of this table;
-- days older than the retention window are rolled up into their year's 1 January row.
CREATE TABLE stats_daily (
    day     BIGINT NOT NULL PRIMARY KEY,  -- unix seconds at 00:00 UTC
    created BIGINT NOT NULL DEFAULT 0,
    viewed  BIGINT NOT NULL DEFAULT 0,
    burned  BIGINT NOT NULL DEFAULT 0,
    expired BIGINT NOT NULL DEFAULT 0,
    removed BIGINT NOT NULL DEFAULT 0,
    reports BIGINT NOT NULL DEFAULT 0   -- takedown reports received (D-19)
);
