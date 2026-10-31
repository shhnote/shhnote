-- Transition counters per UTC day, volume only. Lifetime totals are the sum of this table;
-- days older than the retention window are rolled up into their year's 1 January row.
CREATE TABLE stats_daily (
    day     INTEGER NOT NULL PRIMARY KEY,  -- unix seconds at 00:00 UTC
    created INTEGER NOT NULL DEFAULT 0,
    viewed  INTEGER NOT NULL DEFAULT 0,
    burned  INTEGER NOT NULL DEFAULT 0,
    expired INTEGER NOT NULL DEFAULT 0,
    removed INTEGER NOT NULL DEFAULT 0,
    reports INTEGER NOT NULL DEFAULT 0   -- takedown reports received (D-19)
);
