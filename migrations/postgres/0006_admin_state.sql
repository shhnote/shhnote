-- Instance-level state the admin layer needs across restarts; not settings (those have
-- defaults in code) and not secrets. Today one row: `bootstrap_sessions_valid_after`,
-- written by `reset-admin` so bootstrap sessions from before a reset stay dead (SPEC §8).
CREATE TABLE admin_state (
    key   TEXT   NOT NULL PRIMARY KEY,
    value BIGINT NOT NULL
);
