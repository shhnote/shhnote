-- Runtime settings: only values an admin changed; everything else uses the code default.
CREATE TABLE settings (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);
