-- Sessions of a key issued at or before this instant are invalid (SPEC §8): an operator can
-- end a key's sessions without deleting the key. Unix seconds; 0 means never ended.
ALTER TABLE api_keys ADD COLUMN sessions_valid_after INTEGER NOT NULL DEFAULT 0;
