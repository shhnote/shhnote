-- Size settings changed from bare byte counts to values with a unit (64K, 10M). Stored
-- values are bytes, so they keep their meaning with a B appended; the ladder is a list.
UPDATE settings SET value = value || 'B' WHERE key IN ('padding_min', 'text_max_bytes') AND value <> '';
UPDATE settings SET value = replace(replace(value, ' ', ''), ',', 'B,') || 'B' WHERE key = 'padding_ladder' AND value <> '';
