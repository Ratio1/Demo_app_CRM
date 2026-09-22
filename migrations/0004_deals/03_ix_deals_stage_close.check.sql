-- Postcondition for 03_ix_deals_stage_close (pg_class — index existence has no
-- information_schema view, so every index step reads the catalog directly).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_deals_stage_close' AND relkind = 'i') = 1 AS ok
