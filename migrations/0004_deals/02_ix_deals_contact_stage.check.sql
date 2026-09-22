-- Postcondition for 02_ix_deals_contact_stage (pg_class; see DATA_CONTRACT.md
-- §9.3 item 1 — index existence has no information_schema view, and this is the
-- single known adaptation point for an R1DB port).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_deals_contact_stage' AND relkind = 'i') = 1 AS ok
