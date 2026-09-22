-- Postcondition for 02_ix_contacts_owner_archived_name (pg_class; see §9.3
-- item 1 — index existence has no information_schema view, and this is the
-- single known adaptation point for an R1DB port).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_contacts_owner_archived_name' AND relkind = 'i') = 1 AS ok
