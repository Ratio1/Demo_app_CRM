-- Postcondition for 02_ix_contacts_owner_archived_name (pg_class — index
-- existence has no information_schema view, so every index step reads the
-- catalog directly).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_contacts_owner_archived_name' AND relkind = 'i') = 1 AS ok
