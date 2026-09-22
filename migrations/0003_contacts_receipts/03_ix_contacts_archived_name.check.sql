-- Postcondition for 03_ix_contacts_archived_name (pg_class; see §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_contacts_archived_name' AND relkind = 'i') = 1 AS ok
