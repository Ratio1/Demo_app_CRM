-- Postcondition for 04_ix_contacts_owner_email (pg_class; see §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_contacts_owner_email' AND relkind = 'i') = 1 AS ok
