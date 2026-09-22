-- Postcondition for 03_ix_users_role_active.
--
-- The one engine-flavoured check in the whole chain: index existence has no
-- information_schema view, so every index step reads pg_catalog.pg_class. On
-- a port to another engine these checks are the single known adaptation
-- point; every other postcondition in the chain is standard SQL.
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_users_role_active' AND relkind = 'i') = 1 AS ok
