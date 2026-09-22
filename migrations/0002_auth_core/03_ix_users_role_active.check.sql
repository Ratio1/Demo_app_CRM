-- Postcondition for 03_ix_users_role_active.
--
-- The one engine-flavoured check in the whole chain (DATA_CONTRACT.md §7.1,
-- §9.3 item 1): index existence has no information_schema view, so every index
-- step reads pg_catalog.pg_class. On an R1DB port these checks are the single
-- known adaptation point.
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_users_role_active' AND relkind = 'i') = 1 AS ok
