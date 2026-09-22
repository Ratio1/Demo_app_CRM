-- Postcondition for 07_ix_sessions_user_id (pg_class; see §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_sessions_user_id' AND relkind = 'i') = 1 AS ok
