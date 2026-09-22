-- Postcondition for 08_ix_sessions_absolute_expires_at (pg_class; §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_sessions_absolute_expires_at' AND relkind = 'i') = 1 AS ok
