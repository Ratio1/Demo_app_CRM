-- Postcondition for 11_ix_login_throttle_updated_at (pg_class; §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_login_throttle_updated_at' AND relkind = 'i') = 1 AS ok
