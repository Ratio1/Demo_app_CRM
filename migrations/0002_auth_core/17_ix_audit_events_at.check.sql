-- Postcondition for 17_ix_audit_events_at (pg_class; §9.3 item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_audit_events_at' AND relkind = 'i') = 1 AS ok
