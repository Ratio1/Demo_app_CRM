-- Postcondition for 19_ix_audit_events_actor (pg_class).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_audit_events_actor' AND relkind = 'i') = 1 AS ok
