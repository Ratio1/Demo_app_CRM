-- The runtime role may read the journal, and only read it.
--
-- /health/ready compares the image's expected manifest against
-- schema_migrations while holding the DML-only runtime role, so that role
-- needs SELECT here. It is never granted INSERT, UPDATE or DELETE: the journal
-- is written once, outside serving, by the migration role.
GRANT SELECT ON TABLE public.schema_migrations TO {grant_to}
