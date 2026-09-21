-- Postcondition for 01_schema_migrations: the journal exists with exactly the
-- five columns the runner reads and writes.
--
-- information_schema is standard SQL and lists only objects the current role
-- may touch, so this is portable and answers for the role that will use it.
SELECT count(*) = 5 AS ok
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'schema_migrations'
  AND column_name IN ('migration_id', 'step_id', 'checksum', 'applied_at', 'verified_at')
