-- Postcondition for 03_grant_journal_select: the runtime role holds SELECT on
-- the journal, and the check says so only because the grant exists.
--
-- information_schema.table_privileges is standard SQL and carries one row per
-- direct grant, so unlike the schema check above this cannot be satisfied by
-- an inherited default. It is visible to the migration role because that role
-- is the grantor.
SELECT EXISTS (
  SELECT 1
  FROM information_schema.table_privileges
  WHERE table_schema = 'public'
    AND table_name = 'schema_migrations'
    AND grantee = {grant_to_name}
    AND privilege_type = 'SELECT'
) AS ok
