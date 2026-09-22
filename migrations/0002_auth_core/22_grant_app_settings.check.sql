-- Postcondition for 22_grant_app_settings: the privilege set is EXACTLY
-- SELECT alone. An INSERT or UPDATE reaching the runtime role here would let a
-- serving-path foothold repoint the stored origin, which is the value step 0a
-- compares every Host and Origin header against.
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'app_settings'
          AND grantee = {grant_to_name} AND privilege_type = 'SELECT') = 1
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'app_settings'
          AND grantee = {grant_to_name} AND privilege_type <> 'SELECT') = 0
) AS ok
