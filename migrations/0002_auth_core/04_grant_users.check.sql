-- Postcondition for 04_grant_users: the runtime role's privilege set on
-- `users` is EXACTLY SELECT and UPDATE, and nothing else.
--
-- The two-conjunct shape is what catches an OVER-grant, which a `>= n` check
-- would not. The runner composes {grant_to_name} as a
-- psycopg.sql.Literal; running this file by hand, substitute 'crm_app' (or
-- 'crm_test_app' on the scratch database).
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'users'
          AND grantee = {grant_to_name} AND privilege_type IN ('SELECT','UPDATE')) = 2
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'users'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','UPDATE')) = 0
) AS ok
