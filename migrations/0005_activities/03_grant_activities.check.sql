-- Postcondition for 03_grant_activities: the privilege set is EXACTLY SELECT
-- and INSERT and nothing else — no UPDATE, no DELETE, no TRUNCATE, no
-- REFERENCES, no TRIGGER. The two-conjunct shape is what catches an
-- OVER-grant, which an "at least n" check would not (DATA_CONTRACT.md §7.2),
-- and an over-grant here would silently make the table mutable.
--
-- The runner composes {grant_to_name} as a psycopg.sql.Literal; running this
-- file by hand, substitute 'crm_app' (or 'crm_test_app' on the scratch
-- database).
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT')) = 2
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT')) = 0
) AS ok
