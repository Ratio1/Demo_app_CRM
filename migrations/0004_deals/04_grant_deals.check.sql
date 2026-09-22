-- Postcondition for 04_grant_deals: the privilege set is EXACTLY SELECT, INSERT
-- and UPDATE and nothing else — no DELETE, no TRUNCATE, no REFERENCES, no
-- TRIGGER. The two-conjunct shape is what catches an OVER-grant, which an
-- "at least n" check would not. The runner composes
-- {grant_to_name} as a psycopg.sql.Literal; running this file by hand,
-- substitute 'crm_app' (or 'crm_test_app' on the scratch database).
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT','UPDATE')) = 3
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT','UPDATE')) = 0
) AS ok
