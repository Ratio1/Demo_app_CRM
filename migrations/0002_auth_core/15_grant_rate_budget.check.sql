-- Postcondition for 15_grant_rate_budget: EXACTLY SELECT, INSERT, UPDATE and nothing else.
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'rate_budget'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT','UPDATE')) = 3
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'rate_budget'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT','UPDATE')) = 0
) AS ok
