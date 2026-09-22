-- Postcondition for 12_grant_login_throttle: EXACTLY SELECT, INSERT, UPDATE and nothing else
-- and therefore no DELETE.
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT','UPDATE')) = 3
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT','UPDATE')) = 0
) AS ok
