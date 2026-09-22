-- Postcondition for 09_grant_sessions: the privilege set is EXACTLY
-- SELECT, INSERT, UPDATE, DELETE and nothing else — no TRUNCATE, no REFERENCES, no TRIGGER.
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT','UPDATE','DELETE')) = 4
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT','UPDATE','DELETE')) = 0
) AS ok
