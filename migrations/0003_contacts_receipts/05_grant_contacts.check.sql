-- Postcondition for 05_grant_contacts: the privilege set is EXACTLY
-- SELECT, INSERT and UPDATE and nothing else — no DELETE, no TRUNCATE, no
-- REFERENCES, no TRIGGER. The two-conjunct shape is what catches an
-- OVER-grant, which a "at least n" check would not (§7.2).
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT','UPDATE')) = 3
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT','UPDATE')) = 0
) AS ok
