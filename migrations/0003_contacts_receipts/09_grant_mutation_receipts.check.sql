-- Postcondition for 09_grant_mutation_receipts: the privilege set is EXACTLY
-- SELECT and INSERT and nothing else — no UPDATE, no DELETE, no TRUNCATE, no
-- REFERENCES, no TRIGGER. The second conjunct is what makes this an
-- assertion about write-once rather than about reachability (§7.2).
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
          AND grantee = {grant_to_name}
          AND privilege_type IN ('SELECT','INSERT')) = 2
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('SELECT','INSERT')) = 0
) AS ok
