-- Postcondition for 20_grant_audit_events: the privilege set is EXACTLY
-- INSERT and SELECT, and nothing else. The exact-set shape is what makes
-- "the runtime cannot edit or delete an audit row" checkable rather than
-- merely asserted: a later over-grant fails this step.
SELECT (
      (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND grantee = {grant_to_name} AND privilege_type IN ('INSERT','SELECT')) = 2
  AND (SELECT count(*) FROM information_schema.table_privileges
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND grantee = {grant_to_name}
          AND privilege_type NOT IN ('INSERT','SELECT')) = 0
) AS ok
