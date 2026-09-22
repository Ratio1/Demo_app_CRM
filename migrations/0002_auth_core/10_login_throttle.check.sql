-- Postcondition for 10_login_throttle: five columns, `locked_until` the only
-- nullable one, zero foreign keys, and `ck_login_throttle_key` present
-- (DATA_CONTRACT.md §7.3).
--
-- The CHECK is asserted by NAME, not by parsing its clause. What the
-- constraint says — `char_length(account_key) = 64`, the R13 hash bound — is
-- pinned by the step file's SHA-256 in `schema_migrations`: the checksum is
-- the artefact that cannot drift, whereas `check_clause` is rendered text
-- whose spelling is the engine's business and would make this file a second
-- portability adaptation point beyond the one §9.3 admits.
SELECT (
      (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND column_name IN ('account_key','failure_count','window_started_at',
                              'locked_until','updated_at')) = 5
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'login_throttle') = 5
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND column_name = 'locked_until' AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND constraint_type = 'FOREIGN KEY') = 0
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'login_throttle'
          AND constraint_name = 'ck_login_throttle_key'
          AND constraint_type = 'CHECK') = 1
) AS ok
