-- Postcondition for 06_uq_sessions_token_sha256: the named UNIQUE constraint
-- is present.
SELECT (SELECT count(*) FROM information_schema.table_constraints
         WHERE table_schema = 'public' AND table_name = 'sessions'
           AND constraint_name = 'uq_sessions_token_sha256'
           AND constraint_type = 'UNIQUE') = 1 AS ok
