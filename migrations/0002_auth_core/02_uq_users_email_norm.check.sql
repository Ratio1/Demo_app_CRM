-- Postcondition for 02_uq_users_email_norm: the named UNIQUE constraint is
-- present. A unique *index* of the same name would not appear here, which is
-- why the step writes a constraint (DATA_CONTRACT.md §7.2).
SELECT (SELECT count(*) FROM information_schema.table_constraints
         WHERE table_schema = 'public' AND table_name = 'users'
           AND constraint_name = 'uq_users_email_norm'
           AND constraint_type = 'UNIQUE') = 1 AS ok
