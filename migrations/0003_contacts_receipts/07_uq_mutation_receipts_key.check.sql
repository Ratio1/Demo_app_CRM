-- Postcondition for 07_uq_mutation_receipts_key: the named UNIQUE constraint
-- is present. It is the constraint whose 23505 means "duplicate submission",
-- so its absence would turn a replay into a second business write.
SELECT (SELECT count(*) FROM information_schema.table_constraints
         WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
           AND constraint_name = 'uq_mutation_receipts_key'
           AND constraint_type = 'UNIQUE') = 1 AS ok
