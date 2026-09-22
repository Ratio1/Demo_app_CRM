-- Postcondition for 08_ix_mutation_receipts_created_at (pg_class).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_mutation_receipts_created_at' AND relkind = 'i') = 1 AS ok
