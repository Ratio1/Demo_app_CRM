-- Postcondition for 08_ix_mutation_receipts_created_at (pg_class; see §9.3
-- item 1).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_mutation_receipts_created_at' AND relkind = 'i') = 1 AS ok
