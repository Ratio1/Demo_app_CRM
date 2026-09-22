-- Postcondition for 06_mutation_receipts: nine columns, every one of
-- them NOT NULL, and the foreign key to `users` present.
--
-- As in 05_sessions, the column list is asserted twice: the named nine are
-- present, and the table has exactly nine. Either alone would pass a schema
-- carrying an extra column.
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
          AND column_name IN ('id','user_id','operation','idempotency_key','payload_sha256',
                              'result_status','result_object_type','result_object_id',
                              'created_at')) = 9
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts') = 9
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
          AND is_nullable = 'NO') = 9
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'mutation_receipts'
          AND constraint_name = 'fk_mutation_receipts_user_id'
          AND constraint_type = 'FOREIGN KEY') = 1
) AS ok
