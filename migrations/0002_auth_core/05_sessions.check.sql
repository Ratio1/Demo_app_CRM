-- Postcondition for 05_sessions: nine columns, `user_id` the only nullable
-- one, and the foreign key to `users` present (DATA_CONTRACT.md §7.3).
--
-- The nullability pair is stated twice on purpose: "exactly one nullable
-- column" and "that column is user_id". Either alone would pass a schema
-- where the wrong column had been relaxed.
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sessions') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND column_name IN ('id','token_sha256','csrf_sha256','kind','user_id',
                              'created_at','last_seen_at','idle_expires_at',
                              'absolute_expires_at')) = 9
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions') = 9
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND column_name = 'user_id' AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'sessions'
          AND constraint_name = 'fk_sessions_user_id'
          AND constraint_type = 'FOREIGN KEY') = 1
) AS ok
