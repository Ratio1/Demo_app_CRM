-- Postcondition for 01_users: the table exists with exactly its twelve
-- columns, and every one of them is NOT NULL (DATA_CONTRACT.md §7.2/§7.3).
--
-- The third conjunct is what makes "twelve columns" exact rather than "at
-- least these twelve": a column added outside this contract would leave the
-- IN-count at 12 and go unnoticed.
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'users') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users'
          AND column_name IN ('id','email','email_norm','display_name','role','password_hash',
                              'password_changed_at','must_change_password','is_active','version',
                              'created_at','updated_at')) = 12
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users') = 12
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users'
          AND is_nullable = 'NO') = 12
) AS ok
