-- Postcondition for 01_contacts. Seven conjuncts for five separate claims,
-- because two of the claims are *absences*, which only an exact count can
-- catch.
--
-- Conjuncts 4 and 5 together are "archived_at is the only nullable column":
-- the first says it IS nullable, the second that NOTHING else is. Either alone
-- is satisfiable by a wrong schema.
--
-- Conjunct 7 asserts at migration time, rather than only in the test suite,
-- that there are zero UNIQUE constraints on `contacts`, so no
-- future step can add one without this check failing. "No column named
-- `status`" is carried by conjunct 3 — a `status` column would make the total
-- 15 while the IN-list count stayed 14.
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'contacts') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND column_name IN ('id','owner_id','full_name','full_name_lower','company',
                              'company_lower','email','email_lower','phone','kind',
                              'archived_at','version','created_at','updated_at')) = 14
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'contacts') = 14
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND is_nullable = 'YES' AND column_name = 'archived_at') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND constraint_name = 'fk_contacts_owner_id'
          AND constraint_type = 'FOREIGN KEY') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND constraint_type = 'UNIQUE') = 0
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'contacts'
          AND constraint_name = 'ck_contacts_kind' AND constraint_type = 'CHECK') = 1
) AS ok
