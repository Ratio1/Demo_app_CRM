-- Postcondition for 01_deals (DATA_CONTRACT.md §7.5, PIN C1). Twelve conjuncts.
--
-- Conjuncts 2 and 3 are the pair: the named eleven are present AND the table has
-- exactly eleven, so an extra column fails. Conjunct 4 names the two absences
-- §7.5 asks for explicitly — `owner_id` and `archived_at` — although 2+3 already
-- imply them: a reviewer should be able to read the absence, not derive it.
--
-- Conjuncts 5 and 6 are "close_date is the only nullable column"; either alone is
-- satisfiable by a wrong schema.
--
-- Conjuncts 7 and 8 are PIN C1's whole money contract at the schema level:
-- numeric(12,2), not numeric, not float, not VARCHAR; and DATE, not a timestamp.
-- Without conjunct 7 the migration would happily journal a table whose amounts
-- are `double precision` and every €-rendering downstream would be wrong.
--
-- Conjunct 12 records that `deals` carries NO UNIQUE constraint besides its PK,
-- so a 23505 inside a Slice C business transaction still means the RECEIPT key
-- and needs no constraint-name inspection (contracts/slice-b.md §1(d)).
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'deals') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND column_name IN ('id','contact_id','title','title_lower','amount','close_date',
                              'stage','stage_changed_at','version','created_at',
                              'updated_at')) = 11
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals') = 11
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND column_name IN ('owner_id','archived_at')) = 0
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND is_nullable = 'YES' AND column_name = 'close_date') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND column_name = 'amount' AND data_type = 'numeric'
          AND numeric_precision = 12 AND numeric_scale = 2) = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND column_name = 'close_date' AND data_type = 'date') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND constraint_name = 'fk_deals_contact_id' AND constraint_type = 'FOREIGN KEY') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND constraint_name = 'ck_deals_stage' AND constraint_type = 'CHECK') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND constraint_name = 'ck_deals_amount_nonneg' AND constraint_type = 'CHECK') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'deals'
          AND constraint_type = 'UNIQUE') = 0
) AS ok
