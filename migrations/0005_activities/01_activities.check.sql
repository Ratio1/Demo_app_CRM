-- Postcondition for 01_activities, in the shape 0004_deals/01 established.
-- Eleven conjuncts.
--
-- Conjuncts 2 and 3 are the pair: the named seven are present AND the table
-- has exactly seven, so an extra column fails. Conjunct 4 names the four
-- absences explicitly — `owner_id`, `archived_at`, `version`, `updated_at` —
-- although 2+3 already imply them: a reviewer should be able to read the
-- absence rather than derive it.
--
-- Conjuncts 5 and 6 are "created_by_user_id is the only nullable column";
-- either alone is satisfiable by a wrong schema.
--
-- Conjunct 7 pins `occurred_on` as DATE, not a timestamp: without it the
-- migration would journal a table whose day column silently carries a time
-- zone and every rendered day could differ from the day that was submitted.
--
-- Conjuncts 8-10 are the two foreign keys and their referential actions read
-- from `information_schema.referential_constraints`: RESTRICT on the parent
-- and SET NULL on the author are what make an activity outlive both the
-- account that logged it and any attempt to delete its contact, and a CASCADE
-- substituted for either would pass a "has a foreign key" check.
--
-- Conjunct 11 records that `activities` carries NO UNIQUE constraint besides
-- its PK, so a 23505 inside an activity transaction still means the
-- idempotency receipt key and needs no constraint-name inspection.
SELECT (
      (SELECT count(*) FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'activities') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND column_name IN ('id','contact_id','kind','occurred_on','summary',
                              'created_by_user_id','created_at')) = 7
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities') = 7
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND column_name IN ('owner_id','archived_at','version','updated_at')) = 0
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND is_nullable = 'YES' AND column_name = 'created_by_user_id') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND is_nullable = 'YES') = 1
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND column_name = 'occurred_on' AND data_type = 'date') = 1
  AND (SELECT count(*) FROM information_schema.referential_constraints
        WHERE constraint_schema = 'public'
          AND constraint_name = 'fk_activities_contact_id'
          AND delete_rule = 'RESTRICT') = 1
  AND (SELECT count(*) FROM information_schema.referential_constraints
        WHERE constraint_schema = 'public'
          AND constraint_name = 'fk_activities_created_by_user_id'
          AND delete_rule = 'SET NULL') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND constraint_name = 'ck_activities_kind' AND constraint_type = 'CHECK') = 1
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'activities'
          AND constraint_type = 'UNIQUE') = 0
) AS ok
