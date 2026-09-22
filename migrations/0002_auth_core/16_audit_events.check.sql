-- Postcondition for 16_audit_events: eight columns; `actor_user_id` and
-- `object_id` the only nullable ones; ZERO foreign key constraints on the
-- table; and the three CHECKs this slice's behaviour rests on present by name
-- (DATA_CONTRACT.md §7.3).
--
-- The 31 actions and 7 object types are NOT counted here. There is no
-- portable way to enumerate an IN-list from the catalog, and parsing
-- `check_clause` would pin this file to one engine's rendering of a
-- constraint. The vocabulary is carried by the step file's SHA-256 in
-- `schema_migrations`, which is compared on every readiness probe, and it is
-- enforced at runtime by the CHECK itself: an INSERT naming a value outside
-- the list is rejected 23514 (verified, DATA_CONTRACT.md §1.2 probe 9).
SELECT (
      (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND column_name IN ('id','at','actor_user_id','object_type','object_id',
                              'action','outcome','correlation_id')) = 8
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'audit_events') = 8
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND is_nullable = 'YES') = 2
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND is_nullable = 'YES'
          AND column_name IN ('actor_user_id','object_id')) = 2
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND constraint_type = 'FOREIGN KEY') = 0
  AND (SELECT count(*) FROM information_schema.table_constraints
        WHERE table_schema = 'public' AND table_name = 'audit_events'
          AND constraint_type = 'CHECK'
          AND constraint_name IN ('ck_audit_events_denied',
                                  'ck_audit_events_action',
                                  'ck_audit_events_object_type')) = 3
) AS ok
