-- Postcondition for 02_ix_activities_contact_occurred: the index exists on the
-- right table, and its definition carries both DESC keys.
--
-- The second conjunct reads `pg_indexes.indexdef` rather than counting
-- columns, because an index on the same three columns in ASC order would
-- satisfy a column-set check while serving the timeline's ORDER BY only as a
-- backwards scan the planner may decline.
SELECT (
      (SELECT count(*) FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'activities'
          AND indexname = 'ix_activities_contact_occurred') = 1
  AND (SELECT count(*) FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'activities'
          AND indexname = 'ix_activities_contact_occurred'
          AND indexdef LIKE '%contact_id%occurred_on DESC%created_at DESC%') = 1
) AS ok
