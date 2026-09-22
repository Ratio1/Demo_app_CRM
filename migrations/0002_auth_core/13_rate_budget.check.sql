-- Postcondition for 13_rate_budget: five columns, all NOT NULL, and a
-- three-column composite primary key (DATA_CONTRACT.md §7.3).
--
-- `key_column_usage` is the standard view that says how many columns a named
-- constraint covers; counting its rows is how "composite PK" is asserted
-- without reading pg_catalog.
SELECT (
      (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'rate_budget'
          AND column_name IN ('bucket','subject_key','window_start','counter',
                              'updated_at')) = 5
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'rate_budget') = 5
  AND (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'rate_budget'
          AND is_nullable = 'NO') = 5
  AND (SELECT count(*) FROM information_schema.key_column_usage
        WHERE table_schema = 'public' AND table_name = 'rate_budget'
          AND constraint_name = 'pk_rate_budget') = 3
) AS ok
