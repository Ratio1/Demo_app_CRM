-- Postcondition for 14_ix_rate_budget_window_start (pg_class).
SELECT (SELECT count(*) FROM pg_catalog.pg_class
         WHERE relname = 'ix_rate_budget_window_start' AND relkind = 'i') = 1 AS ok
