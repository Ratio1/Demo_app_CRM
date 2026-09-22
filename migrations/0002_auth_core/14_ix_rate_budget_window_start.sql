-- Serves `manage cleanup`: every window older than retention is dropped in
-- bounded batches, and without this index that scan grows with traffic.
CREATE INDEX ix_rate_budget_window_start ON public.rate_budget (window_start)
