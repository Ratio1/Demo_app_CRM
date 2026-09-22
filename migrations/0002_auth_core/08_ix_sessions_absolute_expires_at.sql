-- Serves `manage cleanup`, which deletes sessions past their absolute expiry
-- in bounded batches.
CREATE INDEX ix_sessions_absolute_expires_at ON public.sessions (absolute_expires_at)
