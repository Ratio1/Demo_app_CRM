-- Serves `manage cleanup`, which deletes sessions past their absolute expiry
-- in bounded batches (§8.1).
CREATE INDEX ix_sessions_absolute_expires_at ON public.sessions (absolute_expires_at)
