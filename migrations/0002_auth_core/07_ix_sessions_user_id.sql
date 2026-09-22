-- Serves revoke-all-for-user (password change, reset-password, disable-user)
-- and indexes the foreign key: PostgreSQL does not index one automatically,
-- and without it every ON DELETE CASCADE check scans this table.
CREATE INDEX ix_sessions_user_id ON public.sessions (user_id)
