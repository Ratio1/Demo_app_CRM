-- Serves the last-active-admin count (§6.9, SQL-014) and create-user's role
-- checks. It is the only query on `users` that is not a primary-key or unique
-- lookup, which is why it is the only index on the table.
CREATE INDEX ix_users_role_active ON public.users (role, is_active)
