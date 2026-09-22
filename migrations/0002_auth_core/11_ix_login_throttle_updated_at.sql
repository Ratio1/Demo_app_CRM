-- Serves `manage cleanup`, which removes throttle rows past retention — the
-- rows are personal data (a pseudonymised identifier, §3.4), so the retention
-- obligation is unchanged by the hashing.
CREATE INDEX ix_login_throttle_updated_at ON public.login_throttle (updated_at)
