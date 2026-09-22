-- Serves `manage cleanup`, which removes throttle rows past retention — the
-- rows are personal data (`account_key` is a pseudonymised identifier, not an
-- address, but it is still derived from one), so the retention
-- obligation is unchanged by the hashing.
CREATE INDEX ix_login_throttle_updated_at ON public.login_throttle (updated_at)
