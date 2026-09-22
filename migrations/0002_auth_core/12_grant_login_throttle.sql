-- Counter read-modify-write: SELECT to read the state, UPDATE to increment or
-- roll the window over, INSERT for the first failure against a key (the
-- counter idiom updates first and inserts only when no row was touched).
-- NO DELETE — expiry is maintenance's job, and
-- `clear_throttle` on a successful login is an UPDATE for exactly this reason.
GRANT SELECT, INSERT, UPDATE ON TABLE public.login_throttle TO {grant_to}
