-- The full four: create a pre-auth row, touch a live one, rotate at login and
-- at a password change, delete at logout and on revocation (§5.2). Sessions
-- are the one table the runtime role may DELETE from, and that is exactly
-- because revocation is a delete rather than a flag (§3.3).
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sessions TO {grant_to}
