-- The login lookup key is unique. `email_norm` is `email.strip().lower()`
-- computed in Python (§3.2): no expression index, no citext, and deliberately
-- no CHECK asserting `email_norm = lower(email)`, because lower() is
-- collation-dependent and a constraint whose meaning can change with a
-- collation is worse than an application invariant plus a test.
--
-- A named UNIQUE *constraint*, not a bare unique index, precisely so that
-- information_schema.table_constraints can see it (§7.2).
ALTER TABLE public.users ADD CONSTRAINT uq_users_email_norm UNIQUE (email_norm)
