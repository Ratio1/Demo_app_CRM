-- The runtime role reads, creates and edits deals.
--
-- NO DELETE: a deal is never deleted by the application. It has no archive route
-- of its own either — it follows its parent — so the absence of the
-- privilege is what makes "no deal disappears" structural rather than a
-- convention. Deletion exists only in `reset-demo` and `erase-subject`, under the
-- MAINTENANCE role.
GRANT SELECT, INSERT, UPDATE ON TABLE public.deals TO {grant_to}
