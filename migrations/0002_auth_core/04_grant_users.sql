-- The runtime role reads accounts at login and writes password_hash,
-- password_changed_at, must_change_password, version and updated_at at a
-- password change (§5.2).
--
-- No INSERT: there is no public signup and account creation is CLI-only. No
-- DELETE: accounts are disabled, never removed. The residual — table-level
-- UPDATE also reaches `role` and `is_active` — is accepted in §5.4 because a
-- column-level grant is not portable, and it is fenced by ARC-018 instead.
GRANT SELECT, UPDATE ON TABLE public.users TO {grant_to}
