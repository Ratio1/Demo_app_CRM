-- The same as step 02 for admin scope, which has no `owner_id` equality
-- (§3.9).
CREATE INDEX ix_contacts_archived_name ON public.contacts (archived_at, full_name_lower, id)
