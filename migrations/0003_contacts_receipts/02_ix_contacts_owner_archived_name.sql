-- The agent-scope list, count, search and every ownership-filtered aggregate:
-- equality on `owner_id`, `archived_at IS NULL`, an optional prefix LIKE, and
-- the ordering `full_name_lower, id`. One index serves all four.
CREATE INDEX ix_contacts_owner_archived_name ON public.contacts (owner_id, archived_at, full_name_lower, id)
