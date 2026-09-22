-- Indexes the parent FK (§2.3 rule 5) and serves the one ordering the timeline
-- ever asks for: newest first within one contact, `occurred_on DESC` with
-- `created_at DESC` as the tiebreaker, so two activities logged for the same
-- day keep the order they were written in.
--
-- The column order matters: `contact_id` leads because every timeline read and
-- every count is per contact, and the two DESC keys then make the page an
-- index walk rather than a sort above a filter. A separate index on
-- `created_by_user_id` is deliberately absent — nothing queries by author, and
-- the only statement that touches that column on write is an ON DELETE SET
-- NULL the application never issues.
CREATE INDEX ix_activities_contact_occurred
  ON public.activities (contact_id, occurred_on DESC, created_at DESC)
