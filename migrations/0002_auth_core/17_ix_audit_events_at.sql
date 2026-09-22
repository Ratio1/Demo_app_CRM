-- Serves retention cleanup and the newest-first view. At ninety days of
-- tutorial traffic this is the largest table by row count, which is why it
-- carries three indexes and no other table in this schema carries more than
-- two.
CREATE INDEX ix_audit_events_at ON public.audit_events (at)
