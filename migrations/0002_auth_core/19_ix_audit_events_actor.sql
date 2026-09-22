-- Serves `manage export-subject`: everything one actor did, newest first.
CREATE INDEX ix_audit_events_actor ON public.audit_events (actor_user_id, at)
