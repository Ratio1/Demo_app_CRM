-- Serves "this object's trail". It is also why §3.6 removed object_type
-- 'subject': splitting a user's erasure under a second type would hide it
-- from that user's own trail, which is this index's whole job.
CREATE INDEX ix_audit_events_object ON public.audit_events (object_type, object_id, at)
