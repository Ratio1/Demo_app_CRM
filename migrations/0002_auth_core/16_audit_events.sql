-- Append-only, identifiers only: no payload, no record
-- bodies, no free text. A failed login against a non-existent account records
-- actor_user_id NULL / object_type 'user' / object_id NULL — the attempted
-- identifier reaches only login_throttle, and there only as a hash.
--
-- NO foreign keys, by design and on two grounds: a referential action would
-- execute with the constraint's own authority and let a maintenance
-- DELETE FROM users rewrite or remove audit rows, which is precisely the write
-- the runtime role is denied; and an audit row must OUTLIVE its subject as an
-- identifier-only record, so a dangling actor_user_id after an erasure is the
-- intended end state.
--
-- The action allowlist holds 31 values and object_type holds 7. Both lists
-- were trimmed to what the code actually writes: 'session_revoked' and
-- 'user_role_changed' are absent because no code path writes them, and
-- object_type 'dashboard' and 'subject' are absent for the same reason. A
-- value a security-relevant
-- allowlist admits but nothing writes reads as evidence that the application
-- records something it does not.
--
-- `ck_audit_events_denied` is an IFF, and it is what keeps the deny-audit
-- rows honest: a denial action can never claim 'success' or 'failure', and
-- 'denied' can never attach to a business verb.
CREATE TABLE public.audit_events (
  id             TEXT NOT NULL,
  at             TIMESTAMP WITH TIME ZONE NOT NULL,
  actor_user_id  TEXT,
  object_type    TEXT NOT NULL,
  object_id      TEXT,
  action         TEXT NOT NULL,
  outcome        TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  CONSTRAINT pk_audit_events PRIMARY KEY (id),
  CONSTRAINT ck_audit_events_id CHECK (char_length(id) = 36
                                   AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_audit_events_actor
    CHECK (actor_user_id IS NULL OR char_length(actor_user_id) = 36),
  CONSTRAINT ck_audit_events_object_type
    CHECK (object_type IN ('user', 'session', 'contact', 'deal', 'activity',
                           'settings', 'system')),
  CONSTRAINT ck_audit_events_object_id
    CHECK (object_id IS NULL OR char_length(object_id) BETWEEN 1 AND 36),
  CONSTRAINT ck_audit_events_action CHECK (action IN (
    'login_succeeded', 'login_failed', 'logout',
    'password_changed', 'password_reset', 'throttle_locked',
    'user_created', 'user_disabled',
    'origin_set', 'provisioned',
    'contact_created', 'contact_updated', 'contact_archived', 'contact_restored',
    'contact_reassigned',
    'deal_created', 'deal_updated', 'deal_stage_changed',
    'activity_created',
    'subject_exported', 'subject_export_dry_run', 'subject_erased',
    'subject_erase_dry_run',
    'demo_seeded', 'demo_reset', 'cleanup_completed',
    'access_denied', 'role_denied', 'forced_reset_blocked',
    'input_rejected', 'budget_denied')),
  CONSTRAINT ck_audit_events_outcome CHECK (outcome IN ('success', 'denied', 'failure')),
  CONSTRAINT ck_audit_events_denied CHECK (
    (outcome = 'denied'
       AND action IN ('access_denied', 'role_denied', 'forced_reset_blocked',
                      'input_rejected', 'budget_denied', 'throttle_locked'))
    OR
    (outcome <> 'denied'
       AND action NOT IN ('access_denied', 'role_denied', 'forced_reset_blocked',
                          'input_rejected', 'budget_denied', 'throttle_locked'))),
  CONSTRAINT ck_audit_events_correlation CHECK (char_length(correlation_id) = 36)
)
