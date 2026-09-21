-- The migration journal itself. app.db.journal.ensure_journal_table runs this
-- statement before reading the journal, and the same text is journaled as the
-- first step so the manifest covers every object the runner creates. CREATE
-- TABLE IF NOT EXISTS keeps both paths idempotent: whichever runs first, the
-- other is a no-op.
CREATE TABLE IF NOT EXISTS public.schema_migrations (
  migration_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMP WITH TIME ZONE NOT NULL,
  verified_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT schema_migrations_pkey PRIMARY KEY (migration_id, step_id),
  CONSTRAINT schema_migrations_checksum_length CHECK (char_length(checksum) = 64)
)
