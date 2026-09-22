-- DATA_CONTRACT.md §3.8. User- and operation-scoped idempotency.
--
-- A surrogate `id` PK plus a unique business key (step 07), rather than a
-- composite PK, so the 24-hour cleanup can batch by a single column
-- (WHERE id IN (SELECT id … LIMIT 1000), §8.1) without a row-constructor IN,
-- which §9.1 bans.
--
-- WRITE-ONCE: the runtime role gets SELECT and INSERT and never UPDATE
-- (step 09). `uq_mutation_receipts_key` is the constraint whose 23505 means
-- *duplicate submission* (§6.4) — and, because it is the only non-PK UNIQUE
-- reachable from a Slice B business transaction, a 23505 there needs no
-- constraint-name inspection to classify.
--
-- `user_id` cascades: receipts are 24-hour operational state, not audit. It is
-- the leading column of step 07's unique key, which satisfies §2.3 rule 5.
CREATE TABLE public.mutation_receipts (
  id                 TEXT NOT NULL,
  user_id            TEXT NOT NULL,
  operation          TEXT NOT NULL,
  idempotency_key    TEXT NOT NULL,
  payload_sha256     TEXT NOT NULL,
  result_status      TEXT NOT NULL,
  result_object_type TEXT NOT NULL,
  result_object_id   TEXT NOT NULL,
  created_at         TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_mutation_receipts PRIMARY KEY (id),
  CONSTRAINT fk_mutation_receipts_user_id
    FOREIGN KEY (user_id) REFERENCES public.users (id) ON DELETE CASCADE,
  CONSTRAINT ck_mutation_receipts_id CHECK (char_length(id) = 36
                                        AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_mutation_receipts_key CHECK (char_length(idempotency_key) = 36
                                         AND idempotency_key LIKE
                                             '________-____-____-____-____________'),
  CONSTRAINT ck_mutation_receipts_payload CHECK (char_length(payload_sha256) = 64),
  CONSTRAINT ck_mutation_receipts_operation CHECK (operation IN (
    'contact_create', 'contact_update', 'contact_archive', 'contact_restore',
    'contact_reassign', 'deal_create', 'deal_update', 'deal_stage_change',
    'activity_create')),
  CONSTRAINT ck_mutation_receipts_status CHECK (result_status IN (
    'created', 'updated', 'archived', 'restored', 'reassigned')),
  CONSTRAINT ck_mutation_receipts_object_type
    CHECK (result_object_type IN ('contact', 'deal', 'activity')),
  CONSTRAINT ck_mutation_receipts_object_id CHECK (char_length(result_object_id) = 36)
)
