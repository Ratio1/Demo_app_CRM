-- The scope of an idempotency key is (user_id, operation) — spec §5's
-- "user/operation-scoped idempotency keys bind to payloads". One user's key
-- can never replay another user's mutation, and one operation's key can never
-- replay another operation's.
--
-- A named UNIQUE constraint, not a bare unique index, precisely so
-- information_schema can see it (§7.2).
ALTER TABLE public.mutation_receipts ADD CONSTRAINT uq_mutation_receipts_key UNIQUE (user_id, operation, idempotency_key)
