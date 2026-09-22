-- The scope of an idempotency key is (user_id, operation), and the key binds
-- to the payload digest stored beside it. One user's key
-- can never replay another user's mutation, and one operation's key can never
-- replay another operation's.
--
-- A named UNIQUE constraint, not a bare unique index, precisely so
-- information_schema can see it.
ALTER TABLE public.mutation_receipts ADD CONSTRAINT uq_mutation_receipts_key UNIQUE (user_id, operation, idempotency_key)
