-- The 24-hour cleanup's scan column (§8.1). A plain column-list index: §9.1
-- bans partial and expression indexes, so "expired" is a bound cutoff in the
-- WHERE, never a predicate baked into the index.
CREATE INDEX ix_mutation_receipts_created_at ON public.mutation_receipts (created_at)
