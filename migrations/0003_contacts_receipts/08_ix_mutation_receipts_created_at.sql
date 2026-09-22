-- The 24-hour cleanup's scan column. A plain column-list index: this schema
-- uses no partial or expression indexes, so "expired" is a bound cutoff in
-- the WHERE, never a predicate baked into the index.
CREATE INDEX ix_mutation_receipts_created_at ON public.mutation_receipts (created_at)
