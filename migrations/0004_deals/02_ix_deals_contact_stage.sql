-- Indexes the FK (§2.3 rule 5), serves the per-contact deal region of
-- contacts/detail.html (PIN C7) and is the inner side of the nested loop for
-- every ownership-filtered deal query and aggregate (DATA_CONTRACT.md §3.10).
CREATE INDEX ix_deals_contact_stage ON public.deals (contact_id, stage)
