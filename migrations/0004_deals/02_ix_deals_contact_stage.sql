-- Indexes the FK, serves the per-contact deal region of
-- contacts/detail.html and is the inner side of the nested loop for
-- every ownership-filtered deal query and aggregate.
CREATE INDEX ix_deals_contact_stage ON public.deals (contact_id, stage)
