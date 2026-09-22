-- The admin pipeline and the stage-scoped card statements, ordered within a
-- stage.
CREATE INDEX ix_deals_stage_close ON public.deals (stage, close_date, id)
