-- One row per token digest. The lookup on every authenticated request is
-- `WHERE token_sha256 = ...`, so this constraint is also that path's index,
-- and it is what makes a token collision a database error rather than an
-- ambiguous session.
ALTER TABLE public.sessions ADD CONSTRAINT uq_sessions_token_sha256 UNIQUE (token_sha256)
