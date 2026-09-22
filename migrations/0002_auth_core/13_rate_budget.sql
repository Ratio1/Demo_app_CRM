-- DATA_CONTRACT.md §3.5. The four bounded windows: the global login and
-- pre-auth budgets and the two per-account budgets, sharing one table because
-- they share one access pattern.
--
-- `subject_key` is the literal '*' for the two global buckets and the user id
-- for the account_* ones. `window_start` is floored to the minute IN PYTHON —
-- never date_trunc, never the server's clock — so the window boundary cannot
-- depend on the engine's date functions.
--
-- The composite primary key is the whole identity of a counter: a new window
-- is a new row, which is what makes the §6.5 idiom's INSERT the natural path
-- at the top of each minute.
CREATE TABLE public.rate_budget (
  bucket       TEXT    NOT NULL,
  subject_key  TEXT    NOT NULL,
  window_start TIMESTAMP WITH TIME ZONE NOT NULL,
  counter      INTEGER NOT NULL,
  updated_at   TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_rate_budget PRIMARY KEY (bucket, subject_key, window_start),
  CONSTRAINT ck_rate_budget_bucket
    CHECK (bucket IN ('login_global', 'preauth_global', 'account_mutation', 'account_query')),
  CONSTRAINT ck_rate_budget_subject CHECK (char_length(subject_key) BETWEEN 1 AND 254),
  CONSTRAINT ck_rate_budget_counter CHECK (counter >= 0)
)
