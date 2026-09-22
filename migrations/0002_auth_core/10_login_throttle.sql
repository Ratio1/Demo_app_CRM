-- DATA_CONTRACT.md §3.4. Five failures per account per fifteen minutes, with
-- backoff (S6); the constants live in code, never here.
--
-- `account_key` is sha256(submitted.strip().lower()) — the identifier HASH,
-- never the address (ruling R13). `ck_login_throttle_key` is an exact length,
-- not a range: a code path that accidentally wrote a raw address would fail
-- loudly at the database instead of silently storing it.
--
-- Deliberately NO foreign key to `users`: an FK would make a row impossible
-- for a non-existent account, and the difference between "throttled" and "not
-- throttled" would enumerate accounts. The hash keeps that property — a
-- fictitious address still gets its own row.
--
-- `locked_until` is the one nullable column, and NULL means "not locked".
CREATE TABLE public.login_throttle (
  account_key       TEXT    NOT NULL,
  failure_count     INTEGER NOT NULL,
  window_started_at TIMESTAMP WITH TIME ZONE NOT NULL,
  locked_until      TIMESTAMP WITH TIME ZONE,
  updated_at        TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_login_throttle PRIMARY KEY (account_key),
  CONSTRAINT ck_login_throttle_key   CHECK (char_length(account_key) = 64),
  CONSTRAINT ck_login_throttle_count CHECK (failure_count >= 0)
)
