-- Pre-auth and full sessions in one table, hashes
-- only: the cookie carries a 256-bit CSPRNG token and only its SHA-256 is
-- stored, and the CSRF token is stored the same way.
--
-- `ck_sessions_kind_user` is what makes a pre-auth row structurally unable to
-- carry an identity — a ten-minute row that exists to hold the login form's
-- CSRF state and nothing else. `user_id` is therefore the one nullable column
-- on the table, and its meaning is exactly "pre_auth".
--
-- Sessions are hard-deleted, never flagged: there is no `revoked_at`, so
-- "revoked" and "unknown token" are one code path and a deleted row leaves no
-- token hash behind.
CREATE TABLE public.sessions (
  id                  TEXT NOT NULL,
  token_sha256        TEXT NOT NULL,
  csrf_sha256         TEXT NOT NULL,
  kind                TEXT NOT NULL,
  user_id             TEXT,
  created_at          TIMESTAMP WITH TIME ZONE NOT NULL,
  last_seen_at        TIMESTAMP WITH TIME ZONE NOT NULL,
  idle_expires_at     TIMESTAMP WITH TIME ZONE NOT NULL,
  absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_sessions PRIMARY KEY (id),
  CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES public.users (id)
    ON DELETE CASCADE,
  CONSTRAINT ck_sessions_id    CHECK (char_length(id) = 36
                                  AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_sessions_token CHECK (char_length(token_sha256) = 64),
  CONSTRAINT ck_sessions_csrf  CHECK (char_length(csrf_sha256) = 64),
  CONSTRAINT ck_sessions_kind  CHECK (kind IN ('pre_auth', 'full')),
  CONSTRAINT ck_sessions_kind_user
    CHECK ((kind = 'full'     AND user_id IS NOT NULL)
        OR (kind = 'pre_auth' AND user_id IS NULL))
)
