-- Two keys and no more: the key CHECK is an allowlist,
-- so a new setting is a migration step rather than a row an operator invents.
--
-- `public_origin` is the exact HTTPS origin the application compares Origin
-- and Host against. It lives here rather than in an environment variable, and
-- it is never derived from a request header.
-- `provisioning_state` is written 'complete' by `bootstrap`; ABSENCE of the
-- row is the pending state, and nothing ever writes 'pending' — the CHECK
-- keeps the value only as a reserved one for a future partial-provisioning
-- step.
--
-- `updated_by_user_id` is nullable because `set-origin` runs from the CLI with
-- no session behind it.
CREATE TABLE public.app_settings (
  key                TEXT NOT NULL,
  value              TEXT NOT NULL,
  updated_at         TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_by_user_id TEXT,
  CONSTRAINT pk_app_settings PRIMARY KEY (key),
  CONSTRAINT ck_app_settings_key   CHECK (key IN ('public_origin', 'provisioning_state')),
  CONSTRAINT ck_app_settings_value CHECK (char_length(value) BETWEEN 1 AND 1000),
  CONSTRAINT ck_app_settings_actor
    CHECK (updated_by_user_id IS NULL OR char_length(updated_by_user_id) = 36)
)
