-- The account table: one row per person who can sign in. `role` is written
-- once, by the INSERT that creates the account, and no UPDATE anywhere in the
-- application names it.
--
-- Every column is NOT NULL and no column carries a DEFAULT: the application
-- supplies every value on every INSERT, including
-- `version = 1` and the three instants, which come from the injected clock and
-- never from the database server.
--
-- Schema-qualified as `public.users`, the shipped form of 0001_journal, so the
-- table cannot land in a role-named schema if a search_path ever differs; the
-- postconditions ask information_schema for `table_schema = 'public'`.
CREATE TABLE public.users (
  id                   TEXT    NOT NULL,
  email                TEXT    NOT NULL,
  email_norm           TEXT    NOT NULL,
  display_name         TEXT    NOT NULL,
  role                 TEXT    NOT NULL,
  password_hash        TEXT    NOT NULL,
  password_changed_at  TIMESTAMP WITH TIME ZONE NOT NULL,
  must_change_password BOOLEAN NOT NULL,
  is_active            BOOLEAN NOT NULL,
  version              INTEGER NOT NULL,
  created_at           TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at           TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_users PRIMARY KEY (id),
  CONSTRAINT ck_users_id      CHECK (char_length(id) = 36
                                 AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_users_email   CHECK (char_length(email) BETWEEN 3 AND 254
                                 AND email LIKE '%_@_%'),
  CONSTRAINT ck_users_email_norm CHECK (char_length(email_norm) BETWEEN 3 AND 254),
  CONSTRAINT ck_users_display CHECK (char_length(display_name) BETWEEN 1 AND 160),
  CONSTRAINT ck_users_role    CHECK (role IN ('admin', 'agent')),
  CONSTRAINT ck_users_hash    CHECK (char_length(password_hash) BETWEEN 20 AND 512),
  CONSTRAINT ck_users_version CHECK (version >= 1)
)
