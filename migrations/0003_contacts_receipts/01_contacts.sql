-- DATA_CONTRACT.md §3.9. One row per contact. `owner_id` is the ONLY ownership
-- column in the business schema: deals and activities reach their owner by the
-- join to this table, which is what makes owner injection on a child
-- structurally impossible rather than merely allowlisted (ACCESS_MATRIX.md
-- §1.4).
--
-- `email` carries NO unique constraint of any kind (T-36, SQL-022): a global
-- unique email would turn a create-contact 409 into an oracle for a foreign
-- contact's address. Spec §5's "normalized unique account emails" governs
-- `users` only.
--
-- The lead/customer column is `kind`, not `status`: the request token `status`
-- is the archive filter and reaches `archived_at` (§3.9's token map). There is
-- no column named `status` on this table and this step's postcondition asserts
-- it.
--
-- `archived_at` is the only nullable column and the only archive flag in the
-- schema (§4.2). Archive is not erasure (S7): nothing is deleted, which is why
-- the runtime role never receives DELETE here (step 05).
--
-- No DEFAULT clause and no server clock (§2.3 rules 1 and 2): the application
-- supplies every value on every INSERT, including `version = 1` and both
-- instants, which come from the injected clock.
CREATE TABLE public.contacts (
  id              TEXT NOT NULL,
  owner_id        TEXT NOT NULL,
  full_name       TEXT NOT NULL,
  full_name_lower TEXT NOT NULL,
  company         TEXT NOT NULL,
  company_lower   TEXT NOT NULL,
  email           TEXT NOT NULL,
  email_lower     TEXT NOT NULL,
  phone           TEXT NOT NULL,
  kind            TEXT NOT NULL,
  archived_at     TIMESTAMP WITH TIME ZONE,
  version         INTEGER NOT NULL,
  created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at      TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_contacts PRIMARY KEY (id),
  CONSTRAINT fk_contacts_owner_id
    FOREIGN KEY (owner_id) REFERENCES public.users (id) ON DELETE RESTRICT,
  CONSTRAINT ck_contacts_id CHECK (char_length(id) = 36
                               AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_contacts_name          CHECK (char_length(full_name) BETWEEN 1 AND 160),
  CONSTRAINT ck_contacts_name_lower    CHECK (char_length(full_name_lower) BETWEEN 1 AND 160),
  CONSTRAINT ck_contacts_company       CHECK (char_length(company) <= 160),
  CONSTRAINT ck_contacts_company_lower CHECK (char_length(company_lower) <= 160),
  CONSTRAINT ck_contacts_email   CHECK (char_length(email) BETWEEN 3 AND 254
                                    AND email LIKE '%_@_%'),
  CONSTRAINT ck_contacts_email_lower CHECK (char_length(email_lower) BETWEEN 3 AND 254),
  CONSTRAINT ck_contacts_phone   CHECK (char_length(phone) <= 32),
  CONSTRAINT ck_contacts_kind    CHECK (kind IN ('lead', 'customer')),
  CONSTRAINT ck_contacts_version CHECK (version >= 1)
)
