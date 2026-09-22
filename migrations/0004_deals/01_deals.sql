-- One row per deal.
--
-- NO `owner_id` and NO `archived_at`. A deal is authorized by the join
-- to its contact and inherits its parent's archived state, which is what makes
-- owner injection on a child structurally impossible rather than allowlisted
-- and what keeps admin reassignment one UPDATE
-- of one row.
--
-- `contact_id` is IMMUTABLE after creation: re-parenting a deal would move it
-- to another owner without any reassignment check. It appears in no
-- UPDATE ... SET list in this chain, and `DealFields`
-- (app/db/repositories/deals.py) does not carry it — the dataclass IS the
-- allowlist.
--
-- `amount` is DECIMAL(12,2) with a non-negative CHECK. The CHECK is the
-- SECOND line for the sign; server-side parsing is the first. For the
-- SCALE there is no second line at all: numeric(12,2) ROUNDS a third decimal
-- rather than refusing it, so the strict
-- pattern is the only control. Currency is not a column: the demo is
-- single-currency EUR, fixed in code and in rendering.
--
-- `stage` is TEXT + CHECK, never CREATE TYPE ... AS ENUM. The CHECK
-- guarantees a legal VALUE and nothing more: the transition GRAPH is not in the
-- schema, because encoding it would need a trigger, and this schema has none.
-- The service enforces which stage may follow which, and `stage_changed_at`
-- is rewritten on every accepted change.
--
-- `close_date` is the only nullable column. No DEFAULT clause and no
-- server clock: the application supplies every value on
-- every INSERT, including `version = 1`, the literal stage 'new' and all three
-- instants, which come from the injected clock.
CREATE TABLE public.deals (
  id               TEXT NOT NULL,
  contact_id       TEXT NOT NULL,
  title            TEXT NOT NULL,
  title_lower      TEXT NOT NULL,
  amount           DECIMAL(12,2) NOT NULL,
  close_date       DATE,
  stage            TEXT NOT NULL,
  stage_changed_at TIMESTAMP WITH TIME ZONE NOT NULL,
  version          INTEGER NOT NULL,
  created_at       TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at       TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_deals PRIMARY KEY (id),
  CONSTRAINT fk_deals_contact_id
    FOREIGN KEY (contact_id) REFERENCES public.contacts (id) ON DELETE RESTRICT,
  CONSTRAINT ck_deals_id CHECK (char_length(id) = 36
                            AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_deals_title       CHECK (char_length(title) BETWEEN 1 AND 160),
  CONSTRAINT ck_deals_title_lower CHECK (char_length(title_lower) BETWEEN 1 AND 160),
  CONSTRAINT ck_deals_amount_nonneg CHECK (amount >= 0),
  CONSTRAINT ck_deals_stage CHECK (stage IN ('new', 'qualified', 'proposal', 'won', 'lost')),
  CONSTRAINT ck_deals_version CHECK (version >= 1)
)
