-- DATA_CONTRACT.md §3.11. One row per logged activity, and the only
-- append-only business table in the schema.
--
-- NO `owner_id`, NO `archived_at`, NO `version` and NO `updated_at` (PIN C8,
-- and the same reasoning `deals` states one migration earlier). An activity is
-- authorized by the join to its contact and inherits its parent's archived
-- state, so owner injection on a child is structurally impossible rather than
-- allowlisted. A `version` column would be a concurrency token for an edit
-- that cannot happen: the runtime role receives SELECT and INSERT only
-- (step 03), which is what makes "once logged, an activity cannot be edited or
-- deleted" a privilege of the database rather than a missing route.
--
-- `contact_id` is immutable for the same reason it is on `deals` (ACC-217):
-- re-parenting is an ownership move by another name, and there is no UPDATE
-- statement anywhere in this application that could perform one.
--
-- `kind` is TEXT + CHECK, never CREATE TYPE ... AS ENUM (§9.1); the four
-- values are UX_FLOWS.md §4.6's radio quad, in the order the form renders
-- them.
--
-- `occurred_on` is a DATE, not a timestamp: the form submits `yyyy-mm-dd` from
-- an `<input type="date">` and the timeline renders a day. `created_at` is the
-- separate record instant, and the two are never conflated — a back-dated
-- activity logged today keeps today's `created_at`, which is what the
-- timeline's second ordering key relies on.
--
-- `created_by_user_id` is the only nullable column and the only ON DELETE SET
-- NULL in the chain: D-H requires an activity to OUTLIVE the account that
-- logged it, and the timeline renders "by removed user" from exactly this NULL
-- (contacts/detail.html line 125). ON DELETE RESTRICT here would make erasing
-- a subject impossible; ON DELETE CASCADE would delete a contact's history
-- when an agent leaves.
--
-- No DEFAULT clause and no server clock (§2.3 rules 1 and 2): the application
-- supplies every value on every INSERT, from the injected clock.
CREATE TABLE public.activities (
  id                 TEXT NOT NULL,
  contact_id         TEXT NOT NULL,
  kind               TEXT NOT NULL,
  occurred_on        DATE NOT NULL,
  summary            TEXT NOT NULL,
  created_by_user_id TEXT,
  created_at         TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT pk_activities PRIMARY KEY (id),
  CONSTRAINT fk_activities_contact_id
    FOREIGN KEY (contact_id) REFERENCES public.contacts (id) ON DELETE RESTRICT,
  CONSTRAINT fk_activities_created_by_user_id
    FOREIGN KEY (created_by_user_id) REFERENCES public.users (id) ON DELETE SET NULL,
  CONSTRAINT ck_activities_id CHECK (char_length(id) = 36
                                 AND id LIKE '________-____-____-____-____________'),
  CONSTRAINT ck_activities_created_by
    CHECK (created_by_user_id IS NULL OR char_length(created_by_user_id) = 36),
  CONSTRAINT ck_activities_kind CHECK (kind IN ('note', 'call', 'email', 'meeting')),
  CONSTRAINT ck_activities_summary CHECK (char_length(summary) BETWEEN 1 AND 1000)
)
