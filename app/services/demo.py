"""``seed-demo`` and ``reset-demo``: the operator's re-run path on one database.

A reset deletes the demo's business rows — never the database, never the
accounts, never ``audit_events``.

Three properties make this safe to point at ``crm``:

*It is maintenance-only.* Every statement it reaches lives in
:mod:`app.db.repositories.maintenance` and runs as the owner role from
``scripts/manage``. The runtime role holds no ``DELETE`` on any business
table, so nothing reachable over HTTP can do any of this.

*It is deterministic and idempotent.* Ids come from
:func:`uuid.uuid5` over a fixed namespace, and every varying value — stage,
kind, amount, day offset — comes from a :class:`random.Random` seeded with a
constant. Running it twice writes the same rows the same way, and the second
run inserts nothing because each row's id is already there. That is what
makes "re-runnable from the same image" true rather than hopeful.

*The data is fictional.* Two ``example.test`` agents, ``example.test``
contacts, invented companies. The ``[PRIVACY]`` fence in ``REVIEW.md``
applies to this build as a whole; this module never invents a real-looking
person, and it never writes anything outside ``example.test``.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Final

from app.db.repositories import maintenance as maintenance_repo
from app.db.retry import run_serializable
from app.security.audit import (
  ACTION_DEMO_RESET,
  ACTION_DEMO_SEEDED,
  OBJECT_SYSTEM,
  OUTCOME_SUCCESS,
  record,
)

if TYPE_CHECKING:
  from datetime import date
  from uuid import UUID

  from app.db.pool import Pool, PoolConnection
  from app.security.clock import Clock

__all__ = [
  "DEMO_AGENTS",
  "DEMO_DELETE_ORDER",
  "SCALE_SMALL",
  "ResetReport",
  "SeedReport",
  "reset_demo",
  "seed_demo",
]

#: Re-exported so ``scripts/manage`` can print the per-table counts in delete
#: order without importing ``app.db.repositories`` itself.
DEMO_DELETE_ORDER: Final[tuple[str, ...]] = maintenance_repo.DEMO_DELETE_ORDER

#: The only scale this command accepts (the plan defers ``profile``, which
#: existed for the deferred resource gate and for nothing else).
SCALE_SMALL: Final = "small"

#: 20 contacts, 20 deals, 100 activities.
_CONTACTS: Final = 20
_DEALS: Final = 20
_ACTIVITIES: Final = 100

#: The two fictional agents the demo data belongs to. Fixed addresses, so a
#: second run finds them instead of creating a third and a fourth.
DEMO_AGENTS: Final[tuple[tuple[str, str], ...]] = (
  ("agent.one@example.test", "Alex One"),
  ("agent.two@example.test", "Robin Two"),
)

#: A fixed namespace, so every id this module writes is a pure function of
#: its index. ``uuid5`` rather than a PRNG for the ids themselves: it is
#: reproducible across Python versions, where ``random``'s stream is only
#: promised to be stable for ``random.Random`` seeded explicitly — which is
#: what the varying values below use.
_NAMESPACE: Final = uuid.UUID("6f1d5a7e-2c34-5a8b-9c10-9b7f3e0d4a21")
_SEED: Final = 20260922

_COMPANIES: Final[tuple[str, ...]] = (
  "Northwind Test",
  "Contoso Example",
  "Acme Fixtures",
  "Fabrikam Demo",
  "Globex Sample",
)
_FIRST_NAMES: Final[tuple[str, ...]] = (
  "Ada",
  "Bo",
  "Cleo",
  "Dev",
  "Eli",
  "Fay",
  "Gil",
  "Hana",
  "Ivo",
  "Jo",
)
_LAST_NAMES: Final[tuple[str, ...]] = (
  "Ash",
  "Brook",
  "Crane",
  "Dune",
  "Elm",
  "Frost",
  "Gale",
  "Holt",
  "Iris",
  "Jet",
)
_STAGES: Final[tuple[str, ...]] = ("new", "qualified", "proposal", "won", "lost")
_KINDS: Final[tuple[str, ...]] = ("note", "call", "email", "meeting")
_SUMMARIES: Final[tuple[str, ...]] = (
  "Intro call: mapped the pilot scope.",
  "Sent the draft proposal for review.",
  "Follow-up email about the licence tiers.",
  "Meeting notes: security questionnaire returned.",
  "Left a voicemail, will retry next week.",
)


@dataclass(frozen=True, slots=True)
class SeedReport:
  """What a seed run did, for the command's one summary line."""

  contacts_written: int
  deals_written: int
  activities_written: int
  contacts_total: int
  deals_total: int
  activities_total: int


@dataclass(frozen=True, slots=True)
class ResetReport:
  """What a reset run removed, per table, in delete order."""

  removed: dict[str, int]


def _identifier(kind: str, index: int) -> UUID:
  """Return the deterministic id of the ``index``-th row of one kind."""
  return uuid.uuid5(_NAMESPACE, f"{kind}:{index}")


def _contact_values(index: int, rng: random.Random) -> dict[str, str]:
  """Return one fictional contact's fields, all inside ``example.test``."""
  first = _FIRST_NAMES[index % len(_FIRST_NAMES)]
  last = _LAST_NAMES[(index * 7) % len(_LAST_NAMES)]
  company = _COMPANIES[index % len(_COMPANIES)]
  return {
    "full_name": f"{first} {last}",
    "company": company,
    "email": f"{first.lower()}.{last.lower()}{index}@example.test",
    "phone": f"+40 700 {100 + index:03d} {200 + index:03d}",
    "kind": "customer" if rng.random() < 0.4 else "lead",
  }


async def seed_demo(
  *,
  pool: Pool,
  clock: Clock,
  agent_ids: tuple[UUID, ...],
  correlation_id: str,
) -> SeedReport:
  """Write the small demo data set, or confirm it is already there.

  Parameters
  ----------
  pool : Pool
    The process pool, under the maintenance role.
  clock : Clock
    Injected time source. Every instant and every date below is derived from
    one reading of it, so a row's ``created_at`` and the day it references
    move together and a run is one point in time.
  agent_ids : tuple[UUID, ...]
    The two demo agents, already created (``accounts.ensure_demo_agent``).
    Contacts are split between them by index, so each agent signs in to a
    populated, *different* workspace — which is what makes the ownership
    filter visible during the walk rather than a claim about it.
  correlation_id : str
    This command's id, written into the ``demo_seeded`` audit row.

  Returns
  -------
  SeedReport
    What was written this run (zero on a second run) and what is there now.

  Notes
  -----
  One ``SERIALIZABLE`` transaction for the whole seed: a half-written demo is
  worse than none, and the row counts in the report are read inside it.
  """
  now = clock.now()
  today = now.date()
  rng = random.Random(_SEED)  # noqa: S311 — fixture data, never a security decision

  async def _work(conn: PoolConnection) -> SeedReport:
    contacts_written = 0
    deals_written = 0
    activities_written = 0
    contact_ids: list[UUID] = []

    for index in range(_CONTACTS):
      contact_id = _identifier("contact", index)
      contact_ids.append(contact_id)
      if await maintenance_repo.row_exists(conn, table="contacts", row_id=contact_id):
        continue
      values = _contact_values(index, rng)
      await maintenance_repo.insert_demo_contact(
        conn,
        contact_id=contact_id,
        owner_id=agent_ids[index % len(agent_ids)],
        full_name=values["full_name"],
        company=values["company"],
        email=values["email"],
        phone=values["phone"],
        kind=values["kind"],
        now=now,
      )
      contacts_written += 1

    for index in range(_DEALS):
      deal_id = _identifier("deal", index)
      if await maintenance_repo.row_exists(conn, table="deals", row_id=deal_id):
        continue
      contact_id = contact_ids[index % len(contact_ids)]
      stage = _STAGES[index % len(_STAGES)]
      amount = Decimal(f"{1200 + index * 275}.00")
      close_date: date = today.replace(day=1) if index % 3 == 0 else today
      await maintenance_repo.insert_demo_deal(
        conn,
        deal_id=deal_id,
        contact_id=contact_id,
        title=f"{_COMPANIES[index % len(_COMPANIES)]} licence {index + 1}",
        amount=amount,
        close_date=close_date,
        stage=stage,
        now=now,
      )
      deals_written += 1

    for index in range(_ACTIVITIES):
      activity_id = _identifier("activity", index)
      if await maintenance_repo.row_exists(conn, table="activities", row_id=activity_id):
        continue
      contact_index = index % len(contact_ids)
      await maintenance_repo.insert_demo_activity(
        conn,
        activity_id=activity_id,
        contact_id=contact_ids[contact_index],
        kind=_KINDS[index % len(_KINDS)],
        # The day walks backwards from today in fixed steps, so the timeline
        # has a real order to page through and the dashboard's "recent" list
        # is not twenty rows sharing one date.
        occurred_on=today.fromordinal(today.toordinal() - (index % 30)),
        summary=_SUMMARIES[index % len(_SUMMARIES)],
        author_id=agent_ids[contact_index % len(agent_ids)],
        now=now,
      )
      activities_written += 1

    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_SYSTEM,
      object_id=None,
      action=ACTION_DEMO_SEEDED,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return SeedReport(
      contacts_written=contacts_written,
      deals_written=deals_written,
      activities_written=activities_written,
      contacts_total=await maintenance_repo.count_rows(conn, table="contacts"),
      deals_total=await maintenance_repo.count_rows(conn, table="deals"),
      activities_total=await maintenance_repo.count_rows(conn, table="activities"),
    )

  return await run_serializable(pool, _work, op="seed-demo")


async def reset_demo(*, pool: Pool, clock: Clock, correlation_id: str) -> ResetReport:
  """Delete the demo's business rows, keeping the accounts and the history.

  Notes
  -----
  Deletes in foreign-key order and writes ``demo_reset`` in the **same**
  transaction, so the record of the reset commits with it — the same rule
  every business mutation follows. ``audit_events`` is never
  in the delete order, so the history of the run that was just erased is
  itself preserved.
  """
  now = clock.now()

  async def _work(conn: PoolConnection) -> ResetReport:
    removed = await maintenance_repo.truncate_demo_rows(conn)
    await record(
      conn,
      actor_id=None,
      object_type=OBJECT_SYSTEM,
      object_id=None,
      action=ACTION_DEMO_RESET,
      outcome=OUTCOME_SUCCESS,
      correlation_id=correlation_id,
      at=now,
    )
    return ResetReport(removed=removed)

  return await run_serializable(pool, _work, op="reset-demo")
