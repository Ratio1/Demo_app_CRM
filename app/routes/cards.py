"""The shared deal sub-contexts, built in one place.

Three surfaces render the same card — the deal list, a pipeline column and
the contact workspace's ``#deals`` region — and two render the same stage
form. The shapes are fixed, so building them here rather than in each route
is what keeps ``app/routes/deals.py`` and ``app/routes/contacts.py`` from
drifting apart one key at a time; neither may invent, rename or drop one.

This module holds the URLs a card needs and no authorization decision at
all. ``url`` and ``contact_url`` are composed from route **names**, never
stored and never taken from a request, so renaming a path moves both.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.services.deals import TERMINAL, lateral_targets

if TYPE_CHECKING:
  from uuid import UUID

  from starlette.requests import Request

  from app.services.deals import DealCardView

__all__ = [
  "contact_url",
  "deal_card_context",
  "deal_url",
  "stage_form_context",
]


def deal_url(request: Request, deal_id: UUID) -> str:
  """Return the relative ``/deals/{id}`` path for one deal."""
  return str(request.app.url_path_for("deal_detail", deal_id=str(deal_id)))


def contact_url(request: Request, contact_id: UUID) -> str:
  """Return the relative ``/contacts/{id}`` path for one contact."""
  return str(request.app.url_path_for("contact_detail", contact_id=str(contact_id)))


def deal_card_context(request: Request, card: DealCardView) -> dict[str, Any]:
  """Build the ``deal_card`` context — and nothing beyond it.

  Parameters
  ----------
  request : Request
    The inbound request, for the two route-name lookups.
  card : DealCardView
    The service's view model.

  Returns
  -------
  dict[str, Any]
    Exactly the thirteen frozen keys. ``amount`` stays a
    :class:`decimal.Decimal` and is rendered by the ``eur`` filter, so no
    money string is built here; ``close_date`` stays a
    :class:`datetime.date` for the ``day`` filter.

  Notes
  -----
  ``version`` is deliberately **not** in the card: the concurrency token
  belongs to a *form*, and the workspace's stage forms carry it under
  ``deal_forms``. A card is a read.
  """
  return {
    "id": str(card.id),
    "url": deal_url(request, card.id),
    "title": card.title,
    "amount": card.amount,
    "close_date": card.close_date,
    "stage": card.stage,
    "stage_label": card.stage_label,
    "contact_id": str(card.contact_id),
    "contact_name": card.contact_name,
    "contact_url": contact_url(request, card.contact_id),
    "owner_name": card.owner_name,
    "is_own": card.is_own,
    "parent_archived": card.parent_archived,
  }


def stage_form_context(*, idempotency_key: UUID, version: int, stage: str) -> dict[str, Any]:
  """Build the ``stage_form`` context the stage control renders from.

  Parameters
  ----------
  idempotency_key : UUID
    **One key per control render**, shared by the three forms the partial
    draws: only one of them can be submitted, because each answers with a
    ``303`` and a full reload, so a second action posted with the same key
    meets the 409 ``duplicate`` answer by design.
  version : int
    The deal's current version, rendered as a hidden field in all three
    forms and re-checked inside the transaction.
  stage : str
    The stage the deal is in.

  Returns
  -------
  dict[str, Any]
    ``lateral_targets`` holds the legal targets **minus the current
    stage**, so a move to the stage the deal is already in is unreachable
    through the UI and still refused server-side; ``terminal`` is ``True``
    for ``won``/``lost``, which is the template's instruction to render
    **no control at all**, just the closing line.
  """
  return {
    "idempotency_key": str(idempotency_key),
    "version": version,
    "lateral_targets": [
      {"value": value, "label": label} for value, label in lateral_targets(stage)
    ],
    "terminal": stage in TERMINAL,
    "current_stage": stage,
  }
