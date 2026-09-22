"""SQL statements, and nothing else.

Every function in this package takes the connection as its first positional
argument and everything else keyword-only. The rules that hold for all of
them (``slice-a.md`` §10(b)):

*No function opens, commits or rolls back a transaction.* The caller's
wrapper — :func:`app.db.retry.run_read_committed` or
:func:`app.db.retry.run_serializable` — chooses the isolation level and owns
the boundary. That is what lets ``insert_event`` ride the transaction of the
mutation it describes (``S7``) and what lets the counter transactions commit
independently of the auth path they were called from (``SQL-027``).

*No function reads a clock.* Every instant arrives as a parameter, bound by
the caller from the injected :class:`app.security.clock.Clock`
(``DATA_CONTRACT.md`` §2.3 rule 2, ``ARC-019``). No ``now()``, no
``CURRENT_TIMESTAMP``, no interval arithmetic and no ``date_trunc`` appears in
any statement here: window boundaries and staleness cutoffs are computed in
Python and bound.

*No function decides anything.* Identifiers are application-generated and
passed in (``A3``), so an insert returns ``None`` and a guarded update returns
only whether it matched. Authorization is the service layer's; these
statements carry the predicates they are given.

*Identifiers cross this boundary as ``str``.* The schema stores ids as
``TEXT`` (``DATA_CONTRACT.md`` §2.2), and psycopg adapts a :class:`uuid.UUID`
parameter to the server's native ``uuid`` type, so binding one against a
``TEXT`` column raises ``UndefinedFunction`` ``42883``. Signatures therefore
speak :class:`uuid.UUID` — which is what the services and routes use — and
each module converts with ``str(...)`` on the way in and ``UUID(...)`` on the
way out, in one place per module.

*Every SELECT names its columns* (``ARC-011``); no ``SELECT *`` appears
anywhere, so a column added by a later migration cannot silently change a row
tuple's shape.
"""

from __future__ import annotations

__all__: list[str] = []
