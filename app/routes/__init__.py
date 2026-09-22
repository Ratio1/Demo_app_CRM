"""HTTP routes: the auth screens, the health probes and the error pages.

``ARC-008``: nothing under this package imports ``app.db.repositories``.
A route reaches the database through :mod:`app.security` (session, throttle,
origin) or through :mod:`app.services` (the use cases), never directly.

``ARC-003``: no ``GET``/``HEAD`` handler calls into ``app.services`` at all.
The safe-method writes this application does perform — the budget counter,
the >60 s session touch, the best-effort deny audit and the pre-auth row
``GET /login`` must create before it can render a CSRF-protected form — are
the four ``DATA_CONTRACT.md`` §6.8 enumerates, and each is reached through
the session or throttle layer rather than through a service.
"""

from __future__ import annotations
