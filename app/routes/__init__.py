"""HTTP routes: the auth screens, the health probes and the error pages.

Nothing under this package imports ``app.db.repositories``.
A route reaches the database through :mod:`app.security` (session, throttle,
origin) or through :mod:`app.services` (the use cases), never directly.

No ``GET``/``HEAD`` handler calls into ``app.services`` at all. The
safe-method writes this application does perform are exactly four — the
budget counter, the >60 s session touch, the best-effort deny audit and the
pre-auth row ``GET /login`` must create before it can render a
CSRF-protected form — and each is reached through the session or throttle
layer rather than through a service.
"""

from __future__ import annotations
