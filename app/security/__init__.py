"""Authentication, sessions, CSRF, authorization, throttling and audit.

The package is deliberately split into two layers:

*Pure modules* — :mod:`app.security.clock`, :mod:`app.security.passwords`,
:mod:`app.security.sessions` and :mod:`app.security.csrf` — import nothing
from :mod:`app.db.repositories` and touch no connection. They hold the
parameters and the primitives (Argon2, token minting, cookie attributes,
constant-time comparison) and are importable on a machine with no database
at all.

*Database-facing modules* — :mod:`app.security.session_store`,
:mod:`app.security.origin`, :mod:`app.security.throttle`,
:mod:`app.security.audit`, :mod:`app.security.principal` and
:mod:`app.security.authz` — compose those primitives with the repository
layer. ``app/routes/**`` reaches the database only through this layer or
through ``app/services/**``.

Nothing here reads the process environment and nothing calls a
wall-clock function outside :mod:`app.security.clock`.
"""

from __future__ import annotations
