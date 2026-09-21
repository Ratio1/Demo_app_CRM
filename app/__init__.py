"""Demo_App_CRM — a small, security-hardened CRM tutorial application.

Importing this package, or any module in it, must never read the environment,
open a socket or touch the filesystem: ``app.config.load_config`` resolves the
environment when it is called, and the connection pool is created with
``open=False`` and opened in the ASGI lifespan. That is what lets the image be
built and ``app.main`` be imported with all five configuration variables
absent.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
