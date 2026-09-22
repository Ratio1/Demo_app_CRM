"""Use cases: the work a mutation does, between the guards and the schema.

A service owns one thing a route does not: the **transaction**. It opens
the ``SERIALIZABLE`` block, re-reads inside it what the decision depends
on, writes the business rows and the audit row together, and returns a
plain result object. A route decides statuses, templates and cookies; a
repository decides nothing at all.

``ARC-003``: nothing here is reachable from a ``GET``/``HEAD`` handler.
Every function in this package is a mutation or the read half of one, and
the route table only calls them from ``POST`` handlers.
"""

from __future__ import annotations
