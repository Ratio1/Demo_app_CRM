"""Database access for Demo_App_CRM: pool, retry, migration journal, manifest.

Importing any module in this package must not open a connection, read the
process environment or touch the filesystem. ``app.config`` is the only module
that reads the environment (``CONTRACTS.md`` §2) and every module here takes its
parameters from a :class:`app.config.Config` handed in by the caller.

Layering, from the bottom up:

``pool``
  One lazy :class:`psycopg_pool.AsyncConnectionPool` per process, built from
  ``Config.connect_kwargs()`` with sizing and timeouts as code constants.
``retry``
  The ``SERIALIZABLE`` transaction runner: whole-transaction retry on the two
  retryable SQLSTATEs, and a distinct error for a commit whose outcome is
  unknown.
``journal``
  The restartable, checksummed migration runner over ``migrations/``, plus the
  ``python -B -m app.db.journal migrate`` entry point.
``manifest``
  The expected ``(migration_id, step_id, checksum)`` manifest the image was
  built with, and the readiness comparison behind ``/health/ready``.

``repositories/`` is added slice by slice from P3 onward; every public
repository function takes a mandatory ``Scope`` and inlines the ownership
predicate in SQL.
"""
