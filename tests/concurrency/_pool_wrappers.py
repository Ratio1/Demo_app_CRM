"""Connection/pool wrapper seams for Slice C's two concurrency proofs.

Authority: ``contracts/slice-c.md`` §1(c)/§2(b) (**PIN C5**, the ambiguous
commit seam is the *pool*), §2(g) hook 2 (the barrier's exact ordering and
its "attempt-aware" requirement).

Not a test module itself (no ``test_*`` name, so pytest never collects it);
imported by ``test_deals_concurrency.py``. Every import here is deferred by
its *caller*, never at this module's top level, so this file never fails to
import before ``app.db.pool``/``app.db.retry`` exist — it only references
their *types* under ``TYPE_CHECKING``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
  from collections.abc import Callable

  from app.db.pool import Pool, PoolConnection


def _statement_text(query: object, conn: Any) -> str:
  """Render a psycopg query object (composed SQL or a plain string) to text.

  Parameters
  ----------
  query : object
    Whatever ``conn.execute`` received as its first argument.
  conn : Any
    The real connection — ``sql.Composed.as_string`` needs one to quote
    identifiers correctly.

  Returns
  -------
  str
  """
  as_string = getattr(query, "as_string", None)
  if callable(as_string):
    result = as_string(conn)
    return str(result)
  return str(query)


class _GatedTransaction:
  """Wraps one ``conn.transaction()`` context manager, signalling on a clean commit.

  Parameters
  ----------
  real : Any
    The real ``psycopg.AsyncTransaction`` (or nested-transaction) context
    manager ``conn.transaction()`` returned.
  on_committed : Callable[[], None] | None
    Called, synchronously, immediately after ``__aexit__`` returns with no
    exception in flight — i.e. exactly when this block's ``COMMIT`` (or the
    outer transaction's, for a nested block) has been sent and accepted.
    ``None`` when this wrapper's only job is statement gating.
  """

  __slots__ = ("_exc_seen", "_on_committed", "_real")

  def __init__(self, real: Any, *, on_committed: Callable[[], None] | None) -> None:
    self._real = real
    self._on_committed = on_committed
    self._exc_seen = False

  async def __aenter__(self) -> Any:
    return await self._real.__aenter__()

  async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool | None:
    result = await self._real.__aexit__(exc_type, exc, tb)
    if exc_type is None and self._on_committed is not None:
      self._on_committed()
    return result


class _GatedConnection:
  """Proxies one real ``PoolConnection``, gating ``execute`` calls by statement text.

  Every attribute access other than ``execute``/``transaction`` falls
  straight through to the real connection (``__getattr__``), so repository
  functions that call ``conn.execute(...)`` or hold onto ``conn`` for a
  cursor see an object that behaves identically except at the two seams
  this test harness actually needs.

  Parameters
  ----------
  real : PoolConnection
    The connection this attempt's ``pool.connection()`` produced.
  before_execute : Callable[[str], Awaitable[None]] | None
    Awaited with the rendered statement text **before** every
    ``execute()`` call reaches the real connection. Raising from it (or
    from what it awaits) propagates to the caller exactly as a real
    ``psycopg.Error`` would from the statement itself.
  on_committed : Callable[[], None] | None
    See :class:`_GatedTransaction`.
  """

  def __init__(
    self,
    real: PoolConnection,
    *,
    before_execute: Callable[[str], Any] | None,
    on_committed: Callable[[], None] | None,
  ) -> None:
    self._real = real
    self._before_execute = before_execute
    self._on_committed = on_committed

  def __getattr__(self, name: str) -> Any:
    return getattr(self._real, name)

  async def execute(self, query: object, *args: object, **kwargs: object) -> object:
    """Gate, then delegate to the real connection's ``execute``."""
    if self._before_execute is not None:
      text = _statement_text(query, self._real)
      await self._before_execute(text)
    return await self._real.execute(query, *args, **kwargs)

  def transaction(self, *args: object, **kwargs: object) -> _GatedTransaction:
    """Wrap the real transaction context manager to observe a clean commit."""
    real_cm = self._real.transaction(*args, **kwargs)
    return _GatedTransaction(real_cm, on_committed=self._on_committed)


class _GatedConnectionContext:
  """Wraps ``pool.connection()``'s own async context manager, gating the connection it yields."""

  def __init__(
    self,
    real_cm: Any,
    *,
    before_execute: Callable[[str], Any] | None,
    on_committed: Callable[[], None] | None,
  ) -> None:
    self._real_cm = real_cm
    self._before_execute = before_execute
    self._on_committed = on_committed

  async def __aenter__(self) -> _GatedConnection:
    real_conn = await self._real_cm.__aenter__()
    return _GatedConnection(
      real_conn, before_execute=self._before_execute, on_committed=self._on_committed
    )

  async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool | None:
    return await self._real_cm.__aexit__(exc_type, exc, tb)


class GatedPool:
  """A ``Pool`` proxy that gates every statement executed on any connection it hands out.

  Used for both of Slice C's harness seams (``contracts/slice-c.md``
  §2(g) hooks 2 and 4): a barrier race (``SQL-012`` part 1) gates a
  specific ``UPDATE`` until a signal fires, and an ambiguous-commit
  wrapper (``SQL-013``) gates nothing on ``execute`` and instead forces
  the commit itself to fail — the caller picks which by what it passes.

  Parameters
  ----------
  pool : Pool
    The real, already-open process pool. Never closed by this wrapper;
    the caller that built it still owns its lifecycle.
  before_execute : Callable[[str], Awaitable[None]] | None
    See :class:`_GatedConnection`. Applied to every connection this pool
    hands out, for the life of this wrapper.
  on_committed : Callable[[], None] | None
    See :class:`_GatedTransaction`.
  """

  def __init__(
    self,
    pool: Pool,
    *,
    before_execute: Callable[[str], Any] | None = None,
    on_committed: Callable[[], None] | None = None,
  ) -> None:
    self._pool = pool
    self._before_execute = before_execute
    self._on_committed = on_committed

  def connection(self, *args: object, **kwargs: object) -> _GatedConnectionContext:
    """Return a gated connection context, one per call — one per retry attempt."""
    real_cm = self._pool.connection(*args, **kwargs)
    return _GatedConnectionContext(
      real_cm, before_execute=self._before_execute, on_committed=self._on_committed
    )

  def __getattr__(self, name: str) -> Any:
    return getattr(self._pool, name)


def statement_matches(text: str, *needles: str) -> bool:
  """Return whether every one of ``needles`` appears in ``text`` (case-sensitive).

  Parameters
  ----------
  text : str
    A rendered SQL statement.
  *needles : str
    Substrings that must all be present — e.g. ``"UPDATE"`` and
    ``"public.deals"``, so an unrelated ``UPDATE`` on another table (or a
    ``SELECT ... FROM public.deals``) never matches.

  Returns
  -------
  bool
  """
  return all(needle in text for needle in needles)


class CommitFailingPool:
  """A ``Pool`` proxy whose every transaction's commit raises (**PIN C5**, ``SQL-013``).

  Parameters
  ----------
  pool : Pool
    The real, already-open process pool.
  land : bool
    ``True``: let the real ``COMMIT`` run, **then** raise — the "landed"
    variant (a fresh re-read finds the receipt; the service replays,
    303). ``False``: roll back first, then raise — the "not landed"
    variant (no receipt; the service answers 503 ``ambiguous_commit``).
  only_once : bool
    ``True`` (the default): only the **first** transaction this pool's
    connections open raises; every later one (in particular the fresh
    ``READ COMMITTED`` re-read ``settle_ambiguous`` performs) behaves
    normally. Set ``False`` only for a test that wants every commit to
    keep failing.
  """

  def __init__(self, pool: Pool, *, land: bool, only_once: bool = True) -> None:
    self._pool = pool
    self._land = land
    self._only_once = only_once
    self._fired = False

  def connection(self, *args: object, **kwargs: object) -> _GatedConnectionContext:
    """Return a connection whose transaction commit is made to fail, once."""
    real_cm = self._pool.connection(*args, **kwargs)
    if self._fired and self._only_once:
      return _GatedConnectionContext(real_cm, before_execute=None, on_committed=None)
    self._fired = True
    land = self._land

    class _CommitFailingTransaction:
      """Lets the real transaction settle, then raises a client-side, sqlstate-less error.

      A bare :class:`psycopg.OperationalError` (``sqlstate is None``) is
      exactly what ``app/db/retry.py``'s ``_commit_outcome_unknown``
      classifies as an unknown outcome — a client-side failure with no
      word at all from the server (``contracts/slice-c.md`` §1(g) probe 10).
      """

      def __init__(self, real: Any) -> None:
        self._real = real

      async def __aenter__(self) -> Any:
        return await self._real.__aenter__()

      async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool | None:
        import psycopg

        if exc_type is not None:
          # The transaction body itself raised — never fabricate an
          # ambiguous commit on top of a real, already-explained failure.
          return await self._real.__aexit__(exc_type, exc, tb)
        if land:
          # Let the real COMMIT run (the row lands), then raise as if the
          # ACK for that COMMIT was lost on the way back to the client.
          await self._real.__aexit__(None, None, None)
        else:
          # Force a rollback (the row never lands), then raise the same
          # client-side error — indistinguishable to the caller from the
          # "landed" case, which is PIN C5's whole point.
          rollback_error = psycopg.OperationalError("simulated rollback before COMMIT")
          await self._real.__aexit__(type(rollback_error), rollback_error, None)
        raise psycopg.OperationalError("simulated connection loss around COMMIT")

    class _CommitFailingConnection:
      def __init__(self, real: Any) -> None:
        self._real = real

      def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

      def transaction(self, *t_args: object, **t_kwargs: object) -> _CommitFailingTransaction:
        return _CommitFailingTransaction(self._real.transaction(*t_args, **t_kwargs))

    class _CommitFailingConnectionContext:
      def __init__(self, real_connection_cm: Any) -> None:
        self._real_connection_cm = real_connection_cm

      async def __aenter__(self) -> _CommitFailingConnection:
        real_conn = await self._real_connection_cm.__aenter__()
        return _CommitFailingConnection(real_conn)

      async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool | None:
        return await self._real_connection_cm.__aexit__(exc_type, exc, tb)

    return _CommitFailingConnectionContext(real_cm)

  def __getattr__(self, name: str) -> Any:
    return getattr(self._pool, name)
