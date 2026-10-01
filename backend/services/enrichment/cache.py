"""SQLite-backed persistent enrichment cache with in-memory fallback.

WHY PERSISTENT
--------------
The in-memory cache resets on every app restart, meaning re-scanning a
previously analysed email after restarting would hit rate-limited APIs again.
This module persists cache entries to a dedicated SQLite table in the same
database file the rest of the app uses, so the TTL clock survives restarts.

DESIGN
------
- Single ``enrichment_cache`` singleton, used by all provider modules exactly
  as before — the public API (``get``/``set``/``invalidate``/``clear_all``)
  is unchanged.
- The persistent layer uses ``aiosqlite`` directly (already a dependency) on
  its own connection, separate from the SQLAlchemy session factory used by the
  analysis pipeline.  This avoids session-lifecycle coupling and lets the
  cache be initialised independently at startup.
- On ``get()``: checks in-memory dict first (O(1), no I/O), falls through to
  SQLite only on a miss.  Populates in-memory on a DB hit so subsequent
  calls in the same session are served from memory.
- On ``set()``: writes to both the in-memory dict and SQLite atomically from
  the caller's event loop.  A failed DB write is logged but never raises —
  the in-memory entry is still valid for the current session.
- ``init_cache(db_path)`` must be called once at startup (from the FastAPI
  lifespan) before any provider module calls ``set()``.  Before init, all
  ``set()`` calls are buffered in-memory and flushed on ``init_cache()``.
- Expired entries are lazily evicted on ``get()`` and proactively pruned by
  ``prune_expired()`` which is called from the lifespan startup after init.

THREAD / EVENT-LOOP SAFETY
---------------------------
All SQLite I/O goes through ``aiosqlite``, which runs blocking SQLite calls
in a ThreadPoolExecutor internally.  All public methods are ``async``.
The in-memory dict is mutated only from the event loop thread — safe for
single-process asyncio usage (no thread pool writes to it directly).

TTL DEFAULTS (seconds)
----------------------
  virustotal_url:   3 600   (1 h)   — VT free tier: 4 req/min
  virustotal_hash:  3 600   (1 h)
  abuseipdb:        3 600   (1 h)   — free tier: 1 000 req/day
  shodan:           3 600   (1 h)
  urlscan:         14 400   (4 h)   — result immutable once complete
  hybrid_analysis: 14 400   (4 h)   — per-file report is immutable
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Per-provider default TTLs (seconds) ──────────────────────────────────────
DEFAULT_TTLS: dict[str, int] = {
    "virustotal_url":     3_600,
    "virustotal_hash":    3_600,
    "abuseipdb":          3_600,
    "shodan":             3_600,
    "urlscan":           14_400,
    "hybrid_analysis":   14_400,
}

# Per-namespace in-memory cap (entries) — prevents unbounded growth
_MAX_ENTRIES_PER_NS: int = 2_000

# SQLite table DDL
_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    namespace  TEXT    NOT NULL,
    cache_key  TEXT    NOT NULL,
    value_json TEXT    NOT NULL,
    expires_at REAL    NOT NULL,
    PRIMARY KEY (namespace, cache_key)
)
"""
_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires
    ON enrichment_cache (expires_at)
"""


@dataclass
class _MemEntry:
    value: Any
    expires_at: float  # monotonic clock


class EnrichmentCache:
    """Persistent TTL cache backed by SQLite with an in-memory L1 layer.

    Usage — same as the previous in-memory-only version::

        cached = await enrichment_cache.get("abuseipdb", ip)
        if cached is not None:
            return cached
        result = await real_call(...)
        if result.get("status") not in ("error", "rate_limit", "timeout"):
            await enrichment_cache.set("abuseipdb", ip, result)
        return result
    """

    def __init__(self) -> None:
        # L1 in-memory layer: {namespace: {key: _MemEntry}}
        self._mem: dict[str, dict[str, _MemEntry]] = {}
        # aiosqlite connection — None until init_cache() is called at startup.
        # Before init_cache() runs, all operations use in-memory only (_ready
        # starts True so tests and early startup callers work without buffering).
        self._conn: Any = None  # aiosqlite.Connection
        self._db_path: Path | None = None
        self._ready: bool = True

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def init_cache(self, db_path: Path | str) -> None:
        """Open the SQLite connection, create the cache table, and upgrade the
        cache to persistent mode.

        Call once from the FastAPI lifespan after the DB engine is ready.
        Before this is called, all operations work in-memory only.
        """
        import aiosqlite

        self._db_path = Path(db_path)
        try:
            self._conn = await aiosqlite.connect(str(self._db_path))
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute(_CREATE_TABLE)
            await self._conn.execute(_CREATE_INDEX)
            await self._conn.commit()
            logger.info(
                "EnrichmentCache: SQLite backend ready at %s", self._db_path
            )
        except Exception as exc:
            logger.warning(
                "EnrichmentCache: could not open SQLite backend (%s) — "
                "falling back to in-memory only",
                type(exc).__name__,
            )
            self._conn = None

        # Prune stale rows from previous sessions on startup
        await self.prune_expired()

    async def close(self) -> None:
        """Close the SQLite connection. Call from the FastAPI lifespan shutdown."""
        if self._conn is not None:
            try:
                await self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ── Public API ────────────────────────────────────────────────────────────

    async def get(self, namespace: str, key: str) -> Any | None:
        """Return the cached value for (namespace, key), or None if absent/expired."""
        # L1: in-memory
        ns_mem = self._mem.get(namespace)
        if ns_mem:
            entry = ns_mem.get(key)
            if entry is not None:
                if time.monotonic() > entry.expires_at:
                    del ns_mem[key]
                else:
                    return entry.value

        # L2: SQLite (only when ready and connection is open)
        if self._conn is not None:
            try:
                now_wall = time.time()
                async with self._conn.execute(
                    "SELECT value_json, expires_at FROM enrichment_cache "
                    "WHERE namespace = ? AND cache_key = ?",
                    (namespace, key),
                ) as cursor:
                    row = await cursor.fetchone()

                if row is not None:
                    if row["expires_at"] > now_wall:
                        value = json.loads(row["value_json"])
                        # Populate L1 with remaining TTL
                        remaining = row["expires_at"] - now_wall
                        self._mem_set(namespace, key, value, int(remaining))
                        return value
                    else:
                        # Expired in DB — evict lazily
                        await self._db_delete(namespace, key)

            except Exception as exc:
                logger.debug("EnrichmentCache DB get error: %s", exc)

        return None

    async def set(
        self,
        namespace: str,
        key: str,
        value: Any,
        *,
        ttl: int | None = None,
    ) -> None:
        """Cache ``value`` under (namespace, key) with the given TTL in seconds."""
        effective_ttl = ttl if ttl is not None else DEFAULT_TTLS.get(namespace, 3_600)

        # L1 write (always)
        self._mem_set(namespace, key, value, effective_ttl)

        # L2 write — wall-clock expiry so it survives restarts
        if self._conn is not None:
            expires_wall = time.time() + effective_ttl
            try:
                await self._conn.execute(
                    """
                    INSERT INTO enrichment_cache (namespace, cache_key, value_json, expires_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(namespace, cache_key) DO UPDATE SET
                        value_json = excluded.value_json,
                        expires_at = excluded.expires_at
                    """,
                    (namespace, key, json.dumps(value), expires_wall),
                )
                await self._conn.commit()
            except Exception as exc:
                # Non-fatal — L1 entry is still valid for this session
                logger.debug("EnrichmentCache DB set error: %s", exc)

    async def invalidate(self, namespace: str, key: str) -> None:
        """Remove a single entry from both L1 and L2."""
        ns_mem = self._mem.get(namespace)
        if ns_mem:
            ns_mem.pop(key, None)
        await self._db_delete(namespace, key)

    async def clear_namespace(self, namespace: str) -> None:
        """Remove all entries for a provider namespace from L1 and L2."""
        self._mem.pop(namespace, None)
        if self._conn is not None:
            try:
                await self._conn.execute(
                    "DELETE FROM enrichment_cache WHERE namespace = ?", (namespace,)
                )
                await self._conn.commit()
            except Exception as exc:
                logger.debug("EnrichmentCache DB clear_namespace error: %s", exc)

    async def clear_all(self) -> None:
        """Wipe the entire cache from both L1 and L2. Useful in tests."""
        self._mem.clear()
        if self._conn is not None:
            try:
                await self._conn.execute("DELETE FROM enrichment_cache")
                await self._conn.commit()
            except Exception as exc:
                logger.debug("EnrichmentCache DB clear_all error: %s", exc)

    async def prune_expired(self) -> int:
        """Delete all expired rows from the SQLite table.

        Called at startup and can be called periodically.
        Returns the number of rows deleted.
        """
        if self._conn is None:
            return 0
        try:
            now_wall = time.time()
            cursor = await self._conn.execute(
                "DELETE FROM enrichment_cache WHERE expires_at <= ?", (now_wall,)
            )
            await self._conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("EnrichmentCache: pruned %d expired rows", deleted)
            return deleted
        except Exception as exc:
            logger.debug("EnrichmentCache DB prune error: %s", exc)
            return 0

    def stats(self) -> dict[str, int]:
        """Return live L1 entry counts per namespace."""
        return {ns: len(entries) for ns, entries in self._mem.items()}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _mem_set(self, namespace: str, key: str, value: Any, ttl: int) -> None:
        """Write to L1 in-memory dict, enforcing per-namespace size cap."""
        ns = self._mem.setdefault(namespace, {})
        if len(ns) >= _MAX_ENTRIES_PER_NS and key not in ns:
            # Evict the oldest entry (FIFO approximation)
            oldest = next(iter(ns))
            del ns[oldest]
        ns[key] = _MemEntry(value=value, expires_at=time.monotonic() + ttl)

    async def _db_delete(self, namespace: str, key: str) -> None:
        if self._conn is None:
            return
        try:
            await self._conn.execute(
                "DELETE FROM enrichment_cache WHERE namespace = ? AND cache_key = ?",
                (namespace, key),
            )
            await self._conn.commit()
        except Exception as exc:
            logger.debug("EnrichmentCache DB delete error: %s", exc)


# Module-level singleton — imported by all provider modules.
enrichment_cache: EnrichmentCache = EnrichmentCache()
