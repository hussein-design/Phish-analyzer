"""Async engine/session construction.

The engine MUST be created inside the FastAPI lifespan startup (i.e. on the
event loop running inside the backend's own thread), never at import time on
the Qt main thread -- aiosqlite binds its connection to whichever loop
created it.
"""

from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine_and_sessionmaker(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(database_url, future=True)

    if database_url.startswith("sqlite"):
        # ORM-level cascade deletes (cascade="all, delete-orphan") work
        # without this, but enabling FK enforcement keeps the DB itself
        # consistent under any future raw-SQL access.
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_sqlite_fk(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory
