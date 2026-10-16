"""FastAPI application factory.

Lifespan step order (each step emits an INFO log line so a stall is
immediately visible in the log file):

  1. run_migrations       — Alembic upgrade head (sync, run_in_executor)
  2. create_engine        — build async SQLAlchemy engine + sessionmaker
  3. seed_settings        — insert default app_settings row on first run
  4. mark_interrupted     — mark PENDING/RUNNING rows from a previous crash
  5. init_cache           — open aiosqlite enrichment-cache connection
  6. reaper_started       — launch _reaper_loop background task
  7. startup_complete     — backend is ready to serve requests

ROOT CAUSE OF STARTUP HANG (fixed here)
----------------------------------------
``asyncio`` was never imported in this module.  The lifespan called
``asyncio.create_task(...)`` at step 6, which raised::

    NameError: name 'asyncio' is not defined

The exception propagated out of the ``@asynccontextmanager`` generator,
which made uvicorn treat startup as failed — it never entered its serving
loop, so ``GET /health`` always timed out (15 s), and the launcher showed
"could not start its local backend service".

Fix: add ``import asyncio`` at the top of this file.

SECONDARY BLOCKING CALL (not a stall, but documented)
------------------------------------------------------
``get_settings()`` is called synchronously in ``create_app()`` on the Qt
main thread before uvicorn starts.  It reads the ``.env`` file from disk via
pydantic-settings.  On a warm OS file-cache this takes < 1 ms and is not the
source of the reported hang, but it is the only truly synchronous I/O call in
the startup path.  All other steps are async (run_in_executor for Alembic,
aiosqlite for the enrichment cache, async SQLAlchemy for every DB query).
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.core.config import get_settings
from backend.core.exceptions import register_exception_handlers
from backend.core.logging import configure_logging
from backend.database.init_db import run_migrations, seed_settings_if_empty
from backend.database.session import create_engine_and_sessionmaker
from backend.routes import analyses, health
from backend.routes import settings as settings_routes
from backend.services.analysis_service import AnalysisService
from backend.services.enrichment.cache import enrichment_cache

logger = logging.getLogger(__name__)


class LocalhostOnlyMiddleware(BaseHTTPMiddleware):
    """Reject every request that did not originate from 127.0.0.1 / ::1.

    The backend is intentionally an in-process local service.  This middleware
    is a defence-in-depth measure: even if the port is somehow reachable from
    another host (e.g. via a misconfigured VPN or container bridge), all
    non-loopback requests are refused with 403 before they reach any route
    handler or touch the database.
    """

    _LOOPBACK = {"127.0.0.1", "::1", "localhost"}

    async def dispatch(self, request: Request, call_next):
        client_host = request.client.host if request.client else ""
        if client_host not in self._LOOPBACK:
            logger.warning(
                "Rejected non-localhost request from %s %s", client_host, request.url.path
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access denied: this API is localhost-only."},
            )
        return await call_next(request)


def create_app() -> FastAPI:
    app_settings = get_settings()
    configure_logging(app_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # ── Step 1: Alembic migrations ────────────────────────────────────
        # Runs synchronously inside run_in_executor so the event loop is
        # never blocked.  "Will assume non-transactional DDL." printed by
        # Alembic to stdout is normal SQLite behaviour — not an error.
        logger.info("Lifespan [1/7] running database migrations …")
        await run_migrations(app_settings.sync_database_url())
        logger.info("Lifespan [1/7] migrations done")

        # ── Step 2: async engine + session factory ────────────────────────
        logger.info("Lifespan [2/7] creating async engine …")
        engine, session_factory = create_engine_and_sessionmaker(
            app_settings.async_database_url()
        )
        app.state.engine = engine
        app.state.session_factory = session_factory
        logger.info("Lifespan [2/7] engine ready (%s)", app_settings.async_database_url())

        # ── Step 3: seed app_settings on first run ────────────────────────
        logger.info("Lifespan [3/7] seeding app_settings if empty …")
        await seed_settings_if_empty(
            session_factory,
            vt_api_key=app_settings.vt_api_key,
            abuseipdb_api_key=app_settings.abuseipdb_api_key,
        )
        logger.info("Lifespan [3/7] settings seed done")

        # ── Step 4: mark interrupted analyses as FAILED ───────────────────
        # If the app was closed (or crashed) while an analysis was in flight,
        # that row stays in RUNNING/PENDING forever — the pipeline asyncio task
        # died with the process.  On the next startup we mark those rows FAILED
        # so the UI shows "Failed" rather than a permanent "Analyzing…" spinner.
        # This runs before any new analysis tasks start so there is no race.
        logger.info("Lifespan [4/7] marking interrupted analyses …")
        async with session_factory() as _startup_session:
            from backend.repositories.analysis_repository import AnalysisRepository as _AR
            _interrupted = await _AR(_startup_session).mark_interrupted()
        logger.info(
            "Lifespan [4/7] interrupted cleanup done (%d row(s) marked FAILED)",
            _interrupted,
        )

        # ── Step 5: AnalysisService ───────────────────────────────────────
        logger.info("Lifespan [5/7] initialising AnalysisService …")
        app.state.analysis_service = AnalysisService(
            session_factory=session_factory,
            vt_api_key_env=app_settings.vt_api_key,
            abuseipdb_key_env=app_settings.abuseipdb_api_key,
        )
        logger.info("Lifespan [5/7] AnalysisService ready")

        # ── Step 6: enrichment cache ──────────────────────────────────────
        # Opens a dedicated aiosqlite connection to the same DB file and
        # creates the enrichment_cache table if it does not exist yet.
        # prune_expired() is called inside init_cache to evict stale rows
        # from previous sessions; on a cold start this is instant.
        logger.info("Lifespan [6/7] initialising enrichment cache …")
        from shared.paths import db_path as _db_path
        await enrichment_cache.init_cache(_db_path())
        logger.info("Lifespan [6/7] enrichment cache ready")

        # ── Step 7: runtime reaper background task ────────────────────────
        # Starts a background coroutine that sleeps 60 s, then marks any
        # PENDING/RUNNING rows that have no live asyncio task and are older
        # than 15 min as FAILED.  The first iteration does NOT run at startup
        # — it always begins with asyncio.sleep(60) — so this step completes
        # immediately without touching the DB.
        logger.info("Lifespan [7/7] starting runtime reaper …")
        from backend.services.analysis_service import _reaper_loop as _rl
        _reaper_task = asyncio.create_task(_rl(session_factory))
        logger.info("Lifespan [7/7] reaper started — backend startup complete")

        yield

        # ── Shutdown ──────────────────────────────────────────────────────
        logger.info("Lifespan shutdown: cancelling reaper …")
        _reaper_task.cancel()
        try:
            await _reaper_task
        except asyncio.CancelledError:
            pass
        logger.info("Lifespan shutdown: closing enrichment cache …")
        await enrichment_cache.close()
        await engine.dispose()
        logger.info("Lifespan shutdown complete")

    app = FastAPI(
        title="Phish Analyzer Desktop API",
        version="3.0.0",
        lifespan=lifespan,
        # Disable the interactive docs UI and raw OpenAPI schema endpoint in
        # the packaged app.  The /openapi.json endpoint is still available for
        # internal tooling (e.g. curl-based testing) but the Swagger/ReDoc UIs
        # that render it are removed to reduce the exposed attack surface.
        docs_url=None,
        redoc_url=None,
    )

    # Localhost-only guard — must be added before any route handlers
    app.add_middleware(LocalhostOnlyMiddleware)

    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
    app.include_router(settings_routes.router, prefix="/settings", tags=["settings"])

    return app
