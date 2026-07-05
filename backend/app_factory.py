from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.core.config import get_settings
from backend.core.exceptions import register_exception_handlers
from backend.core.logging import configure_logging
from backend.database.init_db import run_migrations, seed_settings_if_empty
from backend.database.session import create_engine_and_sessionmaker
from backend.routes import analyses, health
from backend.routes import settings as settings_routes
from backend.services.analysis_service import AnalysisService

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app_settings = get_settings()
    configure_logging(app_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await run_migrations(app_settings.sync_database_url())

        engine, session_factory = create_engine_and_sessionmaker(
            app_settings.async_database_url()
        )
        app.state.engine = engine
        app.state.session_factory = session_factory

        await seed_settings_if_empty(session_factory)

        app.state.analysis_service = AnalysisService(
            session_factory=session_factory,
            vt_api_key_env=app_settings.vt_api_key,
            abuseipdb_key_env=app_settings.abuseipdb_api_key,
        )

        logger.info("Backend startup complete (db=%s)", app_settings.async_database_url())
        yield

        await engine.dispose()
        logger.info("Backend shutdown complete")

    app = FastAPI(
        title="Phish Analyzer Desktop API",
        version="1.0.0",
        lifespan=lifespan,
    )

    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
    app.include_router(settings_routes.router, prefix="/settings", tags=["settings"])

    return app
