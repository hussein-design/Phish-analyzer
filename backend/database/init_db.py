"""First-run database initialization, invoked from the FastAPI lifespan.

Never requires the user to run `alembic upgrade head` manually -- migrations
run programmatically at startup, then the single app_settings row is seeded
if the table is empty.
"""

from __future__ import annotations

import asyncio
import logging

from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.core.defaults import (
    DEFAULT_BRAND_DOMAINS,
    DEFAULT_SCORING_WEIGHTS,
    DEFAULT_SUSPICIOUS_TLDS,
    DEFAULT_URGENCY_KEYWORDS,
    DEFAULT_URL_SHORTENERS,
    DEFAULT_URL_SUSPICIOUS_KEYWORDS,
)
from backend.models.app_settings import AppSettingsRecord
from shared.paths import alembic_ini_path, migrations_dir

logger = logging.getLogger(__name__)


def _run_migrations_sync(sync_database_url: str) -> None:
    cfg = Config(str(alembic_ini_path()))
    cfg.set_main_option("script_location", str(migrations_dir()))
    cfg.set_main_option("sqlalchemy.url", sync_database_url)
    command.upgrade(cfg, "head")


async def run_migrations(sync_database_url: str) -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _run_migrations_sync, sync_database_url)


async def seed_settings_if_empty(session_factory: async_sessionmaker) -> None:
    async with session_factory() as session:
        existing = await session.scalar(select(AppSettingsRecord).limit(1))
        if existing is not None:
            return

        session.add(
            AppSettingsRecord(
                id=1,
                scoring_weights=dict(DEFAULT_SCORING_WEIGHTS),
                brand_domains={k: list(v) for k, v in DEFAULT_BRAND_DOMAINS.items()},
                url_suspicious_keywords=list(DEFAULT_URL_SUSPICIOUS_KEYWORDS),
                suspicious_tlds=list(DEFAULT_SUSPICIOUS_TLDS),
                url_shorteners=list(DEFAULT_URL_SHORTENERS),
                urgency_keywords=list(DEFAULT_URGENCY_KEYWORDS),
                virustotal_key=None,
                abuseipdb_key=None,
            )
        )
        await session.commit()
        logger.info("Seeded default app_settings row")
