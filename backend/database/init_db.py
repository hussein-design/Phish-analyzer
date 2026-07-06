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


async def seed_settings_if_empty(
    session_factory: async_sessionmaker,
    vt_api_key: str | None = None,
    abuseipdb_api_key: str | None = None,
) -> None:
    """Seed the app_settings row on first run.

    If ``vt_api_key`` or ``abuseipdb_api_key`` are provided (read from the
    .env file by AppSettings on startup), they are written into the DB row so
    that users who previously had keys in .env get them migrated into the GUI-
    editable store without having to re-enter them.
    """
    async with session_factory() as session:
        existing = await session.scalar(select(AppSettingsRecord).limit(1))
        if existing is not None:
            # Row already exists — check if the .env has keys that haven't
            # been persisted yet (migration path for users upgrading from the
            # .env-based config to the DB-based settings).
            updated = False
            if vt_api_key and not existing.virustotal_key:
                existing.virustotal_key = vt_api_key
                updated = True
                logger.info("Migrated VT API key from .env into app_settings DB")
            if abuseipdb_api_key and not existing.abuseipdb_key:
                existing.abuseipdb_key = abuseipdb_api_key
                updated = True
                logger.info("Migrated AbuseIPDB API key from .env into app_settings DB")
            if updated:
                await session.commit()
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
                # Seed from .env if keys were provided there; otherwise None.
                # After this first-run seed, the DB row is the live source of
                # truth — .env is never consulted again for key values.
                virustotal_key=vt_api_key or None,
                abuseipdb_key=abuseipdb_api_key or None,
            )
        )
        await session.commit()
        logger.info(
            "Seeded default app_settings row (vt_key_from_env=%s, abuse_key_from_env=%s)",
            bool(vt_api_key),
            bool(abuseipdb_api_key),
        )
