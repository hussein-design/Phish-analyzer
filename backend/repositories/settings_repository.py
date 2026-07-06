from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from backend.models.app_settings import AppSettingsRecord

logger = logging.getLogger(__name__)


class SettingsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self) -> AppSettingsRecord:
        record = await self.session.scalar(select(AppSettingsRecord).limit(1))
        if record is None:
            raise RuntimeError(
                "app_settings row missing -- seed_settings_if_empty() should "
                "have run during startup"
            )
        return record

    async def save(self, record: AppSettingsRecord) -> AppSettingsRecord:
        # SQLAlchemy tracks changes to mapped columns, but JSON columns that
        # are mutated in-place (or replaced with a new dict/list object) are
        # NOT detected as dirty by the default MutableDict/MutableList
        # tracking because we use plain JSON columns, not
        # sqlalchemy.ext.mutable.  Calling flag_modified() for every JSON
        # column (and for the String key columns, for which the instrumented
        # attribute tracking can be skipped under certain session states) tells
        # SQLAlchemy to always include every column in the UPDATE, regardless
        # of whether it thinks they changed.
        for col in (
            "scoring_weights",
            "brand_domains",
            "url_suspicious_keywords",
            "suspicious_tlds",
            "url_shorteners",
            "urgency_keywords",
            "virustotal_key",
            "abuseipdb_key",
        ):
            flag_modified(record, col)

        logger.debug(
            "Saving app_settings: vt_key_set=%s, abuse_key_set=%s",
            bool(record.virustotal_key),
            bool(record.abuseipdb_key),
        )

        self.session.add(record)
        try:
            await self.session.commit()
        except Exception:
            logger.exception("Failed to commit app_settings save")
            await self.session.rollback()
            raise
        await self.session.refresh(record)

        logger.info(
            "app_settings saved: vt_key_configured=%s, abuse_key_configured=%s",
            bool(record.virustotal_key),
            bool(record.abuseipdb_key),
        )
        return record
