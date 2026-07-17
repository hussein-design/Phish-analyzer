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
        """Persist the non-key settings columns (scoring, lists, brand domains).

        Deliberately does NOT touch virustotal_key or abuseipdb_key so that a
        concurrent or sequential settings save can never silently overwrite a
        key that was just written by update_keys_endpoint.  Use save_keys()
        for that purpose.

        SQLAlchemy tracks changes to mapped columns, but JSON columns that are
        mutated in-place (or replaced with a new dict/list object) are NOT
        detected as dirty by the default MutableDict/MutableList tracking
        because we use plain JSON columns, not sqlalchemy.ext.mutable. Calling
        flag_modified() for every JSON column tells SQLAlchemy to always
        include those columns in the UPDATE, regardless of whether it thinks
        they changed.
        """
        for col in (
            "scoring_weights",
            "brand_domains",
            "url_suspicious_keywords",
            "suspicious_tlds",
            "url_shorteners",
            "urgency_keywords",
        ):
            flag_modified(record, col)

        logger.debug("Saving app_settings (non-key columns only)")

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

    async def save_all(
        self,
        record: AppSettingsRecord,
        *,
        set_vt: bool = False,
        set_abuse: bool = False,
        set_shodan: bool = False,
        set_sandbox: bool = False,
    ) -> AppSettingsRecord:
        """Persist all columns in a single atomic commit.

        Always writes the 6 non-key JSON columns.  Also writes the key columns
        when the corresponding flag is True.

        This is the preferred method when saving settings and keys together,
        because it avoids the two-request chain that was the root cause of keys
        being silently dropped.
        """
        cols = [
            "scoring_weights",
            "brand_domains",
            "url_suspicious_keywords",
            "suspicious_tlds",
            "url_shorteners",
            "urgency_keywords",
        ]
        if set_vt:
            cols.append("virustotal_key")
            logger.info("save_all: including virustotal_key (configured=%s)", bool(record.virustotal_key))
        if set_abuse:
            cols.append("abuseipdb_key")
            logger.info("save_all: including abuseipdb_key (configured=%s)", bool(record.abuseipdb_key))
        if set_shodan:
            cols.append("shodan_key")
            logger.info("save_all: including shodan_key (configured=%s)", bool(getattr(record, "shodan_key", None)))
        if set_sandbox:
            cols.extend(["sandbox_provider", "sandbox_api_key"])
            logger.info(
                "save_all: including sandbox settings, provider=%s",
                getattr(record, "sandbox_provider", None),
            )

        for col in cols:
            flag_modified(record, col)

        self.session.add(record)
        try:
            await self.session.commit()
        except Exception:
            logger.exception("Failed to commit save_all")
            await self.session.rollback()
            raise
        await self.session.refresh(record)

        logger.info(
            "save_all committed: vt_key_configured=%s, abuse_key_configured=%s, "
            "shodan_key_configured=%s, sandbox_configured=%s",
            bool(record.virustotal_key),
            bool(record.abuseipdb_key),
            bool(getattr(record, "shodan_key", None)),
            bool(getattr(record, "sandbox_api_key", None)),
        )
        return record

    async def save_keys(
        self,
        record: AppSettingsRecord,
        *,
        set_vt: bool = False,
        set_abuse: bool = False,
    ) -> AppSettingsRecord:
        """Persist only the API key columns.

        Callers must pass set_vt=True and/or set_abuse=True to indicate which
        key columns were intentionally modified.  This prevents accidental
        writes when neither key was touched.
        """
        if not set_vt and not set_abuse:
            logger.debug("save_keys() called with nothing to save — skipping")
            return record

        if set_vt:
            flag_modified(record, "virustotal_key")
            logger.info(
                "Saving virustotal_key: configured=%s", bool(record.virustotal_key)
            )
        if set_abuse:
            flag_modified(record, "abuseipdb_key")
            logger.info(
                "Saving abuseipdb_key: configured=%s", bool(record.abuseipdb_key)
            )

        self.session.add(record)
        try:
            await self.session.commit()
        except Exception:
            logger.exception("Failed to commit API key save")
            await self.session.rollback()
            raise
        await self.session.refresh(record)

        logger.info(
            "API keys saved: vt_key_configured=%s, abuse_key_configured=%s",
            bool(record.virustotal_key),
            bool(record.abuseipdb_key),
        )
        return record
