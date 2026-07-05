from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from backend.models.app_settings import AppSettingsRecord


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
        # column tells SQLAlchemy to always include them in the UPDATE,
        # regardless of whether it thinks they changed.
        for col in (
            "scoring_weights",
            "brand_domains",
            "url_suspicious_keywords",
            "suspicious_tlds",
            "url_shorteners",
            "urgency_keywords",
        ):
            flag_modified(record, col)

        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record
