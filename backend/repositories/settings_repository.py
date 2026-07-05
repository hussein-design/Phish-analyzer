from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record
