from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.app_settings import AppSettingsRecord
from backend.repositories.settings_repository import SettingsRepository
from backend.routes.deps import get_session
from shared.schemas import ApiKeysUpdate, ScoringWeights, SettingsRead, SettingsUpdate

router = APIRouter()


def _to_read(record: AppSettingsRecord) -> SettingsRead:
    return SettingsRead(
        scoring=ScoringWeights(**record.scoring_weights),
        brand_domains=record.brand_domains,
        url_suspicious_keywords=record.url_suspicious_keywords,
        suspicious_tlds=record.suspicious_tlds,
        url_shorteners=record.url_shorteners,
        urgency_keywords=record.urgency_keywords,
        virustotal_key_configured=bool(record.virustotal_key),
        abuseipdb_key_configured=bool(record.abuseipdb_key),
    )


@router.get("", response_model=SettingsRead)
async def get_settings_endpoint(session: AsyncSession = Depends(get_session)) -> SettingsRead:
    record = await SettingsRepository(session).get()
    return _to_read(record)


@router.put("", response_model=SettingsRead)
async def update_settings_endpoint(
    payload: SettingsUpdate, session: AsyncSession = Depends(get_session)
) -> SettingsRead:
    repo = SettingsRepository(session)
    record = await repo.get()

    if payload.scoring is not None:
        record.scoring_weights = payload.scoring.model_dump()
    if payload.brand_domains is not None:
        record.brand_domains = payload.brand_domains
    if payload.url_suspicious_keywords is not None:
        record.url_suspicious_keywords = payload.url_suspicious_keywords
    if payload.suspicious_tlds is not None:
        record.suspicious_tlds = payload.suspicious_tlds
    if payload.url_shorteners is not None:
        record.url_shorteners = payload.url_shorteners
    if payload.urgency_keywords is not None:
        record.urgency_keywords = payload.urgency_keywords

    record = await repo.save(record)
    return _to_read(record)


@router.put("/keys", status_code=204)
async def update_keys_endpoint(
    payload: ApiKeysUpdate, session: AsyncSession = Depends(get_session)
) -> None:
    repo = SettingsRepository(session)
    record = await repo.get()

    if payload.virustotal_key is not None:
        record.virustotal_key = payload.virustotal_key or None
    if payload.abuseipdb_key is not None:
        record.abuseipdb_key = payload.abuseipdb_key or None

    await repo.save(record)
