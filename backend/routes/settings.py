from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from backend.models.app_settings import AppSettingsRecord
from backend.repositories.settings_repository import SettingsRepository
from backend.routes.deps import get_session
from shared.schemas import ApiKeysUpdate, ScoringWeights, SettingsRead, SettingsUpdate

router = APIRouter()
logger = logging.getLogger(__name__)


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
        new_vt = payload.virustotal_key or None
        logger.info(
            "Updating virustotal_key: clearing=%s, setting_new=%s",
            new_vt is None,
            new_vt is not None,
        )
        record.virustotal_key = new_vt
        # Explicitly mark the column dirty so SQLAlchemy includes it in the
        # UPDATE even if its attribute change tracking is bypassed.
        flag_modified(record, "virustotal_key")

    if payload.abuseipdb_key is not None:
        new_abuse = payload.abuseipdb_key or None
        logger.info(
            "Updating abuseipdb_key: clearing=%s, setting_new=%s",
            new_abuse is None,
            new_abuse is not None,
        )
        record.abuseipdb_key = new_abuse
        flag_modified(record, "abuseipdb_key")

    await repo.save(record)
