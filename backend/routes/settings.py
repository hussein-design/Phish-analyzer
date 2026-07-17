from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

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
        shodan_key_configured=bool(getattr(record, "shodan_key", None)),
        sandbox_provider=getattr(record, "sandbox_provider", None),
        sandbox_key_configured=bool(getattr(record, "sandbox_api_key", None)),
    )


@router.get("/keys-status")
async def keys_status_endpoint(session: AsyncSession = Depends(get_session)) -> dict:
    """Diagnostic: returns whether each API key is currently saved in the DB.
    Never returns the key values themselves.
    """
    record = await SettingsRepository(session).get()
    return {
        "virustotal_key_configured": bool(record.virustotal_key),
        "abuseipdb_key_configured": bool(record.abuseipdb_key),
    }


@router.get("", response_model=SettingsRead)
async def get_settings_endpoint(session: AsyncSession = Depends(get_session)) -> SettingsRead:
    record = await SettingsRepository(session).get()
    return _to_read(record)


@router.put("", response_model=SettingsRead)
async def update_settings_endpoint(
    payload: SettingsUpdate, session: AsyncSession = Depends(get_session)
) -> SettingsRead:
    """Single atomic update for all settings including optional API keys.

    API keys are only updated when explicitly included in the payload (not None).
    An empty-string value clears the key. Omitting the field leaves it unchanged.
    """
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

    # Determine which key columns (if any) need updating.
    set_vt = False
    set_abuse = False
    set_shodan = False
    set_sandbox = False

    if payload.virustotal_key is not None:
        new_vt = payload.virustotal_key.strip() or None
        logger.info(
            "Settings PUT: updating virustotal_key, clearing=%s, setting_new=%s",
            new_vt is None, new_vt is not None,
        )
        record.virustotal_key = new_vt
        set_vt = True

    if payload.abuseipdb_key is not None:
        new_abuse = payload.abuseipdb_key.strip() or None
        logger.info(
            "Settings PUT: updating abuseipdb_key, clearing=%s, setting_new=%s",
            new_abuse is None, new_abuse is not None,
        )
        record.abuseipdb_key = new_abuse
        set_abuse = True

    if getattr(payload, "shodan_key", None) is not None:
        record.shodan_key = payload.shodan_key.strip() or None
        set_shodan = True
        logger.info("Settings PUT: updating shodan_key")

    if getattr(payload, "sandbox_provider", None) is not None:
        provider_val = payload.sandbox_provider.strip() or None
        # MED-03: validate against the known provider list to prevent arbitrary
        # strings from being persisted and later interpolated into log messages
        # or API requests.  None (empty string → clear) is always allowed.
        _KNOWN_PROVIDERS = {"anyrun", "hybrid_analysis"}
        if provider_val is not None and provider_val not in _KNOWN_PROVIDERS:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid sandbox_provider '{provider_val}'. "
                    f"Must be one of: {sorted(_KNOWN_PROVIDERS)}"
                ),
            )
        record.sandbox_provider = provider_val
        set_sandbox = True
    if getattr(payload, "sandbox_api_key", None) is not None:
        record.sandbox_api_key = payload.sandbox_api_key.strip() or None
        set_sandbox = True
        logger.info("Settings PUT: updating sandbox settings, provider=%s", record.sandbox_provider)

    # Single atomic write
    from sqlalchemy.orm.attributes import flag_modified
    if set_shodan:
        flag_modified(record, "shodan_key")
    if set_sandbox:
        flag_modified(record, "sandbox_provider")
        flag_modified(record, "sandbox_api_key")

    record = await repo.save_all(record, set_vt=set_vt, set_abuse=set_abuse,
                                  set_shodan=set_shodan, set_sandbox=set_sandbox)
    return _to_read(record)


@router.put("/keys", status_code=204)
async def update_keys_endpoint(
    payload: ApiKeysUpdate, session: AsyncSession = Depends(get_session)
) -> None:
    """Dedicated keys-only update. Kept for backwards compatibility.
    Prefer including keys in the main PUT /settings payload instead.
    """
    repo = SettingsRepository(session)
    record = await repo.get()

    set_vt = False
    set_abuse = False

    if payload.virustotal_key is not None:
        new_vt = payload.virustotal_key.strip() or None
        logger.info(
            "Keys PUT: updating virustotal_key, clearing=%s, setting_new=%s",
            new_vt is None,
            new_vt is not None,
        )
        record.virustotal_key = new_vt
        set_vt = True

    if payload.abuseipdb_key is not None:
        new_abuse = payload.abuseipdb_key.strip() or None
        logger.info(
            "Keys PUT: updating abuseipdb_key, clearing=%s, setting_new=%s",
            new_abuse is None,
            new_abuse is not None,
        )
        record.abuseipdb_key = new_abuse
        set_abuse = True

    await repo.save_keys(record, set_vt=set_vt, set_abuse=set_abuse)
