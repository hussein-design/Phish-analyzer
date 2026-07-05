"""AbuseIPDB sender-IP reputation lookup. Native async via httpx -- unlike
VirusTotal, there's no sync-only client to wrap, so this stays a plain
async function."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def enrich_ip(ip: str | None, api_key: str | None) -> dict:
    if not ip or not api_key:
        return {}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(_ABUSEIPDB_URL, params=params, headers=headers)
        if resp.status_code != 200:
            return {}
        data = resp.json().get("data", {})
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
        }
    except Exception:
        logger.exception("AbuseIPDB lookup failed for %s", ip)
        return {}
