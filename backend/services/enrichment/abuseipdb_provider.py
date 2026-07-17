"""AbuseIPDB sender-IP reputation lookup.

Returns a structured result dict with:
  status  — "no_key" | "no_data" | "ok" | "rate_limit" | "error"
  error   — human-readable error string (only set when status is error/rate_limit)
  data    — the enrichment payload dict (only set when status is ok)

Native async via httpx — no sync-only client to wrap.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


async def enrich_ip(ip: str | None, api_key: str | None) -> dict:
    """Return structured enrichment result.

    Return value shape::

        {
            "status": "no_key" | "no_data" | "ok" | "rate_limit" | "error",
            "error":  str | None,
            "data":   {
                "abuse_score":    int | None,
                "total_reports":  int | None,
                "country_code":   str | None,
                "isp":            str | None,
            } | None,
        }
    """
    if not api_key:
        return {"status": "no_key", "error": None, "data": None}

    if not ip:
        return {"status": "no_data", "error": None, "data": None}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(_ABUSEIPDB_URL, params=params, headers=headers)

        if resp.status_code == 429:
            msg = "AbuseIPDB rate limit / daily quota exceeded (HTTP 429)"
            logger.warning(msg)
            return {"status": "rate_limit", "error": msg, "data": None}

        if resp.status_code == 401:
            msg = "AbuseIPDB API key is invalid or unauthorised (HTTP 401)"
            logger.warning(msg)
            return {"status": "error", "error": msg, "data": None}

        if resp.status_code != 200:
            msg = f"AbuseIPDB returned unexpected status {resp.status_code}"
            logger.warning("%s for IP %s", msg, ip)
            return {"status": "error", "error": msg, "data": None}

        payload = resp.json().get("data", {})
        result = {
            "abuse_score":   payload.get("abuseConfidenceScore"),
            "total_reports": payload.get("totalReports"),
            "country_code":  payload.get("countryCode"),
            "isp":           payload.get("isp"),
        }
        return {"status": "ok", "error": None, "data": result}

    except httpx.TimeoutException:
        # MED-02: use type name only — exception message may contain the full
        # request URL, which could embed the API key in the Authorization header.
        msg = "AbuseIPDB request timed out"
        logger.warning(msg)
        return {"status": "error", "error": msg, "data": None}

    except Exception as exc:
        # MED-02: log the full exception internally but only return the type
        # name to callers so internal details don't leak.
        logger.exception("AbuseIPDB lookup failed for %s", ip)
        return {"status": "error", "error": f"AbuseIPDB lookup failed: {type(exc).__name__}", "data": None}
