"""VirusTotal URL enrichment.

Returns a structured result dict with:
  status  — "no_key" | "ok" | "no_data" | "rate_limit" | "error"
  error   — human-readable error string (only set when status is not ok/no_data/no_key)
  results — {url: {"malicious": int, "harmless": int, "suspicious": int}}

vt-py has no async client, so each lookup runs in a thread-pool executor behind
a semaphore sized for the free-tier rate limit; per-URL lookups overlap via
asyncio.gather instead of serialising.
"""

from __future__ import annotations

import asyncio
import logging

import vt

logger = logging.getLogger(__name__)

_RATE_LIMIT = asyncio.Semaphore(4)

# VT free tier: 4 req/min.  HTTP 429 response body contains "Quota exceeded".
_QUOTA_MESSAGES = ("quota exceeded", "rate limit", "too many requests")


def _is_quota_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(q in msg for q in _QUOTA_MESSAGES)


def _lookup_sync(client: vt.Client, url: str) -> dict:
    """Lookup one URL.  Returns per-URL stats dict or raises."""
    try:
        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id)
        stats = url_obj.last_analysis_stats or {}
    except vt.error.APIError as exc:
        code = getattr(exc, "code", "") or ""
        if "NotFoundError" in str(type(exc)) or code == "NotFoundError":
            # URL not in VT database — submit and wait
            try:
                analysis = client.scan_url(url, wait_for_completion=True)
                stats = analysis.get("stats") or getattr(analysis, "stats", None) or {}
            except Exception:
                stats = {}
        else:
            raise
    return {
        "malicious":  int(stats.get("malicious", 0)),
        "harmless":   int(stats.get("harmless", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
    }


async def enrich_urls(urls: list[str], api_key: str | None) -> dict:
    """Return structured enrichment result.

    Return value shape::

        {
            "status":  "no_key" | "ok" | "no_data" | "rate_limit" | "error",
            "error":   str | None,
            "results": {url: {"malicious": int, "harmless": int, "suspicious": int}},
        }
    """
    if not api_key:
        return {"status": "no_key", "error": None, "results": {}}

    if not urls:
        return {"status": "no_data", "error": None, "results": {}}

    loop = asyncio.get_running_loop()

    async def lookup_one(client: vt.Client, url: str) -> tuple[str, dict]:
        async with _RATE_LIMIT:
            stats = await loop.run_in_executor(None, _lookup_sync, client, url)
            return url, stats

    try:
        with vt.Client(api_key) as client:
            pairs = await asyncio.gather(
                *(lookup_one(client, u) for u in urls), return_exceptions=True
            )
    except vt.error.APIError as exc:
        if _is_quota_error(exc):
            logger.warning("VirusTotal rate limit / quota exceeded: %s", exc)
            return {"status": "rate_limit", "error": str(exc), "results": {}}
        logger.exception("VirusTotal client failed to initialize")
        return {"status": "error", "error": str(exc), "results": {}}
    except Exception as exc:
        logger.exception("VirusTotal client failed to initialize")
        return {"status": "error", "error": str(exc), "results": {}}

    results: dict[str, dict] = {}
    last_error: str | None = None

    for pair in pairs:
        if isinstance(pair, Exception):
            if _is_quota_error(pair):
                logger.warning("VirusTotal rate limit during lookup: %s", pair)
                return {"status": "rate_limit", "error": str(pair), "results": results}
            logger.warning("VirusTotal lookup failed for a URL: %s", pair)
            last_error = str(pair)
            continue
        url, stats = pair
        results[url] = stats

    if not results and last_error:
        return {"status": "error", "error": last_error, "results": {}}

    return {
        "status": "ok" if results else "no_data",
        "error": None,
        "results": results,
    }
