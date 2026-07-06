"""VirusTotal URL enrichment — native async via vt-py's async API.

vt-py 0.18+ ships vt.Client as an aiohttp-based async client.  The old code
called it synchronously inside run_in_executor(), which caused
"This event loop is already running" because aiohttp tries to attach to the
running loop at Client construction time.  The fix is to use the async methods
(get_object_async, scan_url_async) and async context manager directly.

Returns a structured result dict:
  status  — "no_key" | "ok" | "no_data" | "rate_limit" | "error"
  error   — human-readable string (only set on non-ok statuses)
  results — {url: {"malicious": int, "harmless": int, "suspicious": int}}
"""

from __future__ import annotations

import asyncio
import logging

import vt

logger = logging.getLogger(__name__)

# VT free tier allows 4 requests/minute; cap concurrent lookups accordingly.
_RATE_LIMIT = asyncio.Semaphore(4)

_QUOTA_MESSAGES = ("quota exceeded", "rate limit", "too many requests")


def _is_quota_error(exc: Exception) -> bool:
    return any(q in str(exc).lower() for q in _QUOTA_MESSAGES)


async def _lookup_one_async(client: vt.Client, url: str) -> tuple[str, dict]:
    """Look up a single URL using the async vt-py API.

    If the URL is not yet in VT's database, submit it for scanning and wait
    for the result (up to the client's timeout).
    """
    async with _RATE_LIMIT:
        try:
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async("/urls/{}", url_id)
            stats = url_obj.last_analysis_stats or {}
        except vt.error.APIError as exc:
            code = getattr(exc, "code", "") or ""
            if "NotFoundError" in str(type(exc)) or code == "NotFoundError":
                # URL not in VT — submit and wait for the analysis to finish.
                try:
                    analysis = await client.scan_url_async(url, wait_for_completion=True)
                    stats = (
                        analysis.get("stats")
                        or getattr(analysis, "stats", None)
                        or {}
                    )
                except Exception:
                    stats = {}
            else:
                raise

    return url, {
        "malicious":  int(stats.get("malicious", 0)),
        "harmless":   int(stats.get("harmless", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
    }


async def enrich_urls(urls: list[str], api_key: str | None) -> dict:
    """Return structured enrichment result for a list of URLs.

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

    try:
        async with vt.Client(api_key) as client:
            pairs = await asyncio.gather(
                *(_lookup_one_async(client, u) for u in urls),
                return_exceptions=True,
            )
    except vt.error.APIError as exc:
        if _is_quota_error(exc):
            logger.warning("VirusTotal rate limit / quota exceeded: %s", exc)
            return {"status": "rate_limit", "error": str(exc), "results": {}}
        logger.exception("VirusTotal client initialisation failed")
        return {"status": "error", "error": str(exc), "results": {}}
    except Exception as exc:
        logger.exception("VirusTotal client initialisation failed")
        return {"status": "error", "error": str(exc), "results": {}}

    results: dict[str, dict] = {}
    last_error: str | None = None

    for pair in pairs:
        if isinstance(pair, Exception):
            if _is_quota_error(pair):
                logger.warning("VirusTotal rate limit during URL lookup: %s", pair)
                return {"status": "rate_limit", "error": str(pair), "results": results}
            logger.warning("VirusTotal lookup failed for one URL: %s", pair)
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
