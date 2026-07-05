"""VirusTotal URL enrichment. vt-py has no async client, so each lookup runs
in a thread-pool executor behind a semaphore sized for the free-tier rate
limit; per-URL lookups then overlap via asyncio.gather instead of serializing.
"""

from __future__ import annotations

import asyncio
import logging

import vt

logger = logging.getLogger(__name__)

_RATE_LIMIT = asyncio.Semaphore(4)


def _lookup_sync(client: vt.Client, url: str) -> dict:
    try:
        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id)
        stats = url_obj.last_analysis_stats or {}
    except vt.error.APIError:
        try:
            analysis = client.scan_url(url, wait_for_completion=True)
            stats = analysis.get("stats") or getattr(analysis, "stats", None) or {}
        except Exception:
            stats = {}
    except Exception:
        stats = {}

    return {
        "malicious": int(stats.get("malicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
    }


async def enrich_urls(urls: list[str], api_key: str | None) -> dict[str, dict]:
    """Return {url: {"malicious": int, "harmless": int, "suspicious": int}}."""
    if not api_key or not urls:
        return {}

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
    except Exception:
        logger.exception("VirusTotal client failed to initialize")
        return {}

    results: dict[str, dict] = {}
    for pair in pairs:
        if isinstance(pair, Exception):
            logger.warning("VirusTotal lookup failed: %s", pair)
            continue
        url, stats = pair
        results[url] = stats
    return results
