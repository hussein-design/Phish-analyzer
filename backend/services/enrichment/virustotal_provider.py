"""VirusTotal URL enrichment — native async via vt-py's async API.

Returns a structured result dict:
  status  — "no_key" | "ok" | "no_data" | "rate_limit" | "error"
  error   — human-readable string (only set on non-ok statuses)
  results — {url: {"malicious": int, "harmless": int, "suspicious": int}}

VT Quota fast-fail (Phase B hotfix round 2)
───────────────────────────────────────────
Why analysis 43 spent exactly 300 s on VT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The old code called ``asyncio.gather()`` across ALL uncached URLs.  When the
daily free-tier quota (500 req/day) was exhausted mid-gather, the URL that
triggered the quota error returned immediately, but the remaining N-1 URL
coroutines *kept running* — each one blocked inside ``_RATE_LIMIT`` or waiting
up to ``_SCAN_WAIT_TIMEOUT`` (120 s) for a scan to complete.  With the outer
``_ENRICHMENT_DEADLINE`` set to 300 s, the pipeline sat for the full 5 minutes
before the outer watchdog cancelled the survivors.

Fix applied
~~~~~~~~~~~
1. ``_QuotaExhaustedError`` — a sentinel raised by ``_lookup_one_async`` /
   ``_lookup_hash_async`` on any quota APIError.  Distinguished from ordinary
   errors so the caller can treat it as terminal.

2. ``_quota_exhausted_until`` — a module-level ``datetime | None`` sentinel.
   Set to next UTC midnight when a quota error is confirmed; cleared
   automatically when that time passes.  While set, *every* call to
   ``enrich_urls`` / ``enrich_hashes`` returns ``rate_limit`` immediately
   without making a single HTTP request.

3. ``asyncio.as_completed`` replaces ``asyncio.gather`` so results are
   processed one-by-one.  On the first ``_QuotaExhaustedError``, all
   remaining tasks are cancelled immediately, the sentinel is set, and the
   function returns.  No task waits for its 120-s timeout.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import vt

from backend.services.enrichment.cache import enrichment_cache

logger = logging.getLogger(__name__)

# VT free tier allows 4 requests/minute; cap concurrent lookups accordingly.
_RATE_LIMIT = asyncio.Semaphore(4)

# BUG-12 fix: maximum seconds to wait for a scan_url_async poll to complete.
_SCAN_WAIT_TIMEOUT = 120  # 2 minutes

_QUOTA_MESSAGES = ("quota exceeded", "rate limit", "too many requests")

# ── Module-level quota sentinel ───────────────────────────────────────────────
# Set to the next-UTC-midnight datetime when a quota error is confirmed.
# While set, all VT calls skip immediately.  Cleared when that time passes.
_quota_exhausted_until: Optional[datetime] = None


def _next_midnight_utc() -> datetime:
    """Return the start of tomorrow in UTC (when VT daily quota resets)."""
    now = datetime.now(tz=timezone.utc)
    tomorrow = now.date() + timedelta(days=1)
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)


def _quota_is_exhausted() -> bool:
    """Return True if quota sentinel is active and has not yet expired."""
    global _quota_exhausted_until
    if _quota_exhausted_until is None:
        return False
    if datetime.now(tz=timezone.utc) >= _quota_exhausted_until:
        _quota_exhausted_until = None   # new UTC day — reset
        return False
    return True


def _mark_quota_exhausted() -> None:
    """Record that quota is exhausted; block all calls until UTC midnight."""
    global _quota_exhausted_until
    _quota_exhausted_until = _next_midnight_utc()
    logger.warning(
        "VirusTotal: daily quota exhausted — all VT calls skipped until %s UTC",
        _quota_exhausted_until.strftime("%Y-%m-%d %H:%M:%S"),
    )


class _QuotaExhaustedError(Exception):
    """Raised by individual lookup coroutines on quota/rate-limit API errors.

    Catching this in the outer loop lets us cancel surviving tasks immediately
    rather than waiting for each one's individual timeout.
    """


def _is_quota_error(exc: Exception) -> bool:
    return any(q in str(exc).lower() for q in _QUOTA_MESSAGES)


async def _lookup_one_async(client: vt.Client, url: str) -> tuple[str, dict]:
    """Look up one URL.  Raises _QuotaExhaustedError on quota APIErrors."""
    async with _RATE_LIMIT:
        try:
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async("/urls/{}", url_id)
            stats = url_obj.last_analysis_stats or {}
        except vt.error.APIError as exc:
            if _is_quota_error(exc):
                raise _QuotaExhaustedError(str(exc)) from exc
            code = getattr(exc, "code", "") or ""
            if "NotFoundError" in str(type(exc)) or code == "NotFoundError":
                try:
                    analysis = await asyncio.wait_for(
                        client.scan_url_async(url, wait_for_completion=True),
                        timeout=_SCAN_WAIT_TIMEOUT,
                    )
                    stats = (
                        analysis.get("stats")
                        or getattr(analysis, "stats", None)
                        or {}
                    )
                except asyncio.TimeoutError:
                    stats = {}
                except vt.error.APIError as scan_exc:
                    if _is_quota_error(scan_exc):
                        raise _QuotaExhaustedError(str(scan_exc)) from scan_exc
                    stats = {}
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
    """Return VT enrichment for a list of URLs.

    Fast-fails immediately if quota sentinel is set from a prior call.
    On first quota error during the gather, cancels all remaining tasks and
    sets the sentinel — no further 120-s waits for timed-out tasks.
    """
    if not api_key:
        return {"status": "no_key", "error": None, "results": {}}

    if not urls:
        return {"status": "no_data", "error": None, "results": {}}

    # Fast-fail: quota exhausted from a previous call this process lifetime
    if _quota_is_exhausted():
        logger.info("VirusTotal: skipping — quota exhausted until %s UTC", _quota_exhausted_until)
        return {
            "status": "rate_limit",
            "error": f"Daily quota exhausted; resets at {_quota_exhausted_until} UTC",
            "results": {},
        }

    # Cache check
    cached_results: dict[str, dict] = {}
    uncached_urls: list[str] = []
    for url in urls:
        hit = await enrichment_cache.get("virustotal_url", url)
        if hit is not None:
            cached_results[url] = hit  # type: ignore[assignment]
            logger.debug("VT URL cache hit: %s", url)
        else:
            uncached_urls.append(url)

    if not uncached_urls:
        return {"status": "ok", "error": None, "results": cached_results}

    results: dict[str, dict] = dict(cached_results)
    last_error: str | None = None
    quota_error: str | None = None

    try:
        async with vt.Client(api_key) as client:
            # Use ensure_future so we can cancel survivors individually
            tasks = [
                asyncio.ensure_future(_lookup_one_async(client, u))
                for u in uncached_urls
            ]
            for coro in asyncio.as_completed(tasks):
                try:
                    url, stats = await coro
                    results[url] = stats
                    await enrichment_cache.set("virustotal_url", url, stats)
                except _QuotaExhaustedError as qe:
                    quota_error = str(qe)
                    remaining = [t for t in tasks if not t.done()]
                    logger.warning(
                        "VirusTotal quota hit — cancelling %d remaining task(s) immediately",
                        len(remaining),
                    )
                    for t in remaining:
                        t.cancel()
                    await asyncio.gather(*remaining, return_exceptions=True)
                    _mark_quota_exhausted()
                    break
                except asyncio.CancelledError:
                    pass   # task was cancelled by a prior quota hit — ignore
                except Exception as exc:
                    logger.warning("VirusTotal lookup failed for one URL: %s", exc)
                    last_error = str(exc)

    except vt.error.APIError as exc:
        if _is_quota_error(exc):
            _mark_quota_exhausted()
            return {"status": "rate_limit", "error": str(exc), "results": cached_results}
        logger.exception("VirusTotal client init failed")
        return {"status": "error", "error": str(exc), "results": cached_results}
    except Exception as exc:
        logger.exception("VirusTotal client init failed")
        return {"status": "error", "error": str(exc), "results": cached_results}

    if quota_error is not None:
        return {"status": "rate_limit", "error": quota_error, "results": results}

    if not results and last_error:
        return {"status": "error", "error": last_error, "results": {}}

    return {"status": "ok" if results else "no_data", "error": None, "results": results}


async def _lookup_hash_async(client: vt.Client, sha256: str) -> tuple[str, dict]:
    """Look up one file hash.  Raises _QuotaExhaustedError on quota errors."""
    async with _RATE_LIMIT:
        try:
            file_obj = await client.get_object_async("/files/{}", sha256)
            stats = file_obj.last_analysis_stats or {}
        except vt.error.APIError as exc:
            if _is_quota_error(exc):
                raise _QuotaExhaustedError(str(exc)) from exc
            code = getattr(exc, "code", "") or ""
            if "NotFoundError" in str(type(exc)) or code == "NotFoundError":
                stats = {}
            else:
                raise
    return sha256, {
        "malicious":  int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless":   int(stats.get("harmless", 0)),
    }


async def enrich_hashes(sha256_list: list[str], api_key: str | None) -> dict:
    """Return VT file-hash reputation.  Fast-fails if quota sentinel is set."""
    if not api_key:
        return {"status": "no_key", "error": None, "results": {}}

    if _quota_is_exhausted():
        return {
            "status": "rate_limit",
            "error": f"Daily quota exhausted; resets at {_quota_exhausted_until} UTC",
            "results": {},
        }

    hashes = [h for h in sha256_list if h and len(h) == 64]
    if not hashes:
        return {"status": "no_data", "error": None, "results": {}}

    cached_results: dict[str, dict] = {}
    uncached_hashes: list[str] = []
    for h in hashes:
        hit = await enrichment_cache.get("virustotal_hash", h)
        if hit is not None:
            cached_results[h] = hit  # type: ignore[assignment]
            logger.debug("VT hash cache hit: %s", h[:16])
        else:
            uncached_hashes.append(h)

    if not uncached_hashes:
        return {"status": "ok", "error": None, "results": cached_results}

    results: dict[str, dict] = dict(cached_results)
    last_error: str | None = None
    quota_error: str | None = None

    try:
        async with vt.Client(api_key) as client:
            tasks = [
                asyncio.ensure_future(_lookup_hash_async(client, h))
                for h in uncached_hashes
            ]
            for coro in asyncio.as_completed(tasks):
                try:
                    sha256, stats = await coro
                    results[sha256] = stats
                    await enrichment_cache.set("virustotal_hash", sha256, stats)
                except _QuotaExhaustedError as qe:
                    quota_error = str(qe)
                    remaining = [t for t in tasks if not t.done()]
                    for t in remaining:
                        t.cancel()
                    await asyncio.gather(*remaining, return_exceptions=True)
                    _mark_quota_exhausted()
                    break
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    last_error = str(exc)

    except vt.error.APIError as exc:
        if _is_quota_error(exc):
            _mark_quota_exhausted()
            return {"status": "rate_limit", "error": str(exc), "results": cached_results}
        return {"status": "error", "error": str(exc), "results": cached_results}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "results": cached_results}

    if quota_error is not None:
        return {"status": "rate_limit", "error": quota_error, "results": results}

    if not results and last_error:
        return {"status": "error", "error": last_error, "results": {}}

    return {"status": "ok" if results else "no_data", "error": None, "results": results}
