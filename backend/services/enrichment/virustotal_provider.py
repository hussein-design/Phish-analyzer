"""VirusTotal URL enrichment — native async via vt-py's async API.

Returns a structured result dict:
  status       — "no_key" | "ok" | "no_data" | "rate_limit" | "error"
  error        — human-readable string (only set on non-ok statuses)
  results      — {url: {"malicious": int, "harmless": int, "suspicious": int}}
  urls_checked — how many URLs were submitted (after dedup + cap)
  urls_total   — total URLs in the original list passed by the caller

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

Fix applied (quota fast-fail)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

Fix applied (cancellation propagation — Python < 3.12 bug)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Root cause of the 4-minute block observed in the logs (09:25:19 deadline,
09:29:43 VT summary line):

``asyncio.wait_for(coro, timeout=T)`` on Python < 3.12 does NOT propagate
an *outer* task cancellation immediately.  When the outer task (e.g. the
enrichment gather) is cancelled while ``wait_for`` is blocking on its inner
coroutine, Python < 3.12 catches the ``CancelledError``, cancels the inner
coroutine, and then WAITS for it to finish before re-raising.  If the inner
coroutine is a vt-py ``scan_url_async`` call blocked on an HTTP connection,
this wait can take the full ``_SCAN_WAIT_TIMEOUT`` (120 s).

Fix: ``_lookup_one_async`` wraps ``scan_url_async`` in a Task and uses
``asyncio.wait({task}, timeout=_SCAN_WAIT_TIMEOUT)`` instead of
``wait_for``.  ``asyncio.wait`` does NOT suppress ``CancelledError`` from
an outer cancel — it propagates immediately, so the enrichment deadline
(300 s) finishes within 3 s of the grace period, not 4 minutes later.

Fix applied (abandoned tasks keep making requests)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Root cause: when the enrichment deadline fires and the 3 s grace period
expires, abandoned vt tasks are left running on the event loop.  Since
vt-py uses native aiohttp (not a thread pool), these coroutines keep
executing ``await client.get_object_async(...)`` calls until they naturally
complete — 30+ seconds later — each consuming quota.

Fix: ``_lookup_one_async`` accepts a shared ``asyncio.Event`` called
``abort``.  The flag is checked before every network call.  When the
enrichment deadline fires (or the outer enrich_urls task is cancelled),
``abort.set()`` is called so no further requests are issued.  The event is
set inside the done-callback attached to abandoned tasks and in the
cancellation path of ``enrich_urls``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

import vt

from backend.services.enrichment.cache import enrichment_cache

logger = logging.getLogger(__name__)

# VT free tier allows 4 requests/minute; cap concurrent lookups accordingly.
_RATE_LIMIT = asyncio.Semaphore(4)

# BUG-12 fix: maximum seconds to wait for a scan_url_async poll to complete.
_SCAN_WAIT_TIMEOUT = 120  # 2 minutes

_QUOTA_MESSAGES = ("quota exceeded", "rate limit", "too many requests")

# Maximum URLs submitted to VT per analysis.  Emails with hundreds of tracking
# links would otherwise consume the entire free-tier daily quota (500 req/day)
# in a single analysis.  URLs are deduplicated by registered domain and then
# prioritised before the cap is applied (see select_vt_urls()).
VT_URL_CAP = 15

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


def _registered_domain(url: str) -> str:
    """Return the registrable domain (e.g. 'evil.co.uk' → 'evil.co.uk').

    Uses a simple two-label heuristic: the last two labels of the hostname.
    This avoids a hard dependency on tldextract while still deduplicating
    ``tracker1.evil.com`` and ``tracker2.evil.com`` to the same key.
    For IP hosts the raw host string is returned unchanged.
    """
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return url
    parts = host.split(".")
    # Raw IP addresses (v4) — keep as-is
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host
    # Two or more labels → take last two
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip_host(url: str) -> bool:
    """Return True if the URL host is a raw IPv4 or IPv6 address."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    # IPv6 literal (brackets stripped by urlparse)
    return ":" in host


def _unwrap_url(u: str) -> str:
    """Return the real destination URL for known redirect wrappers.

    Delegates to ``backend.services.url_unwrap.unwrap_url`` — the single
    source of truth for all wrapper patterns (SafeLinks, IRIS, Google /url,
    Proofpoint URLDefense).

    Returns ``u`` unchanged when the URL is not a recognised wrapper or the
    destination parameter is absent / malformed (preserves existing call-site
    contract: callers can compare result == u to detect no-unwrap).
    """
    from backend.services.url_unwrap import unwrap_url
    return unwrap_url(u) or u


def select_vt_urls(
    urls: list[str],
    anchor_mismatches: list[dict] | None = None,
    url_shorteners: list[str] | None = None,
    suspicious_keywords: list[str] | None = None,
    limit: int = VT_URL_CAP,
    per_domain_limit: int = 2,
) -> tuple[list[str], int, dict[str, str]]:
    """Choose up to ``limit`` URLs to submit to VirusTotal.

    Selection algorithm
    ───────────────────
    1. **Unwrap** each URL through known redirect wrappers (SafeLinks,
       Google /url) so that 50 SafeLinks-wrapped URLs pointing to 50
       different destinations are treated as 50 distinct URLs, not as one
       ``safelinks.protection.outlook.com`` domain entry.  A mapping
       ``unwrapped → original`` is built so the Intel tab can still show the
       URL that was present in the email.

    2. **Sort by priority** (lower number = higher priority):
       0 — IP-based host (raw IPv4/IPv6)
       1 — known URL shortener host
       2 — href from an anchor/display mismatch
       3 — contains a suspicious keyword
       4 — everything else

       Sorting is stable: URLs at the same priority keep their original
       relative order.

    3. **Deduplicate by registered domain**, allowing at most
       ``per_domain_limit`` (default 2) URLs per domain.  Because the list is
       already sorted by priority, the first URL per domain is always the most
       suspicious one; the second slot allows a different path/subdomain to
       also appear.

    4. **Apply the cap** — take the first ``limit`` from the deduped list.

    Returns ``(selected_urls, total_unique_domains, unwrap_map)`` where:
    - ``selected_urls`` is the list of unwrapped URLs to submit to VT
    - ``total_unique_domains`` is the count of unique registered domains
      across the full (unwrapped, deduped) URL set before the cap
    - ``unwrap_map`` maps each unwrapped URL back to the original URL as
      it appeared in the email (for display in the Intel tab)
    """
    if not urls:
        return [], 0, {}

    _shorteners = set(url_shorteners or [])
    _keywords = list(suspicious_keywords or [])
    _mismatch_hrefs: set[str] = set()
    for am in (anchor_mismatches or []):
        href = am.get("href", "")
        if href:
            _mismatch_hrefs.add(href)

    # Step 1: unwrap each URL and build the reverse mapping
    unwrap_map: dict[str, str] = {}   # unwrapped → original
    unwrapped_urls: list[str] = []
    for original in urls:
        unwrapped = _unwrap_url(original)
        unwrap_map[unwrapped] = original
        unwrapped_urls.append(unwrapped)

    # Step 2: sort by priority (stable — preserves original order within tier)
    def _priority(u: str) -> int:
        if _is_ip_host(u):
            return 0
        try:
            host = urlparse(u).hostname or ""
        except Exception:
            host = ""
        if any(s in host for s in _shorteners):
            return 1
        if u in _mismatch_hrefs or unwrap_map.get(u, u) in _mismatch_hrefs:
            return 2
        if _keywords and any(kw in u.lower() for kw in _keywords):
            return 3
        return 4

    sorted_urls = sorted(unwrapped_urls, key=_priority)

    # Step 3: deduplicate by registered domain, allowing per_domain_limit per domain
    domain_counts: dict[str, int] = {}
    unique: list[str] = []
    seen_unwrapped: set[str] = set()  # also dedup identical unwrapped URLs
    for u in sorted_urls:
        if u in seen_unwrapped:
            continue
        dom = _registered_domain(u)
        count = domain_counts.get(dom, 0)
        if count < per_domain_limit:
            seen_unwrapped.add(u)
            domain_counts[dom] = count + 1
            unique.append(u)

    total_unique = len(set(_registered_domain(u) for u in unique))

    # Step 4: apply cap
    selected = unique[:limit]
    return selected, total_unique, unwrap_map


async def _lookup_one_async(
    client: vt.Client,
    url: str,
    abort: asyncio.Event,
) -> tuple[str, dict]:
    """Look up one URL.  Raises _QuotaExhaustedError on quota APIErrors.

    ``abort`` is a shared event set by the caller when the enclosing
    analysis ends (deadline, watchdog, or cancellation).  Checking it
    before every network call ensures no further HTTP requests are issued
    after the analysis has finished — fixing the "abandoned task makes
    requests 30 s after analysis ended" bug.

    Why asyncio.wait instead of asyncio.wait_for around scan_url_async
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    asyncio.wait_for(coro, timeout=T) on Python < 3.12 has a well-known
    issue: when the *outer* task is cancelled while wait_for is blocking
    on its inner task, it re-raises CancelledError only AFTER the inner
    task completes — which can take up to _SCAN_WAIT_TIMEOUT (120 s).
    This was the root cause of the 4-minute block observed in the logs.

    The fix wraps scan_url_async in a Task and uses asyncio.wait() with a
    timeout instead.  When the outer task is cancelled, CancelledError
    propagates through asyncio.wait() immediately (asyncio.wait does not
    swallow CancelledError).  The inner scan task gets a done-callback to
    swallow its eventual result/exception so it does not become an
    unhandled exception.
    """
    # Guard: abort before acquiring the semaphore so a cancelled task does not
    # queue up behind the rate-limit and make a request after being abandoned.
    if abort.is_set():
        raise asyncio.CancelledError

    async with _RATE_LIMIT:
        # Guard again after acquiring the semaphore — the task may have been
        # waiting in the semaphore queue while the deadline fired.
        if abort.is_set():
            raise asyncio.CancelledError

        try:
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async("/urls/{}", url_id)
            stats = url_obj.last_analysis_stats or {}
        except vt.error.APIError as exc:
            if _is_quota_error(exc):
                raise _QuotaExhaustedError(str(exc)) from exc
            code = getattr(exc, "code", "") or ""
            if "NotFoundError" in str(type(exc)) or code == "NotFoundError":
                # URL not in VT database — submit it for scanning.
                # Guard before the second network call.
                if abort.is_set():
                    raise asyncio.CancelledError

                _scan_task = asyncio.ensure_future(
                    client.scan_url_async(url, wait_for_completion=True)
                )
                try:
                    _done_set, _pend_set = await asyncio.wait(
                        {_scan_task}, timeout=_SCAN_WAIT_TIMEOUT
                    )
                    if _pend_set:
                        # Timed out — cancel the scan task and leave stats empty.
                        _scan_task.cancel()
                        _scan_task.add_done_callback(
                            lambda fut: fut.exception()
                            if not fut.cancelled() else None
                        )
                        stats = {}
                    else:
                        analysis = _scan_task.result()
                        stats = (
                            analysis.get("stats")
                            or getattr(analysis, "stats", None)
                            or {}
                        )
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


async def enrich_urls(
    urls: list[str],
    api_key: str | None,
    *,
    anchor_mismatches: list[dict] | None = None,
    url_shorteners: list[str] | None = None,
    suspicious_keywords: list[str] | None = None,
    limit: int = VT_URL_CAP,
) -> dict:
    """Return VT enrichment for a list of URLs.

    URLs are deduplicated by registered domain and capped at ``limit``
    before any network calls are made.  The result dict includes
    ``urls_checked`` (how many were submitted) and ``urls_total`` (unique
    domain count from the full list) so callers can show "15 of 85 URLs
    checked" in the UI.

    Fast-fails immediately if quota sentinel is set from a prior call.
    On first quota error during the gather, cancels all remaining tasks and
    sets the sentinel — no further 120-s waits for timed-out tasks.

    The shared ``abort`` event is set when any task is cancelled/abandoned so
    that no HTTP request is issued after the analysis deadline has fired.
    """
    urls_total = len(urls)

    if not api_key:
        return {"status": "no_key", "error": None, "results": {},
                "urls_checked": 0, "urls_total": urls_total}

    if not urls:
        return {"status": "no_data", "error": None, "results": {},
                "urls_checked": 0, "urls_total": 0}

    # Fast-fail: quota exhausted from a previous call this process lifetime
    if _quota_is_exhausted():
        logger.info("VirusTotal: skipping — quota exhausted until %s UTC", _quota_exhausted_until)
        return {
            "status": "rate_limit",
            "error": f"Daily quota exhausted; resets at {_quota_exhausted_until} UTC",
            "results": {},
            "urls_checked": 0,
            "urls_total": urls_total,
        }

    # Apply deduplication + priority cap
    selected_urls, unique_domain_count, unwrap_map = select_vt_urls(
        urls,
        anchor_mismatches=anchor_mismatches,
        url_shorteners=url_shorteners,
        suspicious_keywords=suspicious_keywords,
        limit=limit,
    )
    if len(selected_urls) < unique_domain_count:
        logger.info(
            "VirusTotal: capped to %d of %d unique-domain URLs (%d total) for analysis",
            len(selected_urls), unique_domain_count, urls_total,
        )

    # Cache check
    cached_results: dict[str, dict] = {}
    uncached_urls: list[str] = []
    for url in selected_urls:
        hit = await enrichment_cache.get("virustotal_url", url)
        if hit is not None:
            cached_results[url] = hit  # type: ignore[assignment]
            logger.debug("VT URL cache hit: %s", url)
        else:
            uncached_urls.append(url)

    if not uncached_urls:
        return {"status": "ok", "error": None, "results": cached_results,
                "urls_checked": len(selected_urls), "urls_total": unique_domain_count,
                "unwrap_map": unwrap_map}

    results: dict[str, dict] = dict(cached_results)
    last_error: str | None = None
    quota_error: str | None = None

    # Shared abort event — set when tasks are cancelled/abandoned so no
    # further HTTP requests are issued after the enrichment deadline fires.
    abort = asyncio.Event()

    try:
        async with vt.Client(api_key) as client:
            # Use ensure_future so we can cancel survivors individually
            tasks = [
                asyncio.ensure_future(_lookup_one_async(client, u, abort))
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
                    abort.set()
                    for t in remaining:
                        t.cancel()
                    await asyncio.gather(*remaining, return_exceptions=True)
                    _mark_quota_exhausted()
                    break
                except asyncio.CancelledError:
                    abort.set()  # ensure siblings also stop requesting
                    pass   # task was cancelled by a prior quota hit — ignore
                except Exception as exc:
                    logger.warning("VirusTotal lookup failed for one URL: %s", exc)
                    last_error = str(exc)

    except vt.error.APIError as exc:
        abort.set()
        if _is_quota_error(exc):
            _mark_quota_exhausted()
            return {"status": "rate_limit", "error": str(exc), "results": cached_results,
                    "urls_checked": len(selected_urls), "urls_total": unique_domain_count}
        logger.exception("VirusTotal client init failed")
        return {"status": "error", "error": str(exc), "results": cached_results,
                "urls_checked": len(selected_urls), "urls_total": unique_domain_count}
    except Exception as exc:
        abort.set()
        logger.exception("VirusTotal client init failed")
        return {"status": "error", "error": str(exc), "results": cached_results,
                "urls_checked": len(selected_urls), "urls_total": unique_domain_count}
    finally:
        # Always set abort on exit so any task that outlived the function
        # (due to the 3 s grace period in analysis_service) stops requesting.
        abort.set()

    if quota_error is not None:
        return {"status": "rate_limit", "error": quota_error, "results": results,
                "urls_checked": len(selected_urls), "urls_total": unique_domain_count}

    if not results and last_error:
        return {"status": "error", "error": last_error, "results": {},
                "urls_checked": len(selected_urls), "urls_total": unique_domain_count}

    return {"status": "ok" if results else "no_data", "error": None, "results": results,
            "urls_checked": len(selected_urls), "urls_total": unique_domain_count}


async def _lookup_hash_async(
    client: vt.Client,
    sha256: str,
    abort: asyncio.Event,
) -> tuple[str, dict]:
    """Look up one file hash.  Raises _QuotaExhaustedError on quota errors.

    Checks ``abort`` before each network call to prevent requests after
    the enclosing analysis deadline has fired.
    """
    if abort.is_set():
        raise asyncio.CancelledError

    async with _RATE_LIMIT:
        if abort.is_set():
            raise asyncio.CancelledError

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
    abort = asyncio.Event()

    try:
        async with vt.Client(api_key) as client:
            tasks = [
                asyncio.ensure_future(_lookup_hash_async(client, h, abort))
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
                    abort.set()
                    for t in remaining:
                        t.cancel()
                    await asyncio.gather(*remaining, return_exceptions=True)
                    _mark_quota_exhausted()
                    break
                except asyncio.CancelledError:
                    abort.set()
                    pass
                except Exception as exc:
                    last_error = str(exc)

    except vt.error.APIError as exc:
        abort.set()
        if _is_quota_error(exc):
            _mark_quota_exhausted()
            return {"status": "rate_limit", "error": str(exc), "results": cached_results}
        return {"status": "error", "error": str(exc), "results": cached_results}
    except Exception as exc:
        abort.set()
        return {"status": "error", "error": str(exc), "results": cached_results}
    finally:
        abort.set()

    if quota_error is not None:
        return {"status": "rate_limit", "error": quota_error, "results": results}

    if not results and last_error:
        return {"status": "error", "error": last_error, "results": {}}

    return {"status": "ok" if results else "no_data", "error": None, "results": results}
