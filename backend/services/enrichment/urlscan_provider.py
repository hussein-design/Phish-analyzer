"""urlscan.io URL detonation provider — Phase 1 dynamic analysis.

Submits a URL to urlscan.io for detonation, polls until the scan completes
(up to ``_MAX_WAIT`` seconds), and returns a structured result with
screenshot URL, redirect chain, final-page title, and a verdict derived
from urlscan's own verdicts list.

Return value shape (all paths)::

    {
        "status":          "no_key" | "submitted" | "done" | "timeout" | "error",
        "error":           str | None,
        "scan_uuid":       str | None,       # urlscan scan UUID
        "report_url":      str | None,       # https://urlscan.io/result/<uuid>/
        "screenshot_url":  str | None,       # https://urlscan.io/screenshots/<uuid>.png
        "verdict":         str | None,       # "malicious" | "suspicious" | "benign" | None
        "malicious":       bool,             # True when urlscan verdict ≥ malicious
        "redirect_chain":  list[str],        # all URLs observed during detonation
        "final_url":       str | None,       # final landing-page URL
        "page_title":      str | None,       # <title> of the final page
        "tags":            list[str],        # urlscan behavioural tags
        "score":           int | None,       # 0-100 overall threat score (when available)
        "raw":             dict | None,      # raw /result JSON for archival
    }

Interface notes
---------------
* The caller is expected to wrap the call in ``asyncio.wait_for()`` with its
  own timeout guard so a slow urlscan scan never blocks the pipeline.
* Returns ``status="no_key"`` immediately when ``api_key`` is falsy so the
  caller knows enrichment was intentionally skipped, not failed.
* Rate-limit and auth errors return ``status="error"`` with a human-readable
  ``error`` string; the pipeline is not interrupted.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from backend.services.enrichment.cache import enrichment_cache

logger = logging.getLogger(__name__)

# ── API endpoints ─────────────────────────────────────────────────────────────
_SUBMIT_URL   = "https://urlscan.io/api/v1/scan/"
_RESULT_URL   = "https://urlscan.io/api/v1/result/{uuid}/"
_REPORT_BASE  = "https://urlscan.io/result/{uuid}/"
_SCREENSHOT   = "https://urlscan.io/screenshots/{uuid}.png"

# Polling
_POLL_INTERVAL = 10   # seconds between polls
_MAX_WAIT      = 120  # total seconds before returning "timeout"

# Visibility for submitted scans.  "public" is the free-tier default and is
# fine for phishing detection.  A future enhancement could expose this as a
# setting so enterprise users can submit unlisted scans.
_SCAN_VISIBILITY = "public"


# ── Public entry point ────────────────────────────────────────────────────────

async def detonate_url(url: str, api_key: str | None) -> dict:
    """Submit ``url`` to urlscan.io and wait for the result.

    Parameters
    ----------
    url:     The URL to detonate.  Must start with ``http://`` or ``https://``.
    api_key: urlscan.io API key.  If falsy, returns ``status="no_key"``
             immediately without making any network calls.

    Returns
    -------
    Structured result dict — see module docstring for the full shape.
    """
    _empty = {
        "status": "no_key",
        "error": None,
        "scan_uuid": None,
        "report_url": None,
        "screenshot_url": None,
        "verdict": None,
        "malicious": False,
        "redirect_chain": [],
        "final_url": None,
        "page_title": None,
        "tags": [],
        "score": None,
        "raw": None,
    }

    if not api_key:
        return _empty

    if not url or not url.startswith(("http://", "https://")):
        return {**_empty, "status": "error", "error": "Invalid or non-HTTP URL — skipped"}

    # ── Cache check ───────────────────────────────────────────────────────────
    # urlscan results are immutable once the scan is done — safe to cache for 4 h
    cached = await enrichment_cache.get("urlscan", url)
    if cached is not None:
        logger.debug("urlscan.io cache hit: %s", url)
        return cached  # type: ignore[return-value]

    # ── Step 1: submit ────────────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                _SUBMIT_URL,
                headers={
                    "API-Key": api_key,
                    "Content-Type": "application/json",
                },
                json={
                    "url": url,
                    "visibility": _SCAN_VISIBILITY,
                    # Tags help correlate scans in the urlscan UI
                    "tags": ["phish-analyzer"],
                },
            )
    except httpx.TimeoutException:
        return {**_empty, "status": "error", "error": "urlscan.io: submission timed out"}
    except Exception as exc:
        # MED-02 pattern: log full exception internally, surface only type name
        logger.exception("urlscan.io submission failed for %s", url)
        return {**_empty, "status": "error",
                "error": f"urlscan.io submission failed: {type(exc).__name__}"}

    if resp.status_code == 400:
        # urlscan returns 400 with a message field for domain/path issues
        try:
            msg = resp.json().get("message", "bad request")
        except Exception:
            msg = "bad request"
        return {**_empty, "status": "error",
                "error": f"urlscan.io: bad request — {msg}"}

    if resp.status_code == 401:
        return {**_empty, "status": "error",
                "error": "urlscan.io: invalid API key (HTTP 401)"}

    if resp.status_code == 429:
        return {**_empty, "status": "error",
                "error": "urlscan.io: rate limit exceeded (HTTP 429)"}

    if resp.status_code not in (200, 201):
        # MED-02: do NOT embed resp.text — may reflect our auth headers
        return {**_empty, "status": "error",
                "error": f"urlscan.io: unexpected HTTP {resp.status_code}"}

    try:
        submit_data = resp.json()
    except Exception:
        return {**_empty, "status": "error",
                "error": "urlscan.io: submission response was not valid JSON"}

    scan_uuid = submit_data.get("uuid")
    if not scan_uuid:
        return {**_empty, "status": "error",
                "error": "urlscan.io: submission succeeded but no UUID returned",
                "raw": submit_data}

    report_url     = _REPORT_BASE.format(uuid=scan_uuid)
    screenshot_url = _SCREENSHOT.format(uuid=scan_uuid)
    logger.info("urlscan.io scan submitted: uuid=%s", scan_uuid)

    # ── Step 2: poll until done ───────────────────────────────────────────────
    waited = 0
    while waited < _MAX_WAIT:
        await asyncio.sleep(_POLL_INTERVAL)
        waited += _POLL_INTERVAL

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                poll = await client.get(
                    _RESULT_URL.format(uuid=scan_uuid),
                    headers={"API-Key": api_key},
                )
        except Exception as exc:
            logger.debug("urlscan.io poll error (uuid=%s): %s", scan_uuid, exc)
            continue

        if poll.status_code == 404:
            # Scan not finished yet — urlscan returns 404 until the result is ready
            continue

        if poll.status_code != 200:
            logger.debug(
                "urlscan.io poll unexpected HTTP %s for uuid=%s",
                poll.status_code, scan_uuid,
            )
            continue

        try:
            result_data = poll.json()
        except Exception:
            continue

        result = _parse_result(
            result_data,
            scan_uuid=scan_uuid,
            report_url=report_url,
            screenshot_url=screenshot_url,
        )
        # Cache the completed result — immutable, safe to cache for 4 h
        if result.get("status") == "done":
            await enrichment_cache.set("urlscan", url, result)
        return result

    # Timed out — return what we have so far (the report URL is still useful)
    logger.warning("urlscan.io scan timed out after %ds: uuid=%s", _MAX_WAIT, scan_uuid)
    return {
        **_empty,
        "status": "timeout",
        "scan_uuid": scan_uuid,
        "report_url": report_url,
        "screenshot_url": screenshot_url,
        "error": f"urlscan.io: scan did not complete within {_MAX_WAIT}s",
    }


# ── Result parser ─────────────────────────────────────────────────────────────

def _parse_result(data: dict, *, scan_uuid: str, report_url: str, screenshot_url: str) -> dict:
    """Extract the fields we care about from a completed urlscan result JSON."""

    # ── Verdict ───────────────────────────────────────────────────────────────
    # urlscan's verdicts are nested under data.verdicts.overall
    verdicts_block = (data.get("verdicts") or {}).get("overall") or {}
    verdict_str: str | None = None
    is_malicious = bool(verdicts_block.get("malicious", False))
    score_val = verdicts_block.get("score")  # 0-100 when present

    # Map urlscan's categorical verdict to our standard set
    raw_cats = verdicts_block.get("categories") or []
    if is_malicious or "phishing" in raw_cats or "malware" in raw_cats:
        verdict_str = "malicious"
    elif verdicts_block.get("suspicious", False) or score_val and score_val >= 40:
        verdict_str = "suspicious"
    else:
        verdict_str = "benign"

    # Fallback: some older result shapes use data.stats.malicious
    if not verdict_str:
        stats = (data.get("data") or {}).get("stats") or {}
        if stats.get("malicious", 0) > 0:
            verdict_str = "malicious"
            is_malicious = True
        else:
            verdict_str = "benign"

    # ── Redirect chain ────────────────────────────────────────────────────────
    # urlscan records each HTTP request made during detonation under
    # data.requests[].response.redirectResponse or data.lists.urls
    redirect_chain: list[str] = []

    requests_list = (data.get("data") or {}).get("requests") or []
    for req_entry in requests_list:
        # Each entry is {"request": {...}, "response": {...}}
        req = req_entry.get("request") or {}
        req_url = req.get("request", {}).get("url") or ""
        if req_url and req_url not in redirect_chain:
            redirect_chain.append(req_url)

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for u in redirect_chain:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    redirect_chain = deduped[:50]  # cap at 50 entries

    # ── Final URL ─────────────────────────────────────────────────────────────
    # data.page.url is the final landing page URL after all redirects
    page_block = data.get("page") or {}
    final_url = page_block.get("url") or None

    # ── Page title ────────────────────────────────────────────────────────────
    page_title = page_block.get("title") or None
    if page_title:
        page_title = str(page_title)[:200]

    # ── Behavioural tags ──────────────────────────────────────────────────────
    # urlscan.io tags are surfaced under verdicts.overall.tags or
    # data.lists.categories
    tags: list[str] = []
    tags.extend(verdicts_block.get("tags") or [])
    tags.extend(raw_cats)
    # Remove duplicates while preserving order
    seen_tags: set[str] = set()
    unique_tags: list[str] = []
    for t in tags:
        low = str(t).lower()
        if low not in seen_tags:
            seen_tags.add(low)
            unique_tags.append(str(t))
    tags = unique_tags

    logger.info(
        "urlscan.io result parsed: uuid=%s verdict=%s malicious=%s",
        scan_uuid, verdict_str, is_malicious,
    )

    return {
        "status":         "done",
        "error":          None,
        "scan_uuid":      scan_uuid,
        "report_url":     report_url,
        "screenshot_url": screenshot_url,
        "verdict":        verdict_str,
        "malicious":      is_malicious,
        "redirect_chain": redirect_chain,
        "final_url":      final_url,
        "page_title":     page_title,
        "tags":           tags,
        "score":          score_val,
        "raw":            data,
    }
