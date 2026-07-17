"""Sandbox detonation integration — Phase 5.

Provides a configurable provider pattern for submitting suspicious files
and URLs to cloud sandboxes.  Currently implements:

  * Any.run  (https://any.run)      — file + URL submission via public API v1
  * Hybrid Analysis (https://www.hybrid-analysis.com) — file submission

The entry point ``submit_for_sandbox()`` selects the active provider from
the ``sandbox_provider`` setting, submits up to one file/URL per analysis
(caller's choice), and polls for results up to a configurable timeout.

When no API key is configured the provider returns ``status="no_key"``
immediately and the pipeline continues without blocking — sandbox analysis
is always optional.

Return value shape (all providers)::

    {
        "status":   "no_key" | "submitted" | "done" | "timeout" | "error",
        "provider": "anyrun" | "hybrid_analysis" | None,
        "error":    str | None,
        "report_url": str | None,   # link analysts can open in a browser
        "verdict":  str | None,     # "malicious" | "suspicious" | "no threats" | None
        "score":    int | None,     # 0-100 where available
        "tags":     list[str],      # behaviour tags from the sandbox
        "raw":      dict | None,    # raw API response for archival
    }
"""

from __future__ import annotations

import asyncio
import logging
from typing import Literal

import httpx

logger = logging.getLogger(__name__)

# ── Provider constants ────────────────────────────────────────────────────────
_ANYRUN_SUBMIT_URL  = "https://api.any.run/v1/analysis"
_ANYRUN_TASK_URL    = "https://api.any.run/v1/analysis/{task_id}"

_HYBRID_SUBMIT_URL  = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
_HYBRID_REPORT_URL  = "https://www.hybrid-analysis.com/sample/{sha256}"

# Polling: check every N seconds for up to _MAX_WAIT seconds
_POLL_INTERVAL = 15   # seconds between status polls
_MAX_WAIT      = 120  # 2 minutes before we return "timeout"

SandboxProviderName = Literal["anyrun", "hybrid_analysis"]


# ── Public entry point ────────────────────────────────────────────────────────

async def submit_for_sandbox(
    *,
    provider: SandboxProviderName | None,
    api_key: str | None,
    file_payload: bytes | None = None,
    filename: str | None = None,
    url: str | None = None,
    sha256: str | None = None,
) -> dict:
    """Submit a file or URL to the configured sandbox provider.

    At least one of ``file_payload`` or ``url`` must be non-None.
    ``sha256`` is used only for building direct report links (Hybrid Analysis).

    Parameters
    ----------
    provider:     "anyrun" | "hybrid_analysis" | None
    api_key:      API key for the chosen provider
    file_payload: Raw bytes of the attachment to detonate
    filename:     Original filename (passed to the sandbox)
    url:          URL to detonate (Any.run supports URL tasks)
    sha256:       SHA-256 of the file (for report link construction)
    """
    _empty = {
        "status": "no_key", "provider": provider, "error": None,
        "report_url": None, "verdict": None, "score": None,
        "tags": [], "raw": None,
    }

    if not provider:
        return {**_empty, "error": "No sandbox provider configured"}

    if not api_key:
        return _empty

    if not file_payload and not url:
        return {**_empty, "status": "error", "error": "No file or URL to submit"}

    if provider == "anyrun":
        return await _anyrun_submit(api_key, file_payload, filename, url)
    elif provider == "hybrid_analysis":
        return await _hybrid_submit(api_key, file_payload, filename, sha256)
    else:
        return {**_empty, "status": "error", "error": f"Unknown sandbox provider: {provider}"}


# ── Any.run provider ──────────────────────────────────────────────────────────

async def _anyrun_submit(
    api_key: str,
    file_payload: bytes | None,
    filename: str | None,
    url: str | None,
) -> dict:
    """Submit a file or URL to Any.run and poll until done or timeout."""
    headers = {"Authorization": f"API-Key {api_key}"}
    result_base = {
        "provider": "anyrun", "error": None,
        "report_url": None, "verdict": None, "score": None,
        "tags": [], "raw": None,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            if file_payload and filename:
                resp = await client.post(
                    _ANYRUN_SUBMIT_URL,
                    headers=headers,
                    files={"file": (filename, file_payload, "application/octet-stream")},
                    data={
                        "env_os": "Windows",
                        "env_bitness": "64",
                        "obj_type": "file",
                    },
                )
            elif url:
                resp = await client.post(
                    _ANYRUN_SUBMIT_URL,
                    headers=headers,
                    json={"obj_type": "url", "obj_url": url},
                )
            else:
                return {**result_base, "status": "error", "error": "Nothing to submit"}

        if resp.status_code == 401:
            return {**result_base, "status": "error", "error": "Any.run: invalid API key (HTTP 401)"}
        if resp.status_code == 429:
            return {**result_base, "status": "error", "error": "Any.run: rate limit exceeded (HTTP 429)"}
        if resp.status_code not in (200, 201):
            # MED-02: do NOT embed resp.text — external API responses may
            # reflect our request headers (including the Authorization key).
            return {**result_base, "status": "error",
                    "error": f"Any.run: unexpected HTTP {resp.status_code}"}

        data = resp.json()
        task_id = (data.get("data") or {}).get("taskid") or data.get("taskid")
        if not task_id:
            return {**result_base, "status": "error",
                    "error": "Any.run: submission succeeded but no task ID returned",
                    "raw": data}

        report_url = f"https://app.any.run/tasks/{task_id}"
        logger.info("Any.run task submitted: %s", task_id)

    except httpx.TimeoutException:
        return {**result_base, "status": "error", "error": "Any.run: submission timed out"}
    except Exception as exc:
        # MED-02: log internally but expose only exception type to callers.
        logger.exception("Any.run submission failed")
        return {**result_base, "status": "error", "error": f"Any.run submission failed: {type(exc).__name__}"}

    # ── Poll for results ──────────────────────────────────────────────────────
    waited = 0
    while waited < _MAX_WAIT:
        await asyncio.sleep(_POLL_INTERVAL)
        waited += _POLL_INTERVAL

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                poll = await client.get(
                    _ANYRUN_TASK_URL.format(task_id=task_id),
                    headers=headers,
                )
            if poll.status_code != 200:
                continue

            poll_data = poll.json().get("data") or {}
            task_data = poll_data.get("analysis") or poll_data
            status_str = (task_data.get("status") or "").lower()

            if status_str not in ("done", "finished", "completed"):
                continue

            # Extract verdict and score
            scores = task_data.get("scores") or {}
            verdict_val = (task_data.get("verdict") or scores.get("verdict") or "").lower()
            score_val = scores.get("specs", {}).get("score") if isinstance(scores.get("specs"), dict) else None
            tags = [t.get("name", "") for t in (task_data.get("tags") or []) if isinstance(t, dict)]

            return {
                **result_base,
                "status": "done",
                "report_url": report_url,
                "verdict": verdict_val or None,
                "score": score_val,
                "tags": tags,
                "raw": task_data,
            }

        except Exception as exc:
            logger.debug("Any.run poll error: %s", exc)
            continue

    return {
        **result_base,
        "status": "timeout",
        "report_url": report_url,
        "error": f"Any.run: analysis did not complete within {_MAX_WAIT}s",
    }


# ── Hybrid Analysis provider ──────────────────────────────────────────────────

async def _hybrid_submit(
    api_key: str,
    file_payload: bytes | None,
    filename: str | None,
    sha256: str | None,
) -> dict:
    """Submit a file to Hybrid Analysis quick-scan endpoint."""
    result_base = {
        "provider": "hybrid_analysis", "error": None,
        "report_url": None, "verdict": None, "score": None,
        "tags": [], "raw": None,
    }

    if not file_payload:
        return {**result_base, "status": "error",
                "error": "Hybrid Analysis: file payload required (URL submission not supported)"}

    headers = {
        "api-key": api_key,
        "User-Agent": "PhishAnalyzer/1.0",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                _HYBRID_SUBMIT_URL,
                headers=headers,
                files={"file": (filename or "sample.bin", file_payload, "application/octet-stream")},
                data={"scan_id": 100},  # 100 = all environments
            )

        if resp.status_code == 401:
            return {**result_base, "status": "error",
                    "error": "Hybrid Analysis: invalid API key (HTTP 401)"}
        if resp.status_code == 429:
            return {**result_base, "status": "error",
                    "error": "Hybrid Analysis: rate limit exceeded (HTTP 429)"}
        if resp.status_code not in (200, 201):
            # MED-02: do NOT embed resp.text — external API responses may
            # reflect our request headers (including the api-key header).
            return {**result_base, "status": "error",
                    "error": f"Hybrid Analysis: unexpected HTTP {resp.status_code}"}

        data = resp.json()
        scan_id = data.get("id") or (data.get("results") or [{}])[0].get("job_id")
        report_url = _HYBRID_REPORT_URL.format(sha256=sha256) if sha256 else None
        verdict_str = (data.get("verdict") or "").lower() or None
        threat_score = data.get("threat_score")

        logger.info("Hybrid Analysis submission OK: scan_id=%s", scan_id)

        return {
            **result_base,
            "status": "submitted",   # Hybrid Analysis results are async; link is enough
            "report_url": report_url,
            "verdict": verdict_str,
            "score": threat_score,
            "tags": [],
            "raw": data,
        }

    except httpx.TimeoutException:
        return {**result_base, "status": "error",
                "error": "Hybrid Analysis: submission timed out"}
    except Exception as exc:
        # MED-02: log internally but expose only exception type to callers.
        logger.exception("Hybrid Analysis submission failed")
        return {**result_base, "status": "error",
                "error": f"Hybrid Analysis submission failed: {type(exc).__name__}"}
