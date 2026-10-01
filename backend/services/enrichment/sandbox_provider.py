"""Sandbox detonation integration — Phase 5 / Phase 1 dynamic analysis.

Provides a configurable provider pattern for submitting suspicious files
and URLs to cloud sandboxes.  Currently implements:

  * Any.run  (https://any.run)      — file + URL submission via public API v1
  * Hybrid Analysis (https://www.hybrid-analysis.com) — file submission with
    full behavioral report via /report/{id}/summary (process activity,
    network calls, verdict, threat score, extracted IOCs)

The entry point ``submit_for_sandbox()`` selects the active provider from
the ``sandbox_provider`` setting, submits up to one file/URL per analysis
(caller's choice), and polls for results up to a configurable timeout.

``fetch_hybrid_behavioral_report()`` is a second entry point added for Phase
1 dynamic analysis.  It accepts a job_id returned by a prior submission and
polls /report/{id}/summary until the full behavioral report is available,
then parses process activity, network calls, and verdict into the standard
result shape.

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
        # Phase 1 additions — populated by fetch_hybrid_behavioral_report()
        "processes":      list[str],   # spawned process names
        "network_calls":  list[str],   # contacted hosts/IPs
        "iocs":           list[str],   # extracted indicators of compromise
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

_HYBRID_SUBMIT_URL   = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
_HYBRID_REPORT_URL   = "https://www.hybrid-analysis.com/sample/{sha256}"
# Full detonation endpoint for behavioral reports (Phase 1 dynamic analysis)
_HYBRID_SUBMIT_FULL  = "https://www.hybrid-analysis.com/api/v2/submit/file"
_HYBRID_SUMMARY_URL  = "https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary"
_HYBRID_OVERVIEW_URL = "https://www.hybrid-analysis.com/api/v2/overview/{sha256}"

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
        # Phase 1 behavioral fields
        "processes": [], "network_calls": [], "iocs": [],
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
        # Phase 1 behavioral fields (Any.run doesn't populate these yet)
        "processes": [], "network_calls": [], "iocs": [],
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
    """Submit a file to Hybrid Analysis and retrieve the full behavioral report.

    Phase 1 dynamic analysis enhancement: uses the full /submit/file endpoint
    (environment 100 = Windows 10 64-bit) which triggers a complete sandbox
    detonation, then polls /report/{job_id}/summary for process activity,
    network calls, verdict, and extracted IOCs.

    Falls back to the quick-scan endpoint when the full-submit endpoint is
    unavailable so the pipeline degrades gracefully.
    """
    result_base = {
        "provider": "hybrid_analysis", "error": None,
        "report_url": None, "verdict": None, "score": None,
        "tags": [], "raw": None,
        # Phase 1 behavioral fields
        "processes": [], "network_calls": [], "iocs": [],
    }

    if not file_payload:
        return {**result_base, "status": "error",
                "error": "Hybrid Analysis: file payload required (URL submission not supported)"}

    headers = {
        "api-key": api_key,
        "User-Agent": "PhishAnalyzer/1.0",
        "Accept": "application/json",
    }

    job_id: str | None = None
    report_url = _HYBRID_REPORT_URL.format(sha256=sha256) if sha256 else None

    # ── Step 1: submit for full detonation ────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                _HYBRID_SUBMIT_FULL,
                headers=headers,
                files={
                    "file": (filename or "sample.bin", file_payload, "application/octet-stream")
                },
                data={
                    "environment_id": "100",  # Windows 10 64-bit
                    "allow_community_access": "false",
                },
            )

        if resp.status_code == 401:
            return {**result_base, "status": "error",
                    "error": "Hybrid Analysis: invalid API key (HTTP 401)"}
        if resp.status_code == 429:
            return {**result_base, "status": "error",
                    "error": "Hybrid Analysis: rate limit exceeded (HTTP 429)"}

        if resp.status_code in (200, 201):
            submit_data = resp.json()
            # Full submission returns {"job_id": ..., "sha256": ..., ...}
            job_id = submit_data.get("job_id") or submit_data.get("id")
            if not sha256:
                sha256 = submit_data.get("sha256")
                if sha256:
                    report_url = _HYBRID_REPORT_URL.format(sha256=sha256)
            logger.info(
                "Hybrid Analysis full submission OK: job_id=%s sha256=%s",
                job_id, sha256,
            )
        else:
            # Fall back to quick-scan on any other error from the full endpoint
            logger.info(
                "Hybrid Analysis full-submit returned HTTP %s, falling back to quick-scan",
                resp.status_code,
            )
            job_id = None

    except httpx.TimeoutException:
        return {**result_base, "status": "error",
                "error": "Hybrid Analysis: submission timed out"}
    except Exception as exc:
        logger.exception("Hybrid Analysis submission failed")
        return {**result_base, "status": "error",
                "error": f"Hybrid Analysis submission failed: {type(exc).__name__}"}

    # ── Step 1b: quick-scan fallback ──────────────────────────────────────────
    if not job_id:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                qresp = await client.post(
                    _HYBRID_SUBMIT_URL,
                    headers=headers,
                    files={
                        "file": (filename or "sample.bin", file_payload, "application/octet-stream")
                    },
                    data={"scan_id": 100},
                )

            if qresp.status_code == 401:
                return {**result_base, "status": "error",
                        "error": "Hybrid Analysis: invalid API key (HTTP 401)"}
            if qresp.status_code == 429:
                return {**result_base, "status": "error",
                        "error": "Hybrid Analysis: rate limit exceeded (HTTP 429)"}
            if qresp.status_code not in (200, 201):
                return {**result_base, "status": "error",
                        "error": f"Hybrid Analysis: unexpected HTTP {qresp.status_code}"}

            qdata = qresp.json()
            job_id = qdata.get("id") or (qdata.get("results") or [{}])[0].get("job_id")
            verdict_str = (qdata.get("verdict") or "").lower() or None
            threat_score = qdata.get("threat_score")

            if not job_id:
                # Quick-scan only path — no behavioral data available
                return {
                    **result_base,
                    "status": "submitted",
                    "report_url": report_url,
                    "verdict": verdict_str,
                    "score": threat_score,
                    "raw": qdata,
                }

            logger.info("Hybrid Analysis quick-scan submitted: job_id=%s", job_id)

        except httpx.TimeoutException:
            return {**result_base, "status": "error",
                    "error": "Hybrid Analysis: submission timed out"}
        except Exception as exc:
            logger.exception("Hybrid Analysis quick-scan fallback failed")
            return {**result_base, "status": "error",
                    "error": f"Hybrid Analysis submission failed: {type(exc).__name__}"}

    # ── Step 2: poll for behavioral report ────────────────────────────────────
    return await _hybrid_poll_report(
        job_id=job_id,
        api_key=api_key,
        headers=headers,
        result_base=result_base,
        report_url=report_url,
    )


async def _hybrid_poll_report(
    *,
    job_id: str,
    api_key: str,
    headers: dict,
    result_base: dict,
    report_url: str | None,
) -> dict:
    """Poll Hybrid Analysis /report/{job_id}/summary until done or timeout.

    Extracts process activity, network calls, IOCs, verdict, and threat score
    from the summary report and returns them in the standard result shape.
    """
    waited = 0
    while waited < _MAX_WAIT:
        await asyncio.sleep(_POLL_INTERVAL)
        waited += _POLL_INTERVAL

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                poll = await client.get(
                    _HYBRID_SUMMARY_URL.format(job_id=job_id),
                    headers=headers,
                )
        except Exception as exc:
            logger.debug("Hybrid Analysis poll error (job_id=%s): %s", job_id, exc)
            continue

        if poll.status_code == 404:
            # Report not ready yet
            continue

        if poll.status_code != 200:
            logger.debug(
                "Hybrid Analysis poll unexpected HTTP %s for job_id=%s",
                poll.status_code, job_id,
            )
            continue

        try:
            report_data = poll.json()
        except Exception:
            continue

        # The report is ready when it has a "state" of "SUCCESS"
        state = (report_data.get("state") or "").upper()
        if state not in ("SUCCESS", "ERROR"):
            continue

        if state == "ERROR":
            return {
                **result_base,
                "status": "error",
                "report_url": report_url,
                "error": "Hybrid Analysis: detonation returned state=ERROR",
                "raw": report_data,
            }

        return _parse_hybrid_report(report_data, result_base=result_base, report_url=report_url)

    # Timed out
    logger.warning(
        "Hybrid Analysis behavioral report timed out after %ds: job_id=%s",
        _MAX_WAIT, job_id,
    )
    return {
        **result_base,
        "status": "timeout",
        "report_url": report_url,
        "error": f"Hybrid Analysis: report did not complete within {_MAX_WAIT}s",
    }


def _parse_hybrid_report(data: dict, *, result_base: dict, report_url: str | None) -> dict:
    """Extract behavioral signals from a Hybrid Analysis summary report.

    Maps the /report/{id}/summary response onto our standard result dict,
    populating processes, network_calls, iocs, verdict, score, and tags.
    """
    # ── Verdict + threat score ────────────────────────────────────────────────
    verdict_raw = (data.get("verdict") or "").lower()
    # Normalize Hybrid Analysis verdicts to our standard set
    if verdict_raw in ("malicious",):
        verdict_str = "malicious"
    elif verdict_raw in ("suspicious", "whitelisted"):
        verdict_str = "suspicious"
    elif verdict_raw in ("no specific threat", "no threats detected", "clean"):
        verdict_str = "no threats"
    else:
        verdict_str = verdict_raw or None

    threat_score = data.get("threat_score")  # 0-100

    # ── Tags / classifications ────────────────────────────────────────────────
    tags: list[str] = []
    for cls_entry in (data.get("classifications") or []):
        if isinstance(cls_entry, dict):
            tags.append(cls_entry.get("name", "") or "")
        elif isinstance(cls_entry, str):
            tags.append(cls_entry)
    for tag in (data.get("tags") or []):
        if isinstance(tag, str) and tag and tag not in tags:
            tags.append(tag)
    tags = [t for t in tags if t][:30]

    # ── Process activity ──────────────────────────────────────────────────────
    # Hybrid Analysis nests process data under "processes" list
    processes: list[str] = []
    for proc in (data.get("processes") or []):
        if isinstance(proc, dict):
            name = proc.get("name") or proc.get("process_name") or ""
            if name and name not in processes:
                processes.append(str(name)[:200])
        elif isinstance(proc, str) and proc:
            if proc not in processes:
                processes.append(proc[:200])
    processes = processes[:50]

    # ── Network calls ─────────────────────────────────────────────────────────
    # hosts + domains contacted during detonation
    network_calls: list[str] = []
    for host in (data.get("hosts") or []):
        if isinstance(host, str) and host and host not in network_calls:
            network_calls.append(host[:255])
    for domain in (data.get("domains") or []):
        if isinstance(domain, str) and domain and domain not in network_calls:
            network_calls.append(domain[:255])
    # Also check network_list if present
    for net_entry in (data.get("network_list") or []):
        if isinstance(net_entry, dict):
            dest = net_entry.get("destination_ip") or net_entry.get("domain") or ""
            if dest and dest not in network_calls:
                network_calls.append(str(dest)[:255])
    network_calls = network_calls[:50]

    # ── IOCs ──────────────────────────────────────────────────────────────────
    iocs: list[str] = []
    for ioc in (data.get("extracted_files") or []):
        if isinstance(ioc, dict):
            name = ioc.get("name") or ioc.get("filename") or ""
            if name and name not in iocs:
                iocs.append(str(name)[:200])
    for url_ioc in (data.get("malicious_indicators") or []):
        if isinstance(url_ioc, dict):
            val = url_ioc.get("value") or url_ioc.get("indicator") or ""
            if val and val not in iocs:
                iocs.append(str(val)[:200])
    iocs = iocs[:30]

    logger.info(
        "Hybrid Analysis behavioral report parsed: verdict=%s score=%s "
        "processes=%d network_calls=%d iocs=%d",
        verdict_str, threat_score, len(processes), len(network_calls), len(iocs),
    )

    return {
        **result_base,
        "status":        "done",
        "report_url":    report_url,
        "verdict":       verdict_str,
        "score":         threat_score,
        "tags":          tags,
        "raw":           data,
        # Phase 1 behavioral fields
        "processes":     processes,
        "network_calls": network_calls,
        "iocs":          iocs,
    }


# ── Public helper: fetch behavioral report for an existing job ────────────────

async def fetch_hybrid_behavioral_report(
    *,
    job_id: str,
    sha256: str | None,
    api_key: str,
) -> dict:
    """Fetch and parse a full behavioral report for an already-submitted
    Hybrid Analysis job.

    This is the Phase 1 dynamic-analysis entry point when the initial
    submission (via ``submit_for_sandbox()``) returned ``status="submitted"``
    with a ``job_id`` and the caller wants to retrieve the full behavioral
    report as a separate, non-blocking step.

    Parameters
    ----------
    job_id:  Hybrid Analysis job ID returned by the submission endpoint.
    sha256:  SHA-256 hash of the submitted file (for the report URL).
    api_key: Hybrid Analysis API key.
    """
    result_base = {
        "provider": "hybrid_analysis", "error": None,
        "report_url": _HYBRID_REPORT_URL.format(sha256=sha256) if sha256 else None,
        "verdict": None, "score": None,
        "tags": [], "raw": None,
        "processes": [], "network_calls": [], "iocs": [],
    }

    if not api_key:
        return {**result_base, "status": "no_key"}

    headers = {
        "api-key": api_key,
        "User-Agent": "PhishAnalyzer/1.0",
        "Accept": "application/json",
    }

    return await _hybrid_poll_report(
        job_id=job_id,
        api_key=api_key,
        headers=headers,
        result_base=result_base,
        report_url=result_base["report_url"],
    )
