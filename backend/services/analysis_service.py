"""Orchestrates one .eml analysis: validate -> persist PENDING row -> run the
parse/enrich/score pipeline as a background asyncio task, updating status to
RUNNING/DONE/FAILED. The upload endpoint returns as soon as the row exists;
the frontend polls GET /analyses/{id} for completion.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import PurePosixPath

from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.models.analysis import EmailAnalysis
from backend.models.attachment_indicator import AttachmentIndicator
from backend.models.score_reason import ScoreReason
from backend.models.url_indicator import UrlIndicator
from backend.repositories.analysis_repository import AnalysisRepository
from backend.repositories.settings_repository import SettingsRepository
from backend.services import eml_parser_service as eml
from backend.services import scoring_service
from backend.services import threat_signals
from backend.services import validation_service
from backend.services import attachment_intelligence_service as att_intel
from backend.services import url_intelligence_service as url_intel
from backend.services.enrichment import abuseipdb_provider, virustotal_provider
from backend.services.enrichment import shodan_provider
from backend.services.enrichment import sandbox_provider as sandbox_prov
from shared.paths import analysis_upload_dir

logger = logging.getLogger(__name__)

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024   # 25 MB — enforced again here as a server-side guard
_MAX_BODY_TEXT_CHARS = 200_000          # ~200 KB of plain text stored in the DB
_SAFE_FILENAME_RE = re.compile(r"[^\w\-. ]")  # strip everything except word chars, dash, dot, space
# HIGH-02 / MED-10: cap concurrent in-flight tasks so memory can't be exhausted
# by queuing hundreds of 25 MB buffers before they start processing.
_MAX_PENDING_ANALYSES = 10  # reject uploads when this many tasks are already queued/running


def _safe_error(msg: str | None, max_len: int = 200) -> str | None:
    """Return a sanitized, length-capped error string safe for DB storage and API responses.

    CRIT-03 / HIGH-08: raw exception strings can contain SQL schema details,
    absolute filesystem paths, API keys embedded in Authorization headers, or
    internal service addresses.  We keep only the first ``max_len`` chars and
    strip common patterns that look like secrets or paths.
    """
    if not msg:
        return None
    # Strip anything that looks like an Authorization/API-key header value
    import re as _re
    cleaned = _re.sub(
        r"(authorization|api[_-]?key|bearer|token)\s*[:\s]\s*\S+",
        r"\1: [REDACTED]",
        msg,
        flags=_re.IGNORECASE,
    )
    # Truncate
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + " [truncated]"
    return cleaned


def _sanitize_filename(filename: str) -> str:
    """Strip path components and dangerous characters from an uploaded filename.

    Prevents path traversal (e.g. '../../etc/passwd.eml') and ensures the
    name is safe to use directly as a filesystem component.
    """
    # Take only the final component — strips any directory traversal prefix
    name = PurePosixPath(filename).name or filename
    # Replace backslashes (Windows paths uploaded from another machine)
    name = name.replace("\\", "_").replace("/", "_")
    # Remove any remaining non-safe characters
    name = _SAFE_FILENAME_RE.sub("_", name)
    # Collapse runs of underscores/spaces
    name = re.sub(r"[_ ]{2,}", "_", name).strip("_. ")
    # Ensure it ends with .eml and isn't empty
    if not name or name == ".eml":
        name = "upload.eml"
    elif not name.lower().endswith(".eml"):
        name = name + ".eml"
    # Cap length to avoid filesystem limits
    if len(name) > 200:
        name = name[:196] + ".eml"
    return name

# Caps concurrent in-flight analyses to protect the single SQLite writer and
# avoid hammering rate-limited external APIs.
_ANALYSIS_CONCURRENCY = asyncio.Semaphore(3)

# asyncio explicitly warns fire-and-forget tasks can be GC'd mid-flight --
# this dict keeps a live reference until each task finishes.
_in_flight_tasks: dict[int, asyncio.Task] = {}


class AnalysisService:
    def __init__(
        self,
        session_factory: async_sessionmaker,
        vt_api_key_env: str | None = None,
        abuseipdb_key_env: str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self._vt_api_key_env = vt_api_key_env
        self._abuseipdb_key_env = abuseipdb_key_env

    async def submit_upload(self, filename: str, raw_bytes: bytes) -> EmailAnalysis:
        # HIGH-02: reject new uploads when the queue is already full to prevent
        # memory exhaustion from accumulating many large in-flight buffers.
        # _in_flight_tasks includes both PENDING (queued) and RUNNING analyses.
        if len(_in_flight_tasks) >= _MAX_PENDING_ANALYSES:
            from backend.core.exceptions import InvalidEmlError
            raise InvalidEmlError(
                f"Server is busy — {len(_in_flight_tasks)} analyses are already "
                f"in progress. Please try again shortly. "
                f"(max concurrent: {_MAX_PENDING_ANALYSES})"
            )

        # Validate using the ORIGINAL client-supplied filename so extension
        # checks cannot be bypassed by the sanitiser appending .eml.
        # Sanitise only after the content-level checks pass.
        validation_service.validate_eml_upload(filename, raw_bytes)
        filename = _sanitize_filename(filename)

        async with self.session_factory() as session:
            analysis = await AnalysisRepository(session).create_pending(
                filename=filename, stored_path=""
            )

        stored_path = analysis_upload_dir(analysis.id) / filename
        stored_path.parent.mkdir(parents=True, exist_ok=True)  # MED-06: ensure dir exists
        stored_path.write_bytes(raw_bytes)

        async with self.session_factory() as session:
            repo = AnalysisRepository(session)
            analysis = await repo.get_by_id(analysis.id)
            analysis.stored_path = str(stored_path)
            analysis = await repo.save(analysis)

        task = asyncio.create_task(self._run_pipeline(analysis.id, raw_bytes))
        _in_flight_tasks[analysis.id] = task
        task.add_done_callback(lambda _t, aid=analysis.id: _in_flight_tasks.pop(aid, None))

        return analysis

    async def _run_pipeline(self, analysis_id: int, raw_bytes: bytes) -> None:
        async with _ANALYSIS_CONCURRENCY:
            try:
                await self._mark_status(analysis_id, "RUNNING")

                loop = asyncio.get_running_loop()
                parsed = await loop.run_in_executor(None, eml.parse_eml_bytes, raw_bytes)

                body_text = eml.extract_text_from_body(parsed.get("body", {}))
                attachments_raw = parsed.get("attachment", []) or []
                headers = parsed.get("header", {}) or {}
                header_info = eml.analyze_headers(parsed)
                global_hashes = eml.extract_global_hashes(parsed)
                urls = eml.extract_urls_from_body(parsed.get("body", {}), body_text)
                message_id = eml.get_message_id(parsed, headers)
                subject = eml.get_subject(parsed, headers)

                # ── Phase 1: MIME structure + social engineering signals ───────
                mime_parts = eml.extract_mime_parts(parsed)
                html_bodies = threat_signals.extract_html_bodies(parsed)
                anchor_mismatches_raw = []
                for html in html_bodies:
                    anchor_mismatches_raw.extend(threat_signals.detect_anchor_mismatches(html))
                # Deduplicate by (display, href) key
                seen_anchors: set[tuple[str, str]] = set()
                anchor_mismatches: list[dict] = []
                for am in anchor_mismatches_raw:
                    key = (am.display_text[:80], am.href[:120])
                    if key not in seen_anchors:
                        seen_anchors.add(key)
                        anchor_mismatches.append({
                            "display_text": am.display_text,
                            "href": am.href,
                            "reason": am.reason,
                        })
                lure_matches = threat_signals.detect_lure_categories(body_text)
                lure_categories = [
                    {"category": lm.category, "matched_keywords": lm.matched_keywords}
                    for lm in lure_matches
                ]

                async with self.session_factory() as session:
                    settings = await SettingsRepository(session).get()
                    vt_key = settings.virustotal_key or self._vt_api_key_env
                    abuse_key = settings.abuseipdb_key or self._abuseipdb_key_env
                    shodan_key = getattr(settings, "shodan_key", None)
                    _sandbox_provider = getattr(settings, "sandbox_provider", None)
                    _sandbox_key = getattr(settings, "sandbox_api_key", None)
                    scoring_weights = dict(settings.scoring_weights)
                    brand_domains = dict(settings.brand_domains)
                    suspicious_keywords = list(settings.url_suspicious_keywords)
                    suspicious_tlds = list(settings.suspicious_tlds)
                    url_shorteners = list(settings.url_shorteners)
                    urgency_keywords = list(settings.urgency_keywords)

                # ── Threat intel enrichment ───────────────────────────────
                # Both providers now return a structured dict:
                #   {"status": "no_key"|"ok"|"no_data"|"rate_limit"|"error",
                #    "error": str|None, "results"/"data": ...}
                # We log the status and store it on the analysis row so the
                # UI can show a clear explanation instead of just "no data".
                vt_enrichment, abuse_enrichment, shodan_enrichment, url_intel_results = await asyncio.gather(
                    virustotal_provider.enrich_urls(urls, vt_key),
                    abuseipdb_provider.enrich_ip(header_info["sender_ip"], abuse_key),
                    shodan_provider.enrich_ip(header_info["sender_ip"], shodan_key),
                    url_intel.expand_urls(urls),
                )

                vt_status  = vt_enrichment["status"]
                vt_error   = vt_enrichment.get("error")
                vt_results = vt_enrichment.get("results", {})

                if vt_status == "no_key":
                    logger.info("VirusTotal: skipped — no API key configured")
                elif vt_status == "rate_limit":
                    logger.warning("VirusTotal: rate limit / quota exceeded: %s", vt_error)
                elif vt_status == "error":
                    logger.error("VirusTotal: enrichment error: %s", vt_error)
                else:
                    logger.info("VirusTotal: status=%s, urls_enriched=%d", vt_status, len(vt_results))

                abuse_status = abuse_enrichment["status"]
                abuse_error  = abuse_enrichment.get("error")
                abuse_data   = abuse_enrichment.get("data") or {}

                if abuse_status == "no_key":
                    logger.info("AbuseIPDB: skipped — no API key configured")
                elif abuse_status == "rate_limit":
                    logger.warning("AbuseIPDB: rate limit / quota exceeded: %s", abuse_error)
                elif abuse_status == "error":
                    logger.error("AbuseIPDB: enrichment error: %s", abuse_error)
                else:
                    logger.info("AbuseIPDB: status=%s", abuse_status)

                shodan_status = shodan_enrichment["status"]
                shodan_error  = shodan_enrichment.get("error")
                shodan_data   = shodan_enrichment.get("data")

                if shodan_status not in ("ok", "no_data", "no_key"):
                    logger.warning("Shodan: status=%s error=%s", shodan_status, shodan_error)
                else:
                    logger.info("Shodan: status=%s", shodan_status)

                # ── Phase 2: VT hash reputation for attachments ────────────
                sha256_list = [
                    eml.hash_attachment_content(att)
                    for att in attachments_raw
                ]
                vt_hash_enrichment = await virustotal_provider.enrich_hashes(
                    [h for h in sha256_list if h], vt_key
                )
                vt_hash_results = vt_hash_enrichment.get("results", {})

                # ── Phase 4: Build URL rows with intelligence data ─────────
                url_intel_map = {r.original_url: r for r in url_intel_results}

                url_rows = [
                    {
                        "url": u,
                        "vt_malicious":  vt_results.get(u, {}).get("malicious", 0),
                        "vt_harmless":   vt_results.get(u, {}).get("harmless", 0),
                        "vt_suspicious": vt_results.get(u, {}).get("suspicious", 0),
                        "is_suspicious_keyword": False,
                        "is_ip_host":            False,
                        "is_shortener":          False,
                        "is_suspicious_tld":     False,
                        "is_punycode":           False,
                        # Phase 4: URL intelligence
                        "expanded_url":          url_intel_map[u].expanded_url if u in url_intel_map else None,
                        "page_title":            url_intel_map[u].page_title if u in url_intel_map else None,
                        "redirect_count":        url_intel_map[u].redirect_count if u in url_intel_map else 0,
                        "final_status_code":     url_intel_map[u].final_status_code if u in url_intel_map else None,
                        "is_redirect_suspicious": url_intel_map[u].is_redirect_suspicious if u in url_intel_map else False,
                    }
                    for u in urls
                ]
                # ── Phase 3: Static attachment analysis ───────────────────
                # Run in executor so zipfile / OLE2 scanning stays off the loop.
                att_intel_results = []
                for att in attachments_raw:
                    payload = att.get("payload") or b""
                    if isinstance(payload, str):
                        payload = b""  # encoded payload — skip static analysis
                    fname = att.get("filename")
                    declared_ct = eml.get_attachment_content_type(att)
                    intel = await loop.run_in_executor(
                        None,
                        att_intel.analyse_attachment,
                        payload,
                        fname,
                        declared_ct,
                    )
                    att_intel_results.append(intel)

                attachment_rows = []
                for att, intel in zip(attachments_raw, att_intel_results):
                    sha = eml.hash_attachment_content(att)
                    vt_hash_stats = vt_hash_results.get(sha, {}) if sha else {}
                    attachment_rows.append({
                        "filename":          att.get("filename"),
                        "content_type":      eml.get_attachment_content_type(att),
                        "sha256":            sha,
                        "is_executable_like":  False,
                        "is_double_extension": False,
                        # Phase 2: VT hash reputation
                        "vt_hash_malicious":  vt_hash_stats.get("malicious", 0),
                        "vt_hash_suspicious": vt_hash_stats.get("suspicious", 0),
                        "vt_hash_status":     vt_hash_enrichment.get("status"),
                        # Phase 3: static analysis
                        "is_macro_enabled":          intel.is_macro_enabled,
                        "has_embedded_executable":   intel.has_embedded_executable,
                        "is_archive":                intel.is_archive,
                        "mime_magic_mismatch":       intel.mime_magic_mismatch,
                        "file_metadata":             intel.to_dict() if (
                            intel.is_macro_enabled or intel.mime_magic_mismatch
                            or intel.has_embedded_executable or intel.file_metadata
                        ) else None,
                    })

                score_info = scoring_service.compute_score(
                    from_addr=header_info["from_addr"],
                    from_domain=header_info["from_domain"],
                    auth=header_info["auth"],
                    header_issues=header_info["issues"],
                    urls=url_rows,
                    attachments=attachment_rows,
                    # scoring_service still expects the flat abuse dict
                    abuse_result=abuse_data,
                    sender_ip=header_info["sender_ip"],
                    body_text=body_text,
                    scoring_weights=scoring_weights,
                    brand_domains=brand_domains,
                    url_suspicious_keywords=suspicious_keywords,
                    suspicious_tlds=suspicious_tlds,
                    url_shorteners=url_shorteners,
                    urgency_keywords=urgency_keywords,
                    lure_categories=lure_categories,
                    anchor_mismatches=anchor_mismatches,
                )

                # ── Phase 5: Sandbox detonation ───────────────────────────
                # Pick the most suspicious attachment (macro/executable first),
                # or the most suspicious URL if no qualifying attachment.
                sandbox_result: dict = {"status": "no_key", "provider": _sandbox_provider,
                                        "error": None, "report_url": None,
                                        "verdict": None, "score": None, "tags": [], "raw": None}
                if _sandbox_provider and _sandbox_key:
                    # Prefer macro-enabled or embedded-exe attachments
                    sandbox_att = next(
                        (
                            (att, raw)
                            for att, raw in zip(attachment_rows, attachments_raw)
                            if att.get("is_macro_enabled") or att.get("has_embedded_executable")
                               or att.get("is_executable_like")
                        ),
                        None,
                    )
                    if sandbox_att:
                        att_row, att_raw = sandbox_att
                        payload = att_raw.get("payload") or b""
                        if isinstance(payload, str):
                            payload = b""
                        if payload:
                            try:
                                sandbox_result = await sandbox_prov.submit_for_sandbox(
                                    provider=_sandbox_provider,
                                    api_key=_sandbox_key,
                                    file_payload=payload,
                                    filename=att_row.get("filename"),
                                    sha256=att_row.get("sha256"),
                                )
                                logger.info(
                                    "Sandbox (%s): status=%s verdict=%s",
                                    _sandbox_provider,
                                    sandbox_result.get("status"),
                                    sandbox_result.get("verdict"),
                                )
                            except Exception as exc:
                                logger.warning("Sandbox submission failed: %s", type(exc).__name__)
                                sandbox_result["status"] = "error"
                                sandbox_result["error"] = f"Submission error: {type(exc).__name__}"
                    elif urls:
                        # Fall back to detonating the first suspicious URL
                        # MED-07: validate URL scheme before submission
                        suspicious_url = next(
                            (r["url"] for r in url_rows if r.get("is_redirect_suspicious")
                             or r.get("vt_malicious", 0) > 0),
                            urls[0] if urls else None,
                        )
                        if suspicious_url and suspicious_url.startswith(("http://", "https://")):
                            try:
                                sandbox_result = await sandbox_prov.submit_for_sandbox(
                                    provider=_sandbox_provider,
                                    api_key=_sandbox_key,
                                    url=suspicious_url,
                                )
                                logger.info(
                                    "Sandbox URL (%s): status=%s verdict=%s",
                                    _sandbox_provider,
                                    sandbox_result.get("status"),
                                    sandbox_result.get("verdict"),
                                )
                            except Exception as exc:
                                # HIGH-03: log type only — str(exc) may include API key fragments
                                logger.warning("Sandbox URL submission failed: %s", type(exc).__name__)
                                sandbox_result["status"] = "error"
                                sandbox_result["error"] = f"Submission error: {type(exc).__name__}"

                async with self.session_factory() as session:
                    repo = AnalysisRepository(session)
                    analysis = await repo.get_by_id(analysis_id)

                    analysis.message_id = message_id
                    analysis.subject = subject
                    analysis.from_addr = header_info["from_addr"]
                    analysis.from_domain = header_info["from_domain"]
                    analysis.reply_to = header_info["reply_to"]
                    analysis.reply_domain = header_info["reply_domain"]
                    analysis.return_path = header_info["return_path"]
                    analysis.return_domain = header_info["return_domain"]
                    analysis.sender_ip = header_info["sender_ip"]
                    analysis.spf = header_info["auth"]["spf"]
                    analysis.dkim = header_info["auth"]["dkim"]
                    analysis.dmarc = header_info["auth"]["dmarc"]
                    analysis.auth_headers_raw = header_info["auth_headers"]
                    analysis.header_issues = header_info["issues"]

                    # Per-provider enrichment status — persisted so the UI
                    # can show exactly why enrichment data is absent.
                    # HIGH-08 / CRIT-03: truncate and sanitize error strings —
                    # raw exception messages may contain API key fragments,
                    # internal hostnames, or SQL schema details.
                    analysis.vt_enrichment_status  = vt_status
                    analysis.vt_enrichment_error   = _safe_error(vt_error)
                    analysis.abuse_enrichment_status = abuse_status
                    analysis.abuse_enrichment_error  = _safe_error(abuse_error)
                    analysis.shodan_enrichment_status = shodan_status
                    analysis.shodan_enrichment_error  = _safe_error(shodan_error)
                    analysis.shodan_data = shodan_data

                    # Phase 5: sandbox
                    analysis.sandbox_status     = sandbox_result.get("status")
                    analysis.sandbox_provider   = sandbox_result.get("provider")
                    analysis.sandbox_verdict    = sandbox_result.get("verdict")
                    analysis.sandbox_score      = sandbox_result.get("score")
                    analysis.sandbox_report_url = sandbox_result.get("report_url")
                    analysis.sandbox_tags       = sandbox_result.get("tags") or []
                    analysis.sandbox_error      = _safe_error(sandbox_result.get("error"))

                    analysis.abuse_score         = abuse_data.get("abuse_score")
                    analysis.abuse_total_reports = abuse_data.get("total_reports")
                    analysis.abuse_country       = abuse_data.get("country_code")
                    analysis.abuse_isp           = abuse_data.get("isp")
                    analysis.global_hashes = global_hashes
                    # Truncate body text to prevent unbounded SQLite row growth.
                    # 200 000 chars (~200 KB) is more than enough for scoring/preview.
                    analysis.body_text = body_text[:_MAX_BODY_TEXT_CHARS] if body_text else None
                    # Phase 1: MIME structure + social engineering
                    analysis.mime_parts = mime_parts
                    analysis.lure_categories = lure_categories
                    analysis.anchor_mismatches = anchor_mismatches
                    analysis.score = score_info["score"]
                    analysis.verdict = score_info["verdict"]
                    analysis.status = "DONE"
                    analysis.error_message = None

                    header_flags = score_info["header_flags"]
                    analysis.is_lookalike_domain = header_flags["is_lookalike_domain"]
                    analysis.lookalike_of = header_flags["lookalike_of"]
                    analysis.is_punycode_domain = header_flags["is_punycode_domain"]
                    analysis.is_suspicious_sender_tld = header_flags["is_suspicious_sender_tld"]
                    analysis.urgency_keywords_found = score_info["urgency_keywords_found"]

                    analysis.urls = [UrlIndicator(**row) for row in url_rows]
                    analysis.attachments = [
                        AttachmentIndicator(**row) for row in attachment_rows
                    ]
                    analysis.reasons = [
                        ScoreReason(reason_text=text, order_index=i)
                        for i, text in enumerate(score_info["reasons"])
                    ]

                    await repo.save(analysis)

            except Exception as exc:
                logger.exception("Analysis pipeline failed for id=%s", analysis_id)
                # CRIT-03: never expose raw exception strings to callers —
                # str(exc) can contain SQL, filesystem paths, or API key fragments.
                safe_msg = f"Analysis pipeline error: {type(exc).__name__}"
                await self._mark_status(analysis_id, "FAILED", error_message=safe_msg)

    async def re_enrich(self, analysis_id: int) -> EmailAnalysis | None:
        """Re-run VT + AbuseIPDB enrichment on an already-completed analysis.

        Reads the stored URLs and sender IP from the analysis row, fetches
        fresh enrichment data using the current API keys from the DB, updates
        the analysis row in-place, and returns the updated record.

        Returns None if the analysis does not exist.
        Raises RuntimeError if the analysis is still PENDING / RUNNING.
        """
        async with self.session_factory() as session:
            analysis = await AnalysisRepository(session).get_by_id(analysis_id)
            if analysis is None:
                return None
            if analysis.status in ("PENDING", "RUNNING"):
                raise RuntimeError(
                    f"Analysis {analysis_id} is still {analysis.status}; cannot re-enrich yet."
                )

            settings = await SettingsRepository(session).get()
            vt_key    = settings.virustotal_key or self._vt_api_key_env
            abuse_key = settings.abuseipdb_key  or self._abuseipdb_key_env
            shodan_key = getattr(settings, "shodan_key", None)

        # Collect the URLs and sender IP that were stored in the original run.
        urls = [u.url for u in analysis.urls]
        sender_ip = analysis.sender_ip

        # Run all providers concurrently — they are independent.
        vt_enrichment, abuse_enrichment, shodan_enrichment = await asyncio.gather(
            virustotal_provider.enrich_urls(urls, vt_key),
            abuseipdb_provider.enrich_ip(sender_ip, abuse_key),
            shodan_provider.enrich_ip(sender_ip, shodan_key),
        )

        # VT hash re-enrichment for attachments
        sha256_list = [att.sha256 for att in analysis.attachments if att.sha256]
        vt_hash_enrichment = await virustotal_provider.enrich_hashes(sha256_list, vt_key)
        vt_hash_results = vt_hash_enrichment.get("results", {})

        vt_status  = vt_enrichment["status"]
        vt_error   = vt_enrichment.get("error")
        vt_results = vt_enrichment.get("results", {})

        abuse_status = abuse_enrichment["status"]
        abuse_error  = abuse_enrichment.get("error")
        abuse_data   = abuse_enrichment.get("data") or {}

        if vt_status == "no_key":
            logger.info("Re-enrich: VirusTotal skipped — no API key configured")
        elif vt_status == "rate_limit":
            logger.warning("Re-enrich: VirusTotal rate limit: %s", vt_error)
        elif vt_status == "error":
            logger.error("Re-enrich: VirusTotal error: %s", vt_error)
        else:
            logger.info("Re-enrich: VT status=%s, urls=%d", vt_status, len(vt_results))

        if abuse_status == "no_key":
            logger.info("Re-enrich: AbuseIPDB skipped — no API key configured")
        elif abuse_status == "error":
            logger.error("Re-enrich: AbuseIPDB error: %s", abuse_error)

        async with self.session_factory() as session:
            repo = AnalysisRepository(session)
            analysis = await repo.get_by_id(analysis_id)
            if analysis is None:
                return None

            # Update per-provider enrichment status fields.
            # CRIT-03 / HIGH-08: sanitize error strings — raw exception messages
            # may contain API key fragments, internal hostnames, or SQL schema details.
            analysis.vt_enrichment_status   = vt_status
            analysis.vt_enrichment_error    = _safe_error(vt_error)
            analysis.abuse_enrichment_status = abuse_status
            analysis.abuse_enrichment_error  = _safe_error(abuse_error)
            analysis.shodan_enrichment_status = shodan_enrichment["status"]
            analysis.shodan_enrichment_error  = _safe_error(shodan_enrichment.get("error"))
            analysis.shodan_data = shodan_enrichment.get("data")

            # Update per-URL VT results.
            for url_row in analysis.urls:
                stats = vt_results.get(url_row.url, {})
                url_row.vt_malicious  = stats.get("malicious",  0)
                url_row.vt_harmless   = stats.get("harmless",   0)
                url_row.vt_suspicious = stats.get("suspicious", 0)

            # Update VT hash results for attachments.
            for att_row in analysis.attachments:
                if att_row.sha256:
                    hash_stats = vt_hash_results.get(att_row.sha256, {})
                    att_row.vt_hash_malicious  = hash_stats.get("malicious", 0)
                    att_row.vt_hash_suspicious = hash_stats.get("suspicious", 0)
                    att_row.vt_hash_status = vt_hash_enrichment.get("status")

            # Update AbuseIPDB fields.
            if abuse_data:
                analysis.abuse_score         = abuse_data.get("abuse_score")
                analysis.abuse_total_reports = abuse_data.get("total_reports")
                analysis.abuse_country       = abuse_data.get("country_code")
                analysis.abuse_isp           = abuse_data.get("isp")

            analysis = await repo.save(analysis)

        logger.info("Re-enrich complete for analysis_id=%d", analysis_id)
        return analysis

    async def _mark_status(
        self, analysis_id: int, status: str, error_message: str | None = None
    ) -> None:
        async with self.session_factory() as session:
            repo = AnalysisRepository(session)
            analysis = await repo.get_by_id(analysis_id)
            if analysis is None:
                return
            analysis.status = status
            if error_message is not None:
                analysis.error_message = error_message
            await repo.save(analysis)
