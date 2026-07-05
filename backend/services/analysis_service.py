"""Orchestrates one .eml analysis: validate -> persist PENDING row -> run the
parse/enrich/score pipeline as a background asyncio task, updating status to
RUNNING/DONE/FAILED. The upload endpoint returns as soon as the row exists;
the frontend polls GET /analyses/{id} for completion.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.models.analysis import EmailAnalysis
from backend.models.attachment_indicator import AttachmentIndicator
from backend.models.score_reason import ScoreReason
from backend.models.url_indicator import UrlIndicator
from backend.repositories.analysis_repository import AnalysisRepository
from backend.repositories.settings_repository import SettingsRepository
from backend.services import eml_parser_service as eml
from backend.services import scoring_service
from backend.services import validation_service
from backend.services.enrichment import abuseipdb_provider, virustotal_provider
from shared.paths import analysis_upload_dir

logger = logging.getLogger(__name__)

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
        validation_service.validate_eml_upload(filename, raw_bytes)

        async with self.session_factory() as session:
            analysis = await AnalysisRepository(session).create_pending(
                filename=filename, stored_path=""
            )

        stored_path = analysis_upload_dir(analysis.id) / filename
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
                urls = eml.extract_urls_from_text(body_text)
                message_id = eml.get_message_id(parsed, headers)

                async with self.session_factory() as session:
                    settings = await SettingsRepository(session).get()
                    vt_key = settings.virustotal_key or self._vt_api_key_env
                    abuse_key = settings.abuseipdb_key or self._abuseipdb_key_env
                    scoring_weights = dict(settings.scoring_weights)
                    brand_domains = dict(settings.brand_domains)
                    suspicious_keywords = list(settings.url_suspicious_keywords)
                    suspicious_tlds = list(settings.suspicious_tlds)
                    url_shorteners = list(settings.url_shorteners)
                    urgency_keywords = list(settings.urgency_keywords)

                vt_results = await virustotal_provider.enrich_urls(urls, vt_key)
                abuse_result = await abuseipdb_provider.enrich_ip(
                    header_info["sender_ip"], abuse_key
                )

                url_rows = [
                    {
                        "url": u,
                        "vt_malicious": vt_results.get(u, {}).get("malicious", 0),
                        "vt_harmless": vt_results.get(u, {}).get("harmless", 0),
                        "vt_suspicious": vt_results.get(u, {}).get("suspicious", 0),
                        "is_suspicious_keyword": False,
                        "is_ip_host": False,
                        "is_shortener": False,
                        "is_suspicious_tld": False,
                        "is_punycode": False,
                    }
                    for u in urls
                ]
                attachment_rows = [
                    {
                        "filename": att.get("filename"),
                        "content_type": att.get("content-type") or att.get("content_type"),
                        "sha256": eml.hash_attachment_content(att),
                        "is_executable_like": False,
                        "is_double_extension": False,
                    }
                    for att in attachments_raw
                ]

                score_info = scoring_service.compute_score(
                    from_addr=header_info["from_addr"],
                    from_domain=header_info["from_domain"],
                    auth=header_info["auth"],
                    header_issues=header_info["issues"],
                    urls=url_rows,
                    attachments=attachment_rows,
                    abuse_result=abuse_result,
                    sender_ip=header_info["sender_ip"],
                    body_text=body_text,
                    scoring_weights=scoring_weights,
                    brand_domains=brand_domains,
                    url_suspicious_keywords=suspicious_keywords,
                    suspicious_tlds=suspicious_tlds,
                    url_shorteners=url_shorteners,
                    urgency_keywords=urgency_keywords,
                )

                subject = headers.get("subject")

                async with self.session_factory() as session:
                    repo = AnalysisRepository(session)
                    analysis = await repo.get_by_id(analysis_id)

                    analysis.message_id = message_id
                    analysis.subject = str(subject) if subject else None
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
                    analysis.abuse_score = abuse_result.get("abuse_score")
                    analysis.abuse_total_reports = abuse_result.get("total_reports")
                    analysis.abuse_country = abuse_result.get("country_code")
                    analysis.abuse_isp = abuse_result.get("isp")
                    analysis.global_hashes = global_hashes
                    analysis.body_text = body_text
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
                await self._mark_status(analysis_id, "FAILED", error_message=str(exc))

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
