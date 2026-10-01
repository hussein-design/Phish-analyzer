"""Phase 1 dynamic analysis tests.

Covers:
  - urlscan.io provider (no_key, timeout, HTTP errors, successful parse)
  - Hybrid Analysis behavioral report parsing (polling, verdict mapping, process/network extraction)
  - scoring_service.compute_score() dynamic signal handling (urlscan + attachment detonation,
    static/dynamic split, combined verdict, no interference when providers return no_key)

All tests are self-contained.  No real network calls are made; httpx is mocked
using unittest.mock.  Run with:

    pip install pytest pytest-asyncio
    pytest tests/test_phase1_dynamic_analysis.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _base_weights() -> dict:
    """Minimal scoring weights dict for tests — only includes the fields
    compute_score() actually uses."""
    return {
        "brand_mismatch": 2, "spf_fail": 2, "dkim_fail": 2,
        "dmarc_fail": 2, "header_issue": 1, "url_bad_keyword": 2,
        "url_ip_host": 3, "attachment_executable": 3,
        "vt_malicious_threshold": 3, "vt_malicious_points": 4,
        "abuseipdb_high_score": 50, "abuseipdb_points": 3,
        "brand_domain_lookalike": 3, "brand_domain_lookalike_threshold": 82,
        "suspicious_tld": 2, "punycode_domain": 3, "url_shortener": 1,
        "attachment_double_extension": 4, "body_urgency_keyword": 1,
        "lure_category": 2, "anchor_mismatch": 3,
        "redirect_suspicious": 3, "macro_enabled": 4,
        "embedded_executable": 5, "mime_magic_mismatch": 3,
        "vt_hash_malicious_points": 5,
        # Phase 1 dynamic
        "urlscan_malicious": 4,
        "urlscan_suspicious": 2,
        "dynamic_attachment_malicious": 5,
        "dynamic_attachment_suspicious": 3,
    }


def _call_compute(*, url_detonation_result=None, attachment_detonation_result=None,
                  urls=None, attachments=None) -> dict:
    from backend.services.scoring_service import compute_score
    return compute_score(
        from_addr="sender@example.com",
        from_domain="example.com",
        auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        header_issues=[],
        urls=urls or [],
        attachments=attachments or [],
        abuse_result={},
        sender_ip=None,
        body_text="",
        scoring_weights=_base_weights(),
        brand_domains={},
        url_suspicious_keywords=[],
        suspicious_tlds=[],
        url_shorteners=[],
        urgency_keywords=[],
        url_detonation_result=url_detonation_result,
        attachment_detonation_result=attachment_detonation_result,
    )


def _mock_httpx_response(status_code: int, json_data: dict) -> MagicMock:
    """Build a fake httpx response that supports .status_code and .json()."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


# ──────────────────────────────────────────────────────────────────────────────
# urlscan.io provider tests
# ──────────────────────────────────────────────────────────────────────────────

class TestUrlscanProvider:
    """Tests for backend.services.enrichment.urlscan_provider.detonate_url"""

    @pytest.mark.asyncio
    async def test_no_key_returns_immediately(self):
        """detonate_url must return status='no_key' with no HTTP calls when key is falsy."""
        from backend.services.enrichment.urlscan_provider import detonate_url

        with patch("httpx.AsyncClient") as mock_client_cls:
            result = await detonate_url("https://evil.example.com", None)

        assert result["status"] == "no_key"
        mock_client_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_http_url_returns_error(self):
        """mailto: and ftp: URLs must be rejected with status='error' without hitting the API."""
        from backend.services.enrichment.urlscan_provider import detonate_url

        with patch("httpx.AsyncClient") as mock_client_cls:
            result = await detonate_url("ftp://files.example.com/payload.exe", "key123")

        assert result["status"] == "error"
        assert "Non-HTTP" in (result["error"] or "") or "Invalid" in (result["error"] or "")
        mock_client_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_401_returns_error(self):
        """HTTP 401 from submission endpoint must map to status='error' with a clear message."""
        from backend.services.enrichment.urlscan_provider import detonate_url

        mock_resp = _mock_httpx_response(401, {})
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detonate_url("https://phish.example.com", "bad-key")

        assert result["status"] == "error"
        assert "401" in (result["error"] or "")

    @pytest.mark.asyncio
    async def test_http_429_returns_error(self):
        """HTTP 429 rate-limit from submission must map to status='error'."""
        from backend.services.enrichment.urlscan_provider import detonate_url

        mock_resp = _mock_httpx_response(429, {})
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detonate_url("https://phish.example.com", "key123")

        assert result["status"] == "error"
        assert "429" in (result["error"] or "")

    @pytest.mark.asyncio
    async def test_submission_without_uuid_returns_error(self):
        """A 200 response with no UUID field must return status='error'."""
        from backend.services.enrichment.urlscan_provider import detonate_url

        submit_resp = _mock_httpx_response(200, {"message": "queued", "visibility": "public"})
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=submit_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await detonate_url("https://phish.example.com", "key123")

        assert result["status"] == "error"
        assert result["scan_uuid"] is None

    @pytest.mark.asyncio
    async def test_timeout_returns_timeout_status(self):
        """When the poll never returns a non-404, status must be 'timeout' after _MAX_WAIT."""
        from backend.services.enrichment import urlscan_provider

        submit_resp = _mock_httpx_response(200, {"uuid": "abc-123"})
        poll_resp = _mock_httpx_response(404, {})  # always 404 (not ready)

        submit_client = AsyncMock()
        submit_client.__aenter__ = AsyncMock(return_value=submit_client)
        submit_client.__aexit__ = AsyncMock(return_value=False)
        submit_client.post = AsyncMock(return_value=submit_resp)

        poll_client = AsyncMock()
        poll_client.__aenter__ = AsyncMock(return_value=poll_client)
        poll_client.__aexit__ = AsyncMock(return_value=False)
        poll_client.get = AsyncMock(return_value=poll_resp)

        call_count = 0

        def client_factory(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return submit_client if call_count == 1 else poll_client

        # Patch asyncio.sleep to advance time instantly and cap _MAX_WAIT at 1 iteration
        original_max_wait = urlscan_provider._MAX_WAIT
        original_interval = urlscan_provider._POLL_INTERVAL
        urlscan_provider._MAX_WAIT = 5
        urlscan_provider._POLL_INTERVAL = 10  # interval > max_wait → loop never runs

        try:
            with patch("httpx.AsyncClient", side_effect=client_factory):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await urlscan_provider.detonate_url(
                        "https://phish.example.com", "key123"
                    )
        finally:
            urlscan_provider._MAX_WAIT = original_max_wait
            urlscan_provider._POLL_INTERVAL = original_interval

        assert result["status"] == "timeout"
        assert result["scan_uuid"] == "abc-123"
        assert result["report_url"] is not None

    @pytest.mark.asyncio
    async def test_successful_scan_parses_verdict(self):
        """A completed scan result must be parsed into verdict, screenshot_url, and tags."""
        from backend.services.enrichment import urlscan_provider

        submit_resp = _mock_httpx_response(200, {"uuid": "scan-uuid-999"})

        result_json = {
            "verdicts": {
                "overall": {
                    "malicious": True,
                    "suspicious": False,
                    "score": 85,
                    "categories": ["phishing"],
                    "tags": ["credential-stealing"],
                }
            },
            "page": {
                "url": "https://fake-login.evil.com/microsoft/login",
                "title": "Sign in to your Microsoft account",
            },
            "data": {
                "requests": [
                    {"request": {"request": {"url": "https://phish.example.com"}}},
                    {"request": {"request": {"url": "https://fake-login.evil.com/microsoft/login"}}},
                ]
            },
        }
        poll_resp = _mock_httpx_response(200, result_json)

        call_count = 0

        def client_factory(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            c = AsyncMock()
            c.__aenter__ = AsyncMock(return_value=c)
            c.__aexit__ = AsyncMock(return_value=False)
            if call_count == 1:
                c.post = AsyncMock(return_value=submit_resp)
            else:
                c.get = AsyncMock(return_value=poll_resp)
            return c

        with patch("httpx.AsyncClient", side_effect=client_factory):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await urlscan_provider.detonate_url(
                    "https://phish.example.com", "key123"
                )

        assert result["status"] == "done"
        assert result["verdict"] == "malicious"
        assert result["malicious"] is True
        assert result["score"] == 85
        assert result["screenshot_url"] == "https://urlscan.io/screenshots/scan-uuid-999.png"
        assert result["report_url"] == "https://urlscan.io/result/scan-uuid-999/"
        assert result["page_title"] == "Sign in to your Microsoft account"
        assert result["final_url"] == "https://fake-login.evil.com/microsoft/login"
        assert "credential-stealing" in result["tags"] or "phishing" in result["tags"]
        assert len(result["redirect_chain"]) >= 1

    @pytest.mark.asyncio
    async def test_benign_verdict_parsed_correctly(self):
        """A scan with malicious=False and low score must parse as benign."""
        from backend.services.enrichment import urlscan_provider

        submit_resp = _mock_httpx_response(200, {"uuid": "scan-benign-1"})
        result_json = {
            "verdicts": {
                "overall": {
                    "malicious": False,
                    "suspicious": False,
                    "score": 0,
                    "categories": [],
                    "tags": [],
                }
            },
            "page": {"url": "https://google.com", "title": "Google"},
            "data": {"requests": []},
        }
        poll_resp = _mock_httpx_response(200, result_json)

        call_count = 0

        def client_factory(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            c = AsyncMock()
            c.__aenter__ = AsyncMock(return_value=c)
            c.__aexit__ = AsyncMock(return_value=False)
            if call_count == 1:
                c.post = AsyncMock(return_value=submit_resp)
            else:
                c.get = AsyncMock(return_value=poll_resp)
            return c

        with patch("httpx.AsyncClient", side_effect=client_factory):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await urlscan_provider.detonate_url(
                    "https://google.com", "key123"
                )

        assert result["status"] == "done"
        assert result["verdict"] == "benign"
        assert result["malicious"] is False


# ──────────────────────────────────────────────────────────────────────────────
# Hybrid Analysis behavioral report tests
# ──────────────────────────────────────────────────────────────────────────────

class TestHybridAnalysisBehavioralReport:
    """Tests for _parse_hybrid_report and fetch_hybrid_behavioral_report in sandbox_provider."""

    def test_parse_hybrid_report_malicious_verdict(self):
        """_parse_hybrid_report must extract malicious verdict, threat_score, and behavioral data."""
        from backend.services.enrichment.sandbox_provider import _parse_hybrid_report

        result_base = {
            "provider": "hybrid_analysis", "error": None,
            "report_url": "https://www.hybrid-analysis.com/sample/abc123",
            "verdict": None, "score": None, "tags": [], "raw": None,
            "processes": [], "network_calls": [], "iocs": [],
        }

        report_data = {
            "state": "SUCCESS",
            "verdict": "malicious",
            "threat_score": 92,
            "classifications": [{"name": "Ransomware"}, {"name": "Trojan"}],
            "tags": ["dropper"],
            "processes": [
                {"name": "cmd.exe"},
                {"name": "powershell.exe"},
                {"name": "rundll32.exe"},
            ],
            "hosts": ["192.168.1.100", "evil-c2.example.com"],
            "domains": ["evil-c2.example.com"],
            "extracted_files": [
                {"name": "payload.exe"},
                {"name": "config.dat"},
            ],
        }

        result = _parse_hybrid_report(
            report_data,
            result_base=result_base,
            report_url=result_base["report_url"],
        )

        assert result["status"] == "done"
        assert result["verdict"] == "malicious"
        assert result["score"] == 92
        assert "Ransomware" in result["tags"] or "dropper" in result["tags"]
        assert "cmd.exe" in result["processes"]
        assert "powershell.exe" in result["processes"]
        assert "evil-c2.example.com" in result["network_calls"]
        assert "payload.exe" in result["iocs"]

    def test_parse_hybrid_report_no_threats_verdict(self):
        """'no specific threat' from Hybrid Analysis must map to 'no threats'."""
        from backend.services.enrichment.sandbox_provider import _parse_hybrid_report

        result_base = {
            "provider": "hybrid_analysis", "error": None, "report_url": None,
            "verdict": None, "score": None, "tags": [], "raw": None,
            "processes": [], "network_calls": [], "iocs": [],
        }

        report_data = {
            "state": "SUCCESS",
            "verdict": "no specific threat",
            "threat_score": 0,
            "classifications": [],
            "tags": [],
            "processes": [],
            "hosts": [],
        }

        result = _parse_hybrid_report(report_data, result_base=result_base, report_url=None)
        assert result["status"] == "done"
        assert result["verdict"] == "no threats"
        assert result["score"] == 0

    def test_parse_hybrid_report_suspicious_verdict(self):
        """'suspicious' verdict from Hybrid Analysis must be preserved."""
        from backend.services.enrichment.sandbox_provider import _parse_hybrid_report

        result_base = {
            "provider": "hybrid_analysis", "error": None, "report_url": None,
            "verdict": None, "score": None, "tags": [], "raw": None,
            "processes": [], "network_calls": [], "iocs": [],
        }

        report_data = {
            "state": "SUCCESS",
            "verdict": "suspicious",
            "threat_score": 45,
            "processes": [{"name": "wscript.exe"}],
            "hosts": ["10.10.10.10"],
        }

        result = _parse_hybrid_report(report_data, result_base=result_base, report_url=None)
        assert result["verdict"] == "suspicious"
        assert result["score"] == 45
        assert "wscript.exe" in result["processes"]

    def test_parse_hybrid_report_deduplicates_network_calls(self):
        """The same domain appearing in both hosts and domains must be de-duplicated."""
        from backend.services.enrichment.sandbox_provider import _parse_hybrid_report

        result_base = {
            "provider": "hybrid_analysis", "error": None, "report_url": None,
            "verdict": None, "score": None, "tags": [], "raw": None,
            "processes": [], "network_calls": [], "iocs": [],
        }

        report_data = {
            "state": "SUCCESS",
            "verdict": "malicious",
            "threat_score": 80,
            "hosts": ["evil.com", "other.com"],
            "domains": ["evil.com"],  # duplicate of hosts entry
        }

        result = _parse_hybrid_report(report_data, result_base=result_base, report_url=None)
        assert result["network_calls"].count("evil.com") == 1, (
            "Duplicate network_calls entry not deduplicated"
        )

    @pytest.mark.asyncio
    async def test_fetch_hybrid_behavioral_report_no_key(self):
        """fetch_hybrid_behavioral_report must return status='no_key' when api_key is falsy."""
        from backend.services.enrichment.sandbox_provider import fetch_hybrid_behavioral_report

        with patch("httpx.AsyncClient") as mock_cls:
            result = await fetch_hybrid_behavioral_report(
                job_id="job-123",
                sha256="abc" * 21 + "ab",
                api_key="",
            )

        assert result["status"] == "no_key"
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_hybrid_poll_times_out_gracefully(self):
        """When the /report endpoint always returns 404, the poll must timeout cleanly."""
        from backend.services.enrichment import sandbox_provider

        poll_resp = _mock_httpx_response(404, {})
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=poll_resp)

        original_max_wait = sandbox_provider._MAX_WAIT
        original_interval = sandbox_provider._POLL_INTERVAL
        sandbox_provider._MAX_WAIT = 5
        sandbox_provider._POLL_INTERVAL = 10  # interval > max_wait → loop body never runs

        try:
            with patch("httpx.AsyncClient", return_value=mock_client):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await sandbox_provider.fetch_hybrid_behavioral_report(
                        job_id="job-timeout",
                        sha256=None,
                        api_key="key123",
                    )
        finally:
            sandbox_provider._MAX_WAIT = original_max_wait
            sandbox_provider._POLL_INTERVAL = original_interval

        assert result["status"] == "timeout"
        assert "complete" in (result["error"] or "").lower() or "timeout" in (result["error"] or "").lower()

    @pytest.mark.asyncio
    async def test_hybrid_poll_returns_done_on_success(self):
        """_hybrid_poll_report must parse the summary report on HTTP 200 with state=SUCCESS."""
        from backend.services.enrichment import sandbox_provider

        report_data = {
            "state": "SUCCESS",
            "verdict": "malicious",
            "threat_score": 75,
            "classifications": [],
            "tags": ["downloader"],
            "processes": [{"name": "mshta.exe"}, {"name": "cmd.exe"}],
            "hosts": ["c2.attacker.example"],
            "domains": [],
            "extracted_files": [],
        }

        poll_resp = _mock_httpx_response(200, report_data)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=poll_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await sandbox_provider.fetch_hybrid_behavioral_report(
                    job_id="job-done-1",
                    sha256="d" * 64,
                    api_key="key123",
                )

        assert result["status"] == "done"
        assert result["verdict"] == "malicious"
        assert result["score"] == 75
        assert "mshta.exe" in result["processes"]
        assert "c2.attacker.example" in result["network_calls"]
        assert "downloader" in result["tags"]

    def test_behavioral_fields_in_result_base(self):
        """submit_for_sandbox no_key result must include the behavioral fields with empty defaults."""
        from backend.services.enrichment.sandbox_provider import submit_for_sandbox
        import asyncio

        result = asyncio.run(submit_for_sandbox(provider=None, api_key=None))
        assert "processes" in result
        assert "network_calls" in result
        assert "iocs" in result
        assert result["processes"] == []
        assert result["network_calls"] == []
        assert result["iocs"] == []


# ──────────────────────────────────────────────────────────────────────────────
# scoring_service dynamic signal tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScoringServiceDynamicSignals:
    """Tests for the Phase 1 dynamic analysis scoring additions in scoring_service.compute_score()."""

    # ── No dynamic data ───────────────────────────────────────────────────────

    def test_no_dynamic_data_scores_same_as_before(self):
        """Passing None for both dynamic params must produce the same score as before the feature."""
        result = _call_compute()
        # No static signals either — score must be 0
        assert result["score"] == 0
        assert result["static_score"] == 0
        assert result["dynamic_score"] == 0
        assert result["verdict"] == "benign"

    def test_dynamic_score_zero_when_providers_skipped(self):
        """status='no_key' results must NOT contribute to the dynamic score."""
        no_key = {"status": "no_key", "verdict": "malicious", "malicious": True}
        result = _call_compute(url_detonation_result=no_key)
        assert result["dynamic_score"] == 0
        # Status != 'done' → no contribution
        assert result["score"] == 0

    def test_dynamic_score_zero_on_timeout(self):
        """status='timeout' results must NOT contribute to the dynamic score."""
        timeout_result = {"status": "timeout", "verdict": "malicious", "malicious": True}
        result = _call_compute(url_detonation_result=timeout_result)
        assert result["dynamic_score"] == 0

    # ── urlscan scoring ───────────────────────────────────────────────────────

    def test_urlscan_malicious_adds_dynamic_score(self):
        """urlscan verdict='malicious' must add pts_urlscan_malicious (4) to dynamic_score."""
        urlscan = {
            "status": "done",
            "verdict": "malicious",
            "malicious": True,
            "score": 80,
            "final_url": "https://fake-bank.example.com",
        }
        result = _call_compute(url_detonation_result=urlscan)
        assert result["dynamic_score"] == 4
        assert result["static_score"] == 0
        assert result["score"] == 4  # combined
        # Reason must mention urlscan
        reasons_str = " ".join(result["reasons"])
        assert "urlscan" in reasons_str.lower()

    def test_urlscan_suspicious_adds_lower_dynamic_score(self):
        """urlscan verdict='suspicious' must add pts_urlscan_suspicious (2), not 4."""
        urlscan = {
            "status": "done",
            "verdict": "suspicious",
            "malicious": False,
            "score": 45,
            "final_url": "https://odd.example.com",
        }
        result = _call_compute(url_detonation_result=urlscan)
        assert result["dynamic_score"] == 2
        assert result["static_score"] == 0

    def test_urlscan_benign_adds_no_dynamic_score(self):
        """urlscan verdict='benign' must add 0 to dynamic_score."""
        urlscan = {
            "status": "done",
            "verdict": "benign",
            "malicious": False,
            "score": 5,
            "final_url": "https://google.com",
        }
        result = _call_compute(url_detonation_result=urlscan)
        assert result["dynamic_score"] == 0

    def test_urlscan_malicious_flag_overrides_benign_verdict(self):
        """If malicious=True but verdict is not 'malicious', the malicious flag wins."""
        urlscan = {
            "status": "done",
            "verdict": "benign",   # inconsistent, but malicious flag is True
            "malicious": True,
            "score": 60,
            "final_url": "https://phish.example.com",
        }
        result = _call_compute(url_detonation_result=urlscan)
        # malicious=True must trigger the malicious branch
        assert result["dynamic_score"] == 4

    # ── attachment detonation scoring ─────────────────────────────────────────

    def test_attachment_malicious_adds_dynamic_score(self):
        """Attachment detonation verdict='malicious' must add pts_dyn_att_malicious (5)."""
        att_result = {
            "status": "done",
            "verdict": "malicious",
            "score": 88,
            "processes": ["cmd.exe", "powershell.exe"],
            "network_calls": ["evil-c2.example.com"],
            "tags": ["ransomware"],
        }
        result = _call_compute(attachment_detonation_result=att_result)
        assert result["dynamic_score"] == 5
        assert result["static_score"] == 0
        reasons_str = " ".join(result["reasons"])
        assert "sandbox" in reasons_str.lower() or "detonation" in reasons_str.lower()

    def test_attachment_suspicious_adds_lower_score(self):
        """Attachment detonation verdict='suspicious' must add pts_dyn_att_suspicious (3)."""
        att_result = {
            "status": "done",
            "verdict": "suspicious",
            "score": 50,
            "processes": ["wscript.exe"],
            "network_calls": [],
            "tags": [],
        }
        result = _call_compute(attachment_detonation_result=att_result)
        assert result["dynamic_score"] == 3

    def test_attachment_no_threats_adds_no_dynamic_score(self):
        """'no threats' verdict must add 0 to dynamic_score."""
        att_result = {
            "status": "done",
            "verdict": "no threats",
            "score": 0,
            "processes": [],
            "network_calls": [],
            "tags": [],
        }
        result = _call_compute(attachment_detonation_result=att_result)
        assert result["dynamic_score"] == 0

    # ── combined static + dynamic ─────────────────────────────────────────────

    def test_static_and_dynamic_scores_sum_correctly(self):
        """Combined score must equal static_score + dynamic_score."""
        # Trigger a static signal: SPF fail (+2)
        from backend.services.scoring_service import compute_score

        urlscan = {
            "status": "done",
            "verdict": "malicious",
            "malicious": True,
            "score": 70,
            "final_url": "https://phish.example.com",
        }

        result = compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "fail", "dkim": "pass", "dmarc": "pass"},  # +2 SPF
            header_issues=[],
            urls=[],
            attachments=[],
            abuse_result={},
            sender_ip=None,
            body_text="",
            scoring_weights=_base_weights(),
            brand_domains={},
            url_suspicious_keywords=[],
            suspicious_tlds=[],
            url_shorteners=[],
            urgency_keywords=[],
            url_detonation_result=urlscan,
        )

        assert result["static_score"] == 2   # SPF fail
        assert result["dynamic_score"] == 4  # urlscan malicious
        assert result["score"] == 6          # 2 + 4
        assert result["verdict"] == "suspicious"  # 6 >= 5

    def test_both_dynamic_providers_fire(self):
        """When both urlscan (malicious=4) and attachment (malicious=5) fire, total dynamic=9."""
        urlscan = {
            "status": "done",
            "verdict": "malicious",
            "malicious": True,
            "score": 85,
            "final_url": "https://phish.example.com",
        }
        att_result = {
            "status": "done",
            "verdict": "malicious",
            "score": 90,
            "processes": ["malware.exe"],
            "network_calls": ["c2.attacker.example"],
            "tags": ["trojan"],
        }
        result = _call_compute(
            url_detonation_result=urlscan,
            attachment_detonation_result=att_result,
        )
        assert result["dynamic_score"] == 9   # 4 + 5
        assert result["score"] == 9
        assert result["verdict"] == "phishing"  # 9 >= 9

    def test_dynamic_reasons_separate_from_static_reasons(self):
        """dynamic_reasons must only contain dynamic signals; static_reasons only static."""
        urlscan = {
            "status": "done",
            "verdict": "malicious",
            "malicious": True,
            "score": 75,
            "final_url": "https://phish.example.com",
        }

        from backend.services.scoring_service import compute_score

        result = compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "fail", "dkim": "pass", "dmarc": "pass"},
            header_issues=[],
            urls=[],
            attachments=[],
            abuse_result={},
            sender_ip=None,
            body_text="",
            scoring_weights=_base_weights(),
            brand_domains={},
            url_suspicious_keywords=[],
            suspicious_tlds=[],
            url_shorteners=[],
            urgency_keywords=[],
            url_detonation_result=urlscan,
        )

        # static_reasons must contain the SPF fail reason
        assert any("SPF" in r for r in result["static_reasons"]), (
            "SPF fail not in static_reasons"
        )
        # dynamic_reasons must contain the urlscan reason
        assert any("urlscan" in r.lower() for r in result["dynamic_reasons"]), (
            "urlscan malicious not in dynamic_reasons"
        )
        # Cross-contamination check: urlscan must NOT appear in static_reasons
        assert not any("urlscan" in r.lower() for r in result["static_reasons"]), (
            "urlscan reason leaked into static_reasons"
        )
        # SPF must NOT appear in dynamic_reasons
        assert not any("SPF" in r for r in result["dynamic_reasons"]), (
            "SPF reason leaked into dynamic_reasons"
        )

    # ── return dict completeness ──────────────────────────────────────────────

    def test_return_dict_has_all_new_keys(self):
        """compute_score return dict must contain all four new Phase 1 dynamic keys."""
        result = _call_compute()
        assert "static_score" in result
        assert "dynamic_score" in result
        assert "static_reasons" in result
        assert "dynamic_reasons" in result

    def test_legacy_keys_still_present(self):
        """Existing callers must not break — score, verdict, reasons, header_flags must all exist."""
        result = _call_compute()
        assert "score" in result
        assert "verdict" in result
        assert "reasons" in result
        assert "header_flags" in result
        assert "urgency_keywords_found" in result


# ──────────────────────────────────────────────────────────────────────────────
# Integration: schema fields presence
# ──────────────────────────────────────────────────────────────────────────────

class TestSchemaFields:
    """Verify that all new Phase 1 dynamic analysis fields are present in the Pydantic schemas."""

    def test_email_detail_has_urlscan_fields(self):
        from shared.schemas import EmailDetail
        fields = EmailDetail.model_fields
        for name in (
            "urlscan_status",
            "urlscan_error",
            "urlscan_screenshot_url",
            "urlscan_verdict",
            "urlscan_redirect_chain",
        ):
            assert name in fields, f"EmailDetail missing field: {name}"

    def test_email_detail_has_dynamic_attachment_fields(self):
        from shared.schemas import EmailDetail
        fields = EmailDetail.model_fields
        for name in (
            "dynamic_attachment_status",
            "dynamic_attachment_verdict",
            "dynamic_attachment_score",
            "dynamic_attachment_report_url",
            "dynamic_attachment_tags",
            "dynamic_attachment_error",
        ):
            assert name in fields, f"EmailDetail missing field: {name}"

    def test_email_detail_has_score_split_fields(self):
        from shared.schemas import EmailDetail
        fields = EmailDetail.model_fields
        assert "static_score" in fields
        assert "dynamic_score" in fields

    def test_scoring_weights_has_dynamic_weight_fields(self):
        from shared.schemas import ScoringWeights
        fields = ScoringWeights.model_fields
        assert "urlscan_malicious" in fields
        assert "urlscan_suspicious" in fields
        assert "dynamic_attachment_malicious" in fields
        assert "dynamic_attachment_suspicious" in fields

    def test_scoring_weights_defaults(self):
        from shared.schemas import ScoringWeights
        w = ScoringWeights()
        assert w.urlscan_malicious == 4
        assert w.urlscan_suspicious == 2
        assert w.dynamic_attachment_malicious == 5
        assert w.dynamic_attachment_suspicious == 3

    def test_settings_read_has_urlscan_key_configured(self):
        from shared.schemas import SettingsRead
        fields = SettingsRead.model_fields
        assert "urlscan_key_configured" in fields
        # Default must be False
        s = SettingsRead()
        assert s.urlscan_key_configured is False

    def test_settings_update_has_urlscan_key(self):
        from shared.schemas import SettingsUpdate
        fields = SettingsUpdate.model_fields
        assert "urlscan_key" in fields
        # Default must be None (leave unchanged)
        u = SettingsUpdate()
        assert u.urlscan_key is None


# ──────────────────────────────────────────────────────────────────────────────
# Migration file presence
# ──────────────────────────────────────────────────────────────────────────────

class TestMigrationFile:
    def test_migration_file_exists(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        assert migration.exists(), f"Migration file not found: {migration}"

    def test_migration_revision_id(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        assert 'revision = "d1e2f3a4b5c6"' in src
        assert 'down_revision = "c3d4e5f6a7b8"' in src

    def test_migration_adds_all_urlscan_columns(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        for col in (
            "urlscan_status", "urlscan_error", "urlscan_screenshot_url",
            "urlscan_verdict", "urlscan_redirect_chain",
        ):
            assert col in src, f"Migration missing column: {col}"

    def test_migration_adds_dynamic_attachment_columns(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        for col in (
            "dynamic_attachment_status", "dynamic_attachment_verdict",
            "dynamic_attachment_score", "dynamic_attachment_report_url",
            "dynamic_attachment_tags", "dynamic_attachment_error",
        ):
            assert col in src, f"Migration missing column: {col}"

    def test_migration_adds_score_split_columns(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        assert "static_score" in src
        assert "dynamic_score" in src

    def test_migration_adds_urlscan_key_to_app_settings(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        assert "urlscan_key" in src

    def test_migration_has_downgrade(self):
        migration = _ROOT / "migrations" / "versions" / "d1e2f3a4b5c6_phase1_dynamic_analysis.py"
        src = migration.read_text()
        assert "def downgrade" in src
        assert "drop_column" in src


# ──────────────────────────────────────────────────────────────────────────────
# Timeout safety — pipeline guard
# ──────────────────────────────────────────────────────────────────────────────

class TestTimeoutGuard:
    def test_pipeline_timeout_guard_present_in_source(self):
        """analysis_service must wrap urlscan in asyncio.wait_for with a timeout > _MAX_WAIT (120s)."""
        src = Path(_ROOT / "backend" / "services" / "analysis_service.py").read_text()
        assert "asyncio.wait_for" in src, (
            "asyncio.wait_for not used in analysis_service.py for urlscan"
        )
        assert "urlscan_provider" in src, (
            "urlscan_provider not imported in analysis_service.py"
        )
        # The outer timeout must be > 120 (internal _MAX_WAIT).
        # Current value is 135 (120 + 15s grace). Check for 135 specifically.
        assert "timeout=135" in src, (
            "Outer pipeline timeout must be 135s (120s inner cap + 15s grace) "
            "so the inner timeout always fires first. Found neither 135 in analysis_service.py."
        )

    def test_urlscan_runs_concurrently_in_gather(self):
        """The urlscan call must be part of an asyncio.gather, not a sequential await."""
        src = Path(_ROOT / "backend" / "services" / "analysis_service.py").read_text()
        # Look for gather containing urlscan-related coroutine
        assert "asyncio.gather" in src, "asyncio.gather not found in analysis_service.py"
        # The _run_urlscan or urlscan_result must appear in the gather context
        assert "_run_urlscan" in src or "urlscan_result" in src, (
            "urlscan result not found in analysis_service.py"
        )
