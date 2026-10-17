"""Tests for Phase C Step 1: reason_evidence column and per-signal evidence data.

One test per signal type, plus a NULL → None mapping test.
All tests use mocks — no real DB or network calls.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_behavioral_result(**kwargs):
    """Build a minimal BehavioralResult-like object with default False flags."""
    from backend.services.behavioral_signals_service import BehavioralResult
    defaults = dict(
        behavioral_score=0,
        behavioral_reasons=[],
        sig_first_time_sender=False,
        sig_domain_age_anomaly=False,
        sig_display_name_mismatch=False,
        sig_reply_chain_break=False,
        sig_send_time_anomaly=False,
        domain_age_evidence=None,
        first_time_sender_evidence=None,
        reply_chain_break_evidence=None,
        send_time_anomaly_evidence=None,
        display_name_mismatch_evidence=None,
    )
    defaults.update(kwargs)
    return BehavioralResult(**defaults)


def _make_bec_result(**kwargs):
    """Build a minimal BecResult-like object with default False flags."""
    from backend.services.bec_signals_service import BecResult
    defaults = dict(
        bec_score=0,
        bec_reasons=[],
        sig_vip_impersonation=False,
        sig_financial_request=False,
        sig_vendor_fraud=False,
        sig_authority_pressure=False,
        vip_evidence=None,
        financial_evidence=None,
    )
    defaults.update(kwargs)
    return BecResult(**defaults)


def _call_build(
    *,
    auth=None,
    header_flags=None,
    from_addr=None,
    from_domain=None,
    url_rows=None,
    reasons=None,
    behavioral_result=None,
    bec_result=None,
):
    from backend.services.analysis_service import _build_reason_evidence
    return _build_reason_evidence(
        auth=auth or {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        header_flags=header_flags or {
            "is_lookalike_domain": False,
            "lookalike_of": None,
            "is_punycode_domain": False,
            "is_suspicious_sender_tld": False,
        },
        from_addr=from_addr or "test@example.com",
        from_domain=from_domain or "example.com",
        url_rows=url_rows or [],
        reasons=reasons or [],
        behavioral_result=behavioral_result,
        bec_result=bec_result,
    )


# ── Signal tests ──────────────────────────────────────────────────────────────

class TestReasonEvidenceBuilder:

    # ── Static: auth failures ──────────────────────────────────────────────

    def test_spf_fail_evidence(self):
        items = _call_build(auth={"spf": "fail", "dkim": "unknown", "dmarc": "unknown"},
                            from_domain="evil.com")
        spf_item = next((i for i in items if i["signal"] == "spf_fail"), None)
        assert spf_item is not None, "Expected spf_fail item"
        assert spf_item["category"] == "static"
        assert spf_item["evidence"]["spf_result"] == "fail"
        assert spf_item["evidence"]["from_domain"] == "evil.com"

    def test_dkim_fail_evidence(self):
        items = _call_build(auth={"spf": "unknown", "dkim": "fail", "dmarc": "unknown"},
                            from_addr="Attacker <attacker@evil.com>")
        dkim_item = next((i for i in items if i["signal"] == "dkim_fail"), None)
        assert dkim_item is not None, "Expected dkim_fail item"
        assert dkim_item["category"] == "static"
        assert dkim_item["evidence"]["dkim_result"] == "fail"

    def test_dmarc_fail_evidence(self):
        items = _call_build(auth={"spf": "unknown", "dkim": "unknown", "dmarc": "fail"},
                            from_domain="evil.com")
        dmarc_item = next((i for i in items if i["signal"] == "dmarc_fail"), None)
        assert dmarc_item is not None
        assert dmarc_item["evidence"]["dmarc_result"] == "fail"

    def test_spf_pass_produces_no_evidence(self):
        items = _call_build(auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        signals = {i["signal"] for i in items}
        assert "spf_fail" not in signals
        assert "dkim_fail" not in signals
        assert "dmarc_fail" not in signals

    # ── Static: lookalike domain ───────────────────────────────────────────

    def test_lookalike_domain_evidence(self):
        items = _call_build(
            header_flags={
                "is_lookalike_domain": True,
                "lookalike_of": "paypal.com",
                "is_punycode_domain": False,
                "is_suspicious_sender_tld": False,
            },
            from_domain="paypa1.com",
        )
        ll_item = next((i for i in items if i["signal"] == "lookalike_domain"), None)
        assert ll_item is not None
        assert ll_item["evidence"]["resembles"] == "paypal.com"
        assert ll_item["evidence"]["sending_domain"] == "paypa1.com"

    # ── Static: URL indicators ─────────────────────────────────────────────

    def test_url_ip_host_evidence(self):
        url_rows = [{"url": "http://1.2.3.4/evil", "is_ip_host": True,
                     "is_shortener": False, "is_suspicious_keyword": False,
                     "is_redirect_suspicious": False, "is_suspicious_tld": False,
                     "vt_malicious": 0, "vt_harmless": 0, "vt_suspicious": 0}]
        items = _call_build(url_rows=url_rows)
        ip_item = next((i for i in items if i["signal"] == "url_ip_host"), None)
        assert ip_item is not None
        assert "http://1.2.3.4/evil" in ip_item["evidence"]["urls"]

    def test_url_shortener_evidence(self):
        url_rows = [{"url": "https://bit.ly/abc", "is_shortener": True,
                     "is_ip_host": False, "is_suspicious_keyword": False,
                     "is_redirect_suspicious": False, "is_suspicious_tld": False,
                     "vt_malicious": 0, "vt_harmless": 0, "vt_suspicious": 0}]
        items = _call_build(url_rows=url_rows)
        short_item = next((i for i in items if i["signal"] == "url_shortener"), None)
        assert short_item is not None
        assert "https://bit.ly/abc" in short_item["evidence"]["urls"]

    def test_url_suspicious_keyword_evidence(self):
        url_rows = [{"url": "https://example.com/login?verify=1",
                     "is_suspicious_keyword": True, "is_ip_host": False,
                     "is_shortener": False, "is_redirect_suspicious": False,
                     "is_suspicious_tld": False,
                     "vt_malicious": 0, "vt_harmless": 0, "vt_suspicious": 0}]
        items = _call_build(url_rows=url_rows)
        kw_item = next((i for i in items if i["signal"] == "url_suspicious_keyword"), None)
        assert kw_item is not None

    def test_url_redirect_suspicious_evidence(self):
        url_rows = [{"url": "https://redirect.evil.com/go?to=phish",
                     "is_redirect_suspicious": True, "is_ip_host": False,
                     "is_shortener": False, "is_suspicious_keyword": False,
                     "is_suspicious_tld": False,
                     "vt_malicious": 0, "vt_harmless": 0, "vt_suspicious": 0}]
        items = _call_build(url_rows=url_rows)
        rd_item = next((i for i in items if i["signal"] == "url_redirect_suspicious"), None)
        assert rd_item is not None

    # ── Dynamic: VT malicious URLs ────────────────────────────────────────

    def test_vt_malicious_url_evidence(self):
        url_rows = [{"url": "https://evil.com/malware",
                     "vt_malicious": 5, "vt_harmless": 2, "vt_suspicious": 1,
                     "is_ip_host": False, "is_shortener": False,
                     "is_suspicious_keyword": False, "is_redirect_suspicious": False,
                     "is_suspicious_tld": False}]
        items = _call_build(url_rows=url_rows)
        vt_item = next((i for i in items if i["signal"] == "vt_malicious_url"), None)
        assert vt_item is not None
        assert vt_item["category"] == "dynamic"
        assert any(e["url"] == "https://evil.com/malware"
                   for e in vt_item["evidence"]["urls"])

    # ── Behavioral: first_time_sender ─────────────────────────────────────

    def test_first_time_sender_evidence(self):
        br = _make_behavioral_result(
            sig_first_time_sender=True,
            behavioral_reasons=["First-time sender: 'a@evil.com' has never contacted 'victim@corp.com' before"],
            first_time_sender_evidence={"sender": "a@evil.com",
                                         "recipient": "victim@corp.com",
                                         "prior_message_count": 0},
        )
        items = _call_build(behavioral_result=br)
        ft_item = next((i for i in items if i["signal"] == "first_time_sender"), None)
        assert ft_item is not None
        assert ft_item["category"] == "behavioral"
        assert ft_item["evidence"]["prior_message_count"] == 0
        assert ft_item["evidence"]["sender"] == "a@evil.com"

    # ── Behavioral: domain_age_anomaly ────────────────────────────────────

    def test_domain_age_anomaly_evidence(self):
        ev = {"domain": "newdomain.com", "registration_date": "2026-10-01",
              "age_days": 5, "threshold_days": 30}
        br = _make_behavioral_result(
            sig_domain_age_anomaly=True,
            behavioral_reasons=["Domain age anomaly: 'newdomain.com' registered within 30 days"],
            domain_age_evidence=ev,
        )
        items = _call_build(behavioral_result=br)
        da_item = next((i for i in items if i["signal"] == "domain_age_anomaly"), None)
        assert da_item is not None
        assert da_item["evidence"]["age_days"] == 5
        assert da_item["evidence"]["registration_date"] == "2026-10-01"
        assert da_item["evidence"]["threshold_days"] == 30

    # ── Behavioral: display_name_mismatch ─────────────────────────────────

    def test_display_name_mismatch_evidence(self):
        br = _make_behavioral_result(
            sig_display_name_mismatch=True,
            behavioral_reasons=["Display name mismatch: From display implies PayPal but domain is evil.com"],
            display_name_mismatch_evidence={"display_name": "PayPal Support <attacker@evil.com>",
                                             "sending_domain": "evil.com"},
        )
        items = _call_build(behavioral_result=br)
        dn_item = next((i for i in items if i["signal"] == "display_name_mismatch"), None)
        assert dn_item is not None
        assert dn_item["evidence"]["sending_domain"] == "evil.com"

    # ── Behavioral: reply_chain_break ─────────────────────────────────────

    def test_reply_chain_break_evidence(self):
        br = _make_behavioral_result(
            sig_reply_chain_break=True,
            behavioral_reasons=["Reply chain break: subject 'Re: Invoice' looks like a reply but sender is new"],
            reply_chain_break_evidence={"thread_key": "invoice", "sender": "attacker@evil.com"},
        )
        items = _call_build(behavioral_result=br)
        rc_item = next((i for i in items if i["signal"] == "reply_chain_break"), None)
        assert rc_item is not None
        assert rc_item["evidence"]["thread_key"] == "invoice"
        assert rc_item["evidence"]["sender"] == "attacker@evil.com"

    # ── Behavioral: send_time_anomaly ─────────────────────────────────────

    def test_send_time_anomaly_evidence(self):
        br = _make_behavioral_result(
            sig_send_time_anomaly=True,
            behavioral_reasons=["Send time anomaly: email sent at 02:xx UTC is outside historical window"],
            send_time_anomaly_evidence={"send_hour": 2, "usual_hours": [9, 10, 11, 14, 15]},
        )
        items = _call_build(behavioral_result=br)
        st_item = next((i for i in items if i["signal"] == "send_time_anomaly"), None)
        assert st_item is not None
        assert st_item["evidence"]["send_hour"] == 2
        assert 9 in st_item["evidence"]["usual_hours"]

    # ── BEC: vip_impersonation ────────────────────────────────────────────

    def test_vip_impersonation_evidence(self):
        bec = _make_bec_result(
            sig_vip_impersonation=True,
            bec_reasons=["VIP impersonation: From display matches 'Jane Smith (CFO)' but domain is evil.com"],
            vip_evidence={"matched_vip_name": "Jane Smith",
                          "protected_domain": "corp.com",
                          "actual_sender": "jane.smith@evil.com"},
        )
        items = _call_build(bec_result=bec)
        vip_item = next((i for i in items if i["signal"] == "vip_impersonation"), None)
        assert vip_item is not None
        assert vip_item["category"] == "bec"
        assert vip_item["evidence"]["matched_vip_name"] == "Jane Smith"
        assert vip_item["evidence"]["protected_domain"] == "corp.com"
        assert vip_item["evidence"]["actual_sender"] == "jane.smith@evil.com"

    # ── BEC: financial_request_language ───────────────────────────────────

    def test_financial_request_evidence(self):
        bec = _make_bec_result(
            sig_financial_request=True,
            bec_reasons=["BEC financial pattern 'wire transfer' — keywords: wire transfer"],
            financial_evidence={"categories": {"wire_transfer": ["wire transfer"],
                                               "urgency_authority": ["strictly confidential"]}},
        )
        items = _call_build(bec_result=bec)
        fin_item = next((i for i in items if i["signal"] == "financial_request_language"), None)
        assert fin_item is not None
        assert fin_item["category"] == "bec"
        assert "wire_transfer" in fin_item["evidence"]["categories"]

    # ── Cap enforcement ───────────────────────────────────────────────────

    def test_cap_at_30_items(self):
        """Generating signals that would exceed 30 items must be capped."""
        # Create 35 URL rows, each with multiple flags set
        url_rows = [
            {"url": f"http://{i}.{i}.{i}.{i}/evil",
             "is_ip_host": True, "is_shortener": True,
             "is_suspicious_keyword": True, "is_redirect_suspicious": True,
             "is_suspicious_tld": True,
             "vt_malicious": 5, "vt_harmless": 0, "vt_suspicious": 0}
            for i in range(35)
        ]
        items = _call_build(url_rows=url_rows)
        assert len(items) <= 30

    def test_value_cap_300_chars(self):
        """String values longer than 300 chars must be truncated."""
        long_domain = "a" * 400
        items = _call_build(
            header_flags={
                "is_lookalike_domain": True,
                "lookalike_of": long_domain,
                "is_punycode_domain": False,
                "is_suspicious_sender_tld": False,
            },
            from_domain="x.com",
        )
        ll_item = next((i for i in items if i["signal"] == "lookalike_domain"), None)
        assert ll_item is not None
        assert len(ll_item["evidence"]["resembles"]) <= 301  # 300 + ellipsis

    # ── NULL → None schema mapping ────────────────────────────────────────

    def test_null_reason_evidence_maps_to_none_in_schema(self):
        """An EmailAnalysis row with reason_evidence=NULL must return None in
        the EmailDetail schema via _to_detail(), not [] or {}.

        This ensures pre-Phase-C rows are clearly distinguishable from analyses
        that were processed and produced no evidence items.
        """
        from backend.routes.analyses import _to_detail
        from backend.models.analysis import EmailAnalysis
        import datetime as _dt

        # Minimal mock analysis with reason_evidence not set (None)
        analysis = MagicMock(spec=EmailAnalysis)
        analysis.id = 1
        analysis.filename = "test.eml"
        analysis.subject = "Test"
        analysis.from_addr = "sender@example.com"
        analysis.status = "DONE"
        analysis.verdict = "benign"
        analysis.score = 0
        _now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
        analysis.created_at = _now
        analysis.updated_at = _now
        analysis.message_id = None
        analysis.error_message = None
        analysis.reply_to = None
        analysis.return_path = None
        analysis.from_domain = "example.com"
        analysis.reply_domain = None
        analysis.return_domain = None
        analysis.sender_ip = None
        analysis.spf = "unknown"
        analysis.dkim = "unknown"
        analysis.dmarc = "unknown"
        analysis.auth_headers_raw = []
        analysis.header_issues = []
        analysis.is_lookalike_domain = False
        analysis.lookalike_of = None
        analysis.is_punycode_domain = False
        analysis.is_suspicious_sender_tld = False
        analysis.urls = []
        analysis.attachments = []
        analysis.global_hashes = {"md5": [], "sha1": [], "sha256": []}
        analysis.abuse_score = None
        analysis.abuse_total_reports = None
        analysis.abuse_country = None
        analysis.abuse_isp = None
        analysis.reasons = []
        analysis.urgency_keywords_found = []
        analysis.body_text = None
        analysis.vt_enrichment_status = None
        analysis.vt_enrichment_error = None
        analysis.abuse_enrichment_status = None
        analysis.abuse_enrichment_error = None
        analysis.mime_parts = []
        analysis.lure_categories = []
        analysis.anchor_mismatches = []
        analysis.shodan_data = None
        analysis.shodan_enrichment_status = None
        analysis.shodan_enrichment_error = None
        analysis.sandbox_status = None
        analysis.sandbox_provider = None
        analysis.sandbox_verdict = None
        analysis.sandbox_score = None
        analysis.sandbox_report_url = None
        analysis.sandbox_tags = []
        analysis.sandbox_error = None
        analysis.urlscan_status = None
        analysis.urlscan_error = None
        analysis.urlscan_screenshot_url = None
        analysis.urlscan_verdict = None
        analysis.urlscan_redirect_chain = []
        analysis.dynamic_attachment_status = None
        analysis.dynamic_attachment_verdict = None
        analysis.dynamic_attachment_score = None
        analysis.dynamic_attachment_report_url = None
        analysis.dynamic_attachment_tags = []
        analysis.dynamic_attachment_error = None
        analysis.static_score = None
        analysis.dynamic_score = None
        analysis.behavioral_score = None
        analysis.behavioral_reasons = []
        analysis.sig_first_time_sender = None
        analysis.sig_domain_age_anomaly = None
        analysis.sig_display_name_mismatch = None
        analysis.sig_reply_chain_break = None
        analysis.sig_send_time_anomaly = None
        analysis.bec_score = None
        analysis.bec_reasons = []
        analysis.sig_vip_impersonation = None
        analysis.sig_financial_request = None
        analysis.sig_vendor_fraud = None
        analysis.sig_authority_pressure = None
        analysis.pipeline_stages = None
        # Simulate a pre-Phase-C row: reason_evidence is None (NULL in DB)
        analysis.reason_evidence = None

        detail = _to_detail(analysis)
        assert detail.reason_evidence is None, (
            f"Pre-Phase-C row should have reason_evidence=None; got {detail.reason_evidence!r}"
        )

    def test_reason_evidence_populated_row_maps_correctly(self):
        """An EmailAnalysis with a populated reason_evidence list maps to list in EmailDetail."""
        from backend.routes.analyses import _to_detail
        from backend.models.analysis import EmailAnalysis
        import datetime as _dt

        evidence_list = [
            {"reason": "SPF fail", "category": "static",
             "signal": "spf_fail", "evidence": {"spf_result": "fail"}}
        ]
        analysis = MagicMock(spec=EmailAnalysis)
        # Set all required fields (same as above test)
        analysis.id = 2
        analysis.filename = "test2.eml"
        analysis.subject = "Test"
        analysis.from_addr = "sender@example.com"
        analysis.status = "DONE"
        analysis.verdict = "suspicious"
        analysis.score = 2
        _now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
        analysis.created_at = _now
        analysis.updated_at = _now
        analysis.message_id = None
        analysis.error_message = None
        analysis.reply_to = None
        analysis.return_path = None
        analysis.from_domain = "example.com"
        analysis.reply_domain = None
        analysis.return_domain = None
        analysis.sender_ip = None
        analysis.spf = "fail"
        analysis.dkim = "unknown"
        analysis.dmarc = "unknown"
        analysis.auth_headers_raw = []
        analysis.header_issues = []
        analysis.is_lookalike_domain = False
        analysis.lookalike_of = None
        analysis.is_punycode_domain = False
        analysis.is_suspicious_sender_tld = False
        analysis.urls = []
        analysis.attachments = []
        analysis.global_hashes = {"md5": [], "sha1": [], "sha256": []}
        analysis.abuse_score = None
        analysis.abuse_total_reports = None
        analysis.abuse_country = None
        analysis.abuse_isp = None
        analysis.reasons = []
        analysis.urgency_keywords_found = []
        analysis.body_text = None
        analysis.vt_enrichment_status = None
        analysis.vt_enrichment_error = None
        analysis.abuse_enrichment_status = None
        analysis.abuse_enrichment_error = None
        analysis.mime_parts = []
        analysis.lure_categories = []
        analysis.anchor_mismatches = []
        analysis.shodan_data = None
        analysis.shodan_enrichment_status = None
        analysis.shodan_enrichment_error = None
        analysis.sandbox_status = None
        analysis.sandbox_provider = None
        analysis.sandbox_verdict = None
        analysis.sandbox_score = None
        analysis.sandbox_report_url = None
        analysis.sandbox_tags = []
        analysis.sandbox_error = None
        analysis.urlscan_status = None
        analysis.urlscan_error = None
        analysis.urlscan_screenshot_url = None
        analysis.urlscan_verdict = None
        analysis.urlscan_redirect_chain = []
        analysis.dynamic_attachment_status = None
        analysis.dynamic_attachment_verdict = None
        analysis.dynamic_attachment_score = None
        analysis.dynamic_attachment_report_url = None
        analysis.dynamic_attachment_tags = []
        analysis.dynamic_attachment_error = None
        analysis.static_score = None
        analysis.dynamic_score = None
        analysis.behavioral_score = None
        analysis.behavioral_reasons = []
        analysis.sig_first_time_sender = None
        analysis.sig_domain_age_anomaly = None
        analysis.sig_display_name_mismatch = None
        analysis.sig_reply_chain_break = None
        analysis.sig_send_time_anomaly = None
        analysis.bec_score = None
        analysis.bec_reasons = []
        analysis.sig_vip_impersonation = None
        analysis.sig_financial_request = None
        analysis.sig_vendor_fraud = None
        analysis.sig_authority_pressure = None
        analysis.pipeline_stages = None
        analysis.reason_evidence = evidence_list

        detail = _to_detail(analysis)
        assert detail.reason_evidence == evidence_list


# ── _check_financial_request_language unit tests ──────────────────────────────

class TestFinancialRequestLanguageEvidence:

    def test_returns_four_tuple(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        result = _check_financial_request_language("please wire transfer the funds")
        assert len(result) == 4, "Should return (fired, categories, reasons, phrases)"
        fired, cats, reasons, phrases = result
        assert fired is True
        assert "wire_transfer" in cats
        assert isinstance(phrases, dict)
        assert "wire_transfer" in phrases

    def test_category_phrases_present(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "strictly confidential. Please wire transfer the funds immediately."
        _, cats, _, phrases = _check_financial_request_language(body)
        assert "wire_transfer" in cats
        assert "urgency_authority" in cats
        assert len(phrases["wire_transfer"]) >= 1
        assert len(phrases["urgency_authority"]) >= 1

    def test_empty_body_returns_empty(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        fired, cats, reasons, phrases = _check_financial_request_language("")
        assert fired is False
        assert cats == []
        assert phrases == {}


# ── _check_domain_age_anomaly unit tests ─────────────────────────────────────

class TestDomainAgeAnomalyEvidence:

    def test_young_domain_returns_evidence(self):
        from datetime import datetime, timezone
        from unittest.mock import AsyncMock, patch
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        reg_date = datetime(2026, 10, 1, tzinfo=timezone.utc)
        email_date = datetime(2026, 10, 10, tzinfo=timezone.utc)  # 9 days after reg

        async def run():
            with patch(
                "backend.services.behavioral_signals_service._lookup_domain_registration_date",
                new=AsyncMock(return_value=reg_date),
            ):
                return await _check_domain_age_anomaly("newdomain.com", email_date, threshold_days=30)

        fired, ev = asyncio.run(run())
        assert fired is True
        assert ev is not None
        assert ev["age_days"] == 9
        assert ev["registration_date"] == "2026-10-01"
        assert ev["threshold_days"] == 30
        assert ev["domain"] == "newdomain.com"

    def test_old_domain_returns_no_evidence(self):
        from datetime import datetime, timezone
        from unittest.mock import AsyncMock, patch
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        reg_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        email_date = datetime(2026, 10, 10, tzinfo=timezone.utc)

        async def run():
            with patch(
                "backend.services.behavioral_signals_service._lookup_domain_registration_date",
                new=AsyncMock(return_value=reg_date),
            ):
                return await _check_domain_age_anomaly("olddomain.com", email_date, threshold_days=30)

        fired, ev = asyncio.run(run())
        assert fired is False
        assert ev is None

    def test_lookup_failure_returns_none_none(self):
        from unittest.mock import AsyncMock, patch
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        async def run():
            with patch(
                "backend.services.behavioral_signals_service._lookup_domain_registration_date",
                new=AsyncMock(return_value=None),
            ):
                return await _check_domain_age_anomaly("unknown.com", None, threshold_days=30)

        fired, ev = asyncio.run(run())
        assert fired is None
        assert ev is None


# ── _check_vip_impersonation unit tests ──────────────────────────────────────

class TestVipImpersonationEvidence:

    def test_vip_match_returns_evidence_dict(self):
        """Matching a VIP by display name returns a 3-tuple with evidence dict."""
        from unittest.mock import AsyncMock, MagicMock
        from backend.services.bec_signals_service import _check_vip_impersonation

        mock_vip = MagicMock()
        mock_vip.name = "Jane Smith"
        mock_vip.protected_email = "jane.smith@corp.com"
        mock_vip.protected_domain = "corp.com"
        mock_vip.title = "CFO"
        mock_vip.is_active = True

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_vip]
        mock_session.execute.return_value = mock_result

        async def run():
            return await _check_vip_impersonation(
                session=mock_session,
                from_addr="Jane Smith <attacker@evil.com>",
                from_domain="evil.com",
            )

        fired, reason, ev = asyncio.run(run())
        assert fired is True
        assert ev is not None
        assert ev["matched_vip_name"] == "Jane Smith"
        assert ev["protected_domain"] == "corp.com"
        assert "evil.com" in ev["actual_sender"] or "attacker" in ev["actual_sender"]

    def test_no_vip_entries_returns_none_none_none(self):
        from unittest.mock import AsyncMock, MagicMock
        from backend.services.bec_signals_service import _check_vip_impersonation

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        async def run():
            return await _check_vip_impersonation(
                session=mock_session,
                from_addr="Anyone <a@b.com>",
                from_domain="b.com",
            )

        fired, reason, ev = asyncio.run(run())
        assert fired is False
        assert reason is None
        assert ev is None
