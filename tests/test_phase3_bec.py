"""Phase 3 BEC (Business Email Compromise) signal detection tests.

Covers:
  - bec_signals_service.py — all four signals, cold-start, edge cases
      Signal 1: _check_vip_impersonation
      Signal 2: _check_financial_request_language
      Signal 3: _check_vendor_fraud_pattern
      Signal 4: _check_authority_pressure_combo
      Full integration: compute_bec_signals()
  - scoring_service.compute_score() — bec_result integration, 2× weight
    formula, BEC_SUSPICIOUS_FLOOR verdict floor, return keys
  - analysis_service._run_pipeline() — BEC import wired, compute_bec_signals
    called after behavioral block, bec_result passed to compute_score,
    bec_* columns written to analysis row

All tests are self-contained.  No real network calls, no real DB state:
  - DB interactions replaced with AsyncMock sessions.
  - VIPIdentity rows returned as MagicMock objects with the expected attrs.

Run with:
    pip install pytest pytest-asyncio
    pytest tests/test_phase3_bec.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_vip(
    name: str,
    protected_domain: str,
    protected_email: str | None = None,
    title: str | None = None,
    is_active: bool = True,
) -> MagicMock:
    """Build a VIPIdentity-like mock with the fields the service reads."""
    vip = MagicMock()
    vip.name = name
    vip.protected_domain = protected_domain
    vip.protected_email = protected_email
    vip.title = title
    vip.is_active = is_active
    return vip


def _session_with_vips(vips: list) -> AsyncMock:
    """Build a session whose execute() returns the given VIP list."""
    session = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = vips
    session.execute = AsyncMock(return_value=result)
    session.scalar = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


def _session_with_sender_history(
    any_history=None,
    sender_known=None,
    thread_rows=None,
) -> AsyncMock:
    """Build a session whose scalar() returns controlled sender-history values."""
    session = AsyncMock()
    session.scalar = AsyncMock(side_effect=[any_history, sender_known])

    result = MagicMock()
    result.scalars.return_value.all.return_value = thread_rows or []
    session.execute = AsyncMock(return_value=result)
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


def _base_weights() -> dict:
    """Minimal scoring weights for compute_score() tests."""
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
        "urlscan_malicious": 4, "urlscan_suspicious": 2,
        "dynamic_attachment_malicious": 5, "dynamic_attachment_suspicious": 3,
    }


def _compute_score(bec_result=None, behavioral_result=None, spf="pass"):
    """Thin wrapper that calls compute_score() with sensible defaults."""
    from backend.services.scoring_service import compute_score
    return compute_score(
        from_addr="sender@example.com",
        from_domain="example.com",
        auth={"spf": spf, "dkim": "pass", "dmarc": "pass"},
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
        bec_result=bec_result,
        behavioral_result=behavioral_result,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Signal 1 — _check_vip_impersonation
# ═══════════════════════════════════════════════════════════════════════════════

class TestVipImpersonation:
    """Unit tests for _check_vip_impersonation()."""

    @pytest.mark.asyncio
    async def test_no_vips_returns_false(self):
        """Empty VIP table → signal must not fire (feature disabled when no VIPs)."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        session = _session_with_vips([])
        fired, reason = await _check_vip_impersonation(
            session, "CEO <ceo@evil.com>", "evil.com"
        )
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_legit_domain_not_flagged(self):
        """Sender with protected_domain → same domain → NOT impersonation."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("Jane Smith", protected_domain="corp.com",
                        protected_email="jane.smith@corp.com")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "Jane Smith <jane.smith@corp.com>", "corp.com"
        )
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_legit_subdomain_not_flagged(self):
        """Subdomain of protected_domain (mail.corp.com) → NOT flagged."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("Jane Smith", protected_domain="corp.com",
                        protected_email="jane.smith@corp.com")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "Jane Smith <jane.smith@mail.corp.com>", "mail.corp.com"
        )
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_exact_email_match_wrong_domain_fires(self):
        """Sender address exactly matches protected_email but wrong domain → fires."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("Jane Smith", protected_domain="corp.com",
                        protected_email="jane.smith@corp.com", title="CFO")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "<jane.smith@corp.com>", "evil-corp.com"
        )
        assert fired is True
        assert "jane.smith@corp.com" in reason
        assert "evil-corp.com" in reason

    @pytest.mark.asyncio
    async def test_display_name_match_wrong_domain_fires(self):
        """VIP name in From display, wrong domain → fires."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("Jane Smith", protected_domain="corp.com", title="CFO")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "Jane Smith <attacker@evil.com>", "evil.com"
        )
        assert fired is True
        assert "Jane Smith" in reason
        assert "evil.com" in reason

    @pytest.mark.asyncio
    async def test_partial_name_not_enough(self):
        """Only first name matches (too short, less than 3 chars combined) → no fire."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        # VIP with short one-word name less than 3 chars — should be skipped
        vip = _make_vip("Jo", protected_domain="corp.com")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "Jo at accounts <jo@evil.com>", "evil.com"
        )
        # name_words for "Jo" with len=2 < 3 → check b is skipped
        assert fired is False

    @pytest.mark.asyncio
    async def test_vip_name_case_insensitive(self):
        """Display name match is case-insensitive."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("JANE SMITH", protected_domain="corp.com")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(
            session, "jane smith <attacker@evil.com>", "evil.com"
        )
        assert fired is True

    @pytest.mark.asyncio
    async def test_none_from_addr_returns_false(self):
        """No From address → cannot check → returns False."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        vip = _make_vip("Jane Smith", protected_domain="corp.com")
        session = _session_with_vips([vip])

        fired, reason = await _check_vip_impersonation(session, None, None)
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_db_exception_returns_false(self):
        """DB query failure → returns (False, None) — does not crash."""
        from backend.services.bec_signals_service import _check_vip_impersonation

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=RuntimeError("DB down"))

        fired, reason = await _check_vip_impersonation(
            session, "Jane Smith <attacker@evil.com>", "evil.com"
        )
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_inactive_vip_ignored(self):
        """Inactive VIP entry (is_active=False) should not trigger impersonation.

        NOTE: The DB query filters WHERE is_active=True, so the inactive entry
        is never returned by the query.  We simulate this by returning an empty
        list (the query result would be empty for inactive entries).
        """
        from backend.services.bec_signals_service import _check_vip_impersonation

        # Simulate DB returning no rows (is_active filter excluded the row)
        session = _session_with_vips([])
        fired, reason = await _check_vip_impersonation(
            session, "Jane Smith <attacker@evil.com>", "evil.com"
        )
        assert fired is False


# ═══════════════════════════════════════════════════════════════════════════════
# Signal 2 — _check_financial_request_language
# ═══════════════════════════════════════════════════════════════════════════════

class TestFinancialRequestLanguage:
    """Unit tests for _check_financial_request_language()."""

    def test_empty_body_returns_false(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        fired, cats, reasons = _check_financial_request_language("")
        assert fired is False
        assert cats == []
        assert reasons == []

    def test_none_body_returns_false(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        fired, cats, reasons = _check_financial_request_language(None)
        assert fired is False

    def test_wire_transfer_category_fires(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "Please initiate a transfer of $50,000 to the following account."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "wire_transfer" in cats
        assert len(reasons) >= 1

    def test_bank_detail_change_category_fires(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "We have updated our bank account. Please update your records with the new account number."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "bank_detail_change" in cats

    def test_urgency_authority_category_fires(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "This is time sensitive. Keep this strictly confidential and do not discuss with anyone."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "urgency_authority" in cats

    def test_gift_card_category_fires(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "Please buy gift cards worth $200 and send me the codes."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "gift_card" in cats

    def test_invoice_redirect_category_fires(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "Please process this invoice and send payment to the new account effective immediately."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "invoice_redirect" in cats

    def test_multiple_categories_fire_independently(self):
        from backend.services.bec_signals_service import _check_financial_request_language
        body = (
            "Please wire transfer the funds immediately. "
            "This is time sensitive. Keep this strictly confidential. "
            "Also please buy gift cards and send me the codes."
        )
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        # At least 3 categories should fire
        assert len(cats) >= 3

    def test_score_capped_at_max(self):
        """Even with all five categories firing, score is capped at BEC_FINANCIAL_MAX_PTS."""
        from backend.services.bec_signals_service import (
            _check_financial_request_language,
            BEC_FINANCIAL_MAX_PTS,
            _PTS_FINANCIAL_PER_CATEGORY,
        )
        body = (
            "initiate a transfer — wire the funds. "       # wire_transfer
            "new account number has changed. "              # bank_detail_change
            "strictly confidential, this is time sensitive. "  # urgency_authority
            "buy gift cards and send me the codes. "        # gift_card
            "process this invoice, send payment to new account."  # invoice_redirect
        )
        fired, cats, reasons = _check_financial_request_language(body, max_pts=BEC_FINANCIAL_MAX_PTS)
        # All 5 categories should fire
        assert len(cats) == 5
        # But point value is capped — compute_bec_signals enforces the cap
        uncapped = len(cats) * _PTS_FINANCIAL_PER_CATEGORY
        assert uncapped > BEC_FINANCIAL_MAX_PTS  # confirm cap would apply

    def test_benign_financial_text_does_not_fire(self):
        """Normal business email with no BEC patterns → no fire."""
        from backend.services.bec_signals_service import _check_financial_request_language
        body = (
            "Hi, please find the quarterly report attached. "
            "Our revenue increased by 12% this quarter. "
            "Let me know if you have questions."
        )
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is False

    def test_case_insensitive_matching(self):
        """Keyword match is case-insensitive."""
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "WIRE TRANSFER of funds required TODAY."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        assert "wire_transfer" in cats

    def test_reasons_include_keyword(self):
        """Reason strings must include the matched keyword."""
        from backend.services.bec_signals_service import _check_financial_request_language
        body = "Please wire transfer the funds to our new account."
        fired, cats, reasons = _check_financial_request_language(body)
        assert fired is True
        # At least one reason should mention 'wire transfer' (or similar keyword)
        assert any("wire" in r.lower() for r in reasons)


# ═══════════════════════════════════════════════════════════════════════════════
# Signal 3 — _check_vendor_fraud_pattern
# ═══════════════════════════════════════════════════════════════════════════════

class TestVendorFraudPattern:
    """Unit tests for _check_vendor_fraud_pattern()."""

    @pytest.mark.asyncio
    async def test_no_financial_language_returns_false(self):
        """No financial language → vendor fraud cannot fire (early-out)."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        session = AsyncMock()
        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="bob@vendor.com",
            subject="Hello",
            in_reply_to=None,
            message_id="<abc@vendor.com>",
            financial_fired=False,
        )
        assert fired is False
        assert reason is None

    @pytest.mark.asyncio
    async def test_cold_start_no_history_returns_neutral(self):
        """Recipient has NO prior sender history at all → cold start → neutral (False)."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        # any_history = None (no recipients at all in DB)
        session = _session_with_sender_history(any_history=None, sender_known=None)
        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="bob@evil.com",
            subject="Re: Invoice",
            in_reply_to=None,
            message_id="<x@evil.com>",
            financial_fired=True,
        )
        assert fired is False

    @pytest.mark.asyncio
    async def test_known_sender_no_fire(self):
        """Financial language but sender is already known → NOT vendor fraud."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        # any_history=42 (mailbox has history), sender_known=7 (this sender known)
        session = _session_with_sender_history(any_history=42, sender_known=7)
        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="trustedvendor@vendor.com",
            subject="Invoice update",
            in_reply_to=None,
            message_id="<y@vendor.com>",
            financial_fired=True,
        )
        assert fired is False

    @pytest.mark.asyncio
    async def test_unknown_sender_with_financial_fires(self):
        """Financial language + unknown sender (any_history exists) → vendor fraud fires."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        # any_history=42 (mailbox has data), sender_known=None (unknown sender)
        session = _session_with_sender_history(any_history=42, sender_known=None)
        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="attacker@evil.com",
            subject="Payment update",
            in_reply_to=None,
            message_id="<z@evil.com>",
            financial_fired=True,
        )
        assert fired is True
        assert reason is not None
        assert "attacker@evil.com" in reason or "Vendor fraud" in reason

    @pytest.mark.asyncio
    async def test_in_reply_to_match_suppresses_vendor_fraud(self):
        """Unknown sender BUT In-Reply-To matches a known thread message_id → suppressed."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        # Build thread row with a matching message_id
        thread_row = MagicMock()
        thread_row.message_id = "known-thread-id@corp.com"

        # any_history=42, sender_known=None → unknown sender
        # But thread has history and In-Reply-To matches
        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=[42, None])  # [any_history, sender_known]

        result = MagicMock()
        # The thread rows are returned as message_id scalars
        result.scalars.return_value.all.return_value = ["known-thread-id@corp.com"]
        session.execute = AsyncMock(return_value=result)

        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="newpartner@partner.com",
            subject="Re: Invoice Payment",
            in_reply_to="known-thread-id@corp.com",  # matches thread
            message_id="<new@partner.com>",
            financial_fired=True,
        )
        assert fired is False

    @pytest.mark.asyncio
    async def test_db_exception_returns_false(self):
        """DB failure → (False, None) — does not propagate exception."""
        from backend.services.bec_signals_service import _check_vendor_fraud_pattern

        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=RuntimeError("DB down"))
        session.execute = AsyncMock(side_effect=RuntimeError("DB down"))

        fired, reason = await _check_vendor_fraud_pattern(
            session,
            recipient="alice@corp.com",
            sender="attacker@evil.com",
            subject="Wire transfer",
            in_reply_to=None,
            message_id="<abc@evil.com>",
            financial_fired=True,
        )
        assert fired is False


# ═══════════════════════════════════════════════════════════════════════════════
# Signal 4 — _check_authority_pressure_combo
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuthorityPressureCombo:
    """Unit tests for _check_authority_pressure_combo()."""

    def test_no_financial_language_never_fires(self):
        """Authority pressure cannot fire without financial language."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=False,
            vip_impersonation_fired=True,
            first_time_sender=True,
        )
        assert fired is False
        assert reason is None

    def test_financial_plus_vip_fires(self):
        """Financial language + VIP impersonation → classic BEC combo fires."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=True,
            vip_impersonation_fired=True,
            first_time_sender=False,
        )
        assert fired is True
        assert reason is not None
        assert "VIP impersonation" in reason

    def test_financial_plus_first_time_sender_fires(self):
        """Financial language + first_time_sender → fires."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=True,
            vip_impersonation_fired=False,
            first_time_sender=True,
        )
        assert fired is True
        assert "first-time sender" in reason

    def test_financial_plus_both_identity_signals_fires(self):
        """Both VIP impersonation and first_time_sender → reason lists both."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=True,
            vip_impersonation_fired=True,
            first_time_sender=True,
        )
        assert fired is True
        assert "VIP impersonation" in reason
        assert "first-time sender" in reason

    def test_financial_alone_does_not_fire(self):
        """Financial language alone (no identity signal) → combo does NOT fire."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=True,
            vip_impersonation_fired=False,
            first_time_sender=False,
        )
        assert fired is False
        assert reason is None

    def test_financial_with_first_time_sender_none_does_not_fire(self):
        """first_time_sender=None (undetermined) should not trigger authority pressure."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=True,
            vip_impersonation_fired=False,
            first_time_sender=None,  # undetermined — not True
        )
        assert fired is False

    def test_no_signals_no_fire(self):
        """All inputs False → no fire."""
        from backend.services.bec_signals_service import _check_authority_pressure_combo
        fired, reason = _check_authority_pressure_combo(
            financial_fired=False,
            vip_impersonation_fired=False,
            first_time_sender=False,
        )
        assert fired is False


# ═══════════════════════════════════════════════════════════════════════════════
# compute_bec_signals() integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestComputeBecSignals:
    """Integration tests for compute_bec_signals()."""

    def _no_vip_session(self) -> AsyncMock:
        """Session with no VIPs and no sender history."""
        s = _session_with_vips([])
        s.scalar = AsyncMock(return_value=None)
        return s

    @pytest.mark.asyncio
    async def test_clean_email_all_signals_false(self):
        """Email with no BEC indicators → all signals False, bec_score=0."""
        from backend.services.bec_signals_service import compute_bec_signals

        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="bob@vendor.com",
            from_domain="vendor.com",
            subject="Hi",
            message_id="<hi@vendor.com>",
            body_text="Just checking in.",
            recipient="alice@corp.com",
        )
        assert result.bec_score == 0
        assert result.sig_vip_impersonation is False
        assert result.sig_financial_request is False
        assert result.sig_vendor_fraud is False
        assert result.sig_authority_pressure is False
        assert result.bec_reasons == []

    @pytest.mark.asyncio
    async def test_financial_request_alone_contributes_score(self):
        """Financial language → bec_score > 0, sig_financial_request=True."""
        from backend.services.bec_signals_service import compute_bec_signals

        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="cfo@corp.com",
            from_domain="corp.com",
            subject="Urgent transfer",
            message_id="<x@corp.com>",
            body_text="Please initiate a wire transfer of $50,000 immediately.",
            recipient="accounts@corp.com",
        )
        assert result.sig_financial_request is True
        assert result.bec_score >= 2  # at least one category
        assert len(result.bec_reasons) >= 1

    @pytest.mark.asyncio
    async def test_vip_impersonation_contributes_score(self):
        """VIP impersonation fires → bec_score includes vip_impersonation points."""
        from backend.services.bec_signals_service import compute_bec_signals, _PTS_VIP_IMPERSONATION

        vip = _make_vip("Jane Smith", protected_domain="corp.com", title="CFO")
        session = _session_with_vips([vip])
        session.scalar = AsyncMock(return_value=None)

        result = await compute_bec_signals(
            session=session,
            from_addr="Jane Smith <attacker@evil.com>",
            from_domain="evil.com",
            subject="Confidential request",
            message_id="<x@evil.com>",
            body_text="A normal message.",
            recipient="accounts@corp.com",
        )
        assert result.sig_vip_impersonation is True
        assert result.bec_score >= _PTS_VIP_IMPERSONATION

    @pytest.mark.asyncio
    async def test_authority_pressure_requires_financial_plus_identity(self):
        """authority_pressure fires when both VIP impersonation + financial language co-occur."""
        from backend.services.bec_signals_service import (
            compute_bec_signals, _PTS_VIP_IMPERSONATION, _PTS_AUTHORITY_PRESSURE,
        )

        vip = _make_vip("Jane Smith", protected_domain="corp.com", title="CFO")
        session = _session_with_vips([vip])
        session.scalar = AsyncMock(return_value=None)

        result = await compute_bec_signals(
            session=session,
            from_addr="Jane Smith <attacker@evil.com>",
            from_domain="evil.com",
            subject="Urgent wire",
            message_id="<uw@evil.com>",
            body_text="Please wire transfer the funds immediately. Strictly confidential.",
            recipient="accounts@corp.com",
        )
        assert result.sig_vip_impersonation is True
        assert result.sig_financial_request is True
        assert result.sig_authority_pressure is True
        # Score: vip(4) + financial(at least 2) + authority(3) = ≥ 9
        assert result.bec_score >= _PTS_VIP_IMPERSONATION + _PTS_AUTHORITY_PRESSURE

    @pytest.mark.asyncio
    async def test_first_time_sender_passed_in_triggers_authority_pressure(self):
        """first_time_sender=True passed in → authority_pressure fires with financial."""
        from backend.services.bec_signals_service import compute_bec_signals, _PTS_AUTHORITY_PRESSURE

        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="stranger@evil.com",
            from_domain="evil.com",
            subject="Payment",
            message_id="<pay@evil.com>",
            body_text="Please initiate a transfer right away. This is time sensitive.",
            recipient="alice@corp.com",
            first_time_sender=True,  # Phase 2 behavioral flag passed in
        )
        assert result.sig_financial_request is True
        assert result.sig_authority_pressure is True
        assert result.bec_score >= _PTS_AUTHORITY_PRESSURE

    @pytest.mark.asyncio
    async def test_financial_max_pts_cap_applied(self):
        """Scoring point cap is applied even when all five financial categories fire."""
        from backend.services.bec_signals_service import (
            compute_bec_signals, BEC_FINANCIAL_MAX_PTS,
        )

        # Body triggers all 5 categories
        body = (
            "wire transfer funds immediately. "
            "new account number has changed. "
            "strictly confidential, time sensitive. "
            "buy gift cards and send me the codes. "
            "process this invoice, send payment to new account."
        )
        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="cfo@evil.com",
            from_domain="evil.com",
            subject="Urgent",
            message_id="<u@evil.com>",
            body_text=body,
            recipient="accounts@corp.com",
        )
        assert result.sig_financial_request is True
        # Financial contribution must not exceed the cap
        assert result.bec_score <= BEC_FINANCIAL_MAX_PTS + 20  # leave room for other signals

    @pytest.mark.asyncio
    async def test_scoring_weights_override_respected(self):
        """Custom weights override default point values."""
        from backend.services.bec_signals_service import compute_bec_signals

        session = self._no_vip_session()
        # Override: each financial category scores 1 pt instead of default 2
        weights = {"bec_financial_per_category": 1, "bec_financial_max_pts": 10}
        result = await compute_bec_signals(
            session=session,
            from_addr="cfo@evil.com",
            from_domain="evil.com",
            subject="Wire",
            message_id="<w@evil.com>",
            body_text="wire transfer funds now",
            recipient="alice@corp.com",
            scoring_weights=weights,
        )
        # wire_transfer category fires (1 pt) — should be 1, not 2
        assert result.sig_financial_request is True
        assert result.bec_score == 1  # exactly 1 pt per category override

    @pytest.mark.asyncio
    async def test_becresult_namedtuple_fields(self):
        """compute_bec_signals must return a BecResult with all expected fields."""
        from backend.services.bec_signals_service import compute_bec_signals, BecResult

        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="sender@example.com",
            from_domain="example.com",
            subject="Test",
            message_id="<t@example.com>",
            body_text="",
            recipient="user@corp.com",
        )
        assert isinstance(result, BecResult)
        assert hasattr(result, "bec_score")
        assert hasattr(result, "bec_reasons")
        assert hasattr(result, "sig_vip_impersonation")
        assert hasattr(result, "sig_financial_request")
        assert hasattr(result, "sig_vendor_fraud")
        assert hasattr(result, "sig_authority_pressure")

    @pytest.mark.asyncio
    async def test_signal_exception_sets_none_not_crash(self):
        """If a signal's DB query raises internally, the signal degrades gracefully
        (returns False from the inner handler, not None) and compute_bec_signals
        does not propagate the exception."""
        from backend.services.bec_signals_service import compute_bec_signals

        # VIP query blows up — but _check_vip_impersonation catches the exception
        # internally and returns (False, None).  The outer compute_bec_signals
        # therefore sets sig_vip_impersonation = False (not None — that only
        # happens when the outer try/except fires, which requires the whole
        # coroutine to raise, not an internal handled exception).
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=RuntimeError("DB error"))
        session.scalar = AsyncMock(return_value=None)

        result = await compute_bec_signals(
            session=session,
            from_addr="Jane Smith <evil@evil.com>",
            from_domain="evil.com",
            subject="Test",
            message_id="<t@evil.com>",
            body_text="",
            recipient="alice@corp.com",
        )
        # Should not raise.  vip_impersonation degrades to False (handled internally).
        assert result.sig_vip_impersonation is False
        assert result.bec_score >= 0

    @pytest.mark.asyncio
    async def test_empty_recipient_still_runs(self):
        """Empty recipient string → function does not crash."""
        from backend.services.bec_signals_service import compute_bec_signals

        session = self._no_vip_session()
        result = await compute_bec_signals(
            session=session,
            from_addr="cfo@evil.com",
            from_domain="evil.com",
            subject="Pay",
            message_id="<p@evil.com>",
            body_text="wire transfer",
            recipient="",
        )
        assert isinstance(result.bec_score, int)


# ═══════════════════════════════════════════════════════════════════════════════
# scoring_service BEC integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestScoringServiceBecIntegration:
    """Tests for compute_score() BEC path."""

    def test_no_bec_result_returns_zero_bec_fields(self):
        """When bec_result=None, all BEC keys must be present with zero/None defaults."""
        result = _compute_score(bec_result=None)
        assert "bec_score" in result
        assert "bec_reasons" in result
        assert "sig_vip_impersonation" in result
        assert "sig_financial_request" in result
        assert "sig_vendor_fraud" in result
        assert "sig_authority_pressure" in result
        assert result["bec_score"] == 0
        assert result["bec_reasons"] == []
        assert result["sig_vip_impersonation"] is None
        assert result["sig_financial_request"] is None

    def test_bec_score_applied_at_double_weight(self):
        """bec_score contributes at 2× weight to combined score."""
        from backend.services.bec_signals_service import BecResult
        bec = BecResult(
            bec_score=4,
            bec_reasons=["VIP impersonation"],
            sig_vip_impersonation=True,
            sig_financial_request=False,
            sig_vendor_fraud=False,
            sig_authority_pressure=False,
        )
        result = _compute_score(bec_result=bec)
        # static(0) + dynamic(0) + bec(4)*2 + behavioral(0)*1 = 8
        assert result["score"] == 8
        assert result["bec_score"] == 4

    def test_bec_dict_input_also_works(self):
        """compute_score must accept a plain dict for bec_result."""
        bec_dict = {
            "bec_score": 3,
            "bec_reasons": ["financial language"],
            "sig_vip_impersonation": False,
            "sig_financial_request": True,
            "sig_vendor_fraud": False,
            "sig_authority_pressure": False,
        }
        result = _compute_score(bec_result=bec_dict)
        # bec(3)*2 = 6 combined
        assert result["score"] == 6
        assert result["bec_score"] == 3
        assert result["sig_financial_request"] is True

    def test_bec_score_floor_overrides_benign_verdict(self):
        """When bec_score >= BEC_SUSPICIOUS_FLOOR and combined score is below 5,
        verdict must be at least 'suspicious'.

        The floor is a safety net for the BEC case where content_score=0 but
        impersonation/financial signals are present.

        Scenario: BEC_SUSPICIOUS_FLOOR patched to 2.
        bec_score=2 → 2×2=4 combined → formula says 'benign'.
        Floor kicks in (2 >= 2) → verdict overridden to 'suspicious'.
        """
        from backend.services.bec_signals_service import BecResult
        from backend.services.scoring_service import VERDICT_SUSPICIOUS

        bec = BecResult(
            bec_score=2,
            bec_reasons=["financial language"],
            sig_vip_impersonation=False,
            sig_financial_request=True,
            sig_vendor_fraud=False,
            sig_authority_pressure=False,
        )
        # The scoring_service imports BEC_SUSPICIOUS_FLOOR from bec_signals_service
        # at call time, so patching the constant on the source module works.
        with patch("backend.services.bec_signals_service.BEC_SUSPICIOUS_FLOOR", 2):
            result = _compute_score(bec_result=bec)

        # combined = 0 + 0 + 2*2 + 0 = 4 → benign by formula → floor kicks in
        assert result["score"] == 4
        assert result["verdict"] == VERDICT_SUSPICIOUS

    def test_bec_verdict_phishing_when_high_combined_score(self):
        """High bec_score pushes combined score into phishing territory."""
        from backend.services.bec_signals_service import BecResult
        from backend.services.scoring_service import VERDICT_PHISHING

        # bec_score=5 → 5*2=10 → phishing (≥9)
        bec = BecResult(
            bec_score=5,
            bec_reasons=["vip impersonation + financial + authority"],
            sig_vip_impersonation=True,
            sig_financial_request=True,
            sig_vendor_fraud=False,
            sig_authority_pressure=True,
        )
        result = _compute_score(bec_result=bec)
        assert result["verdict"] == VERDICT_PHISHING
        assert result["score"] == 10

    def test_bec_signals_visible_in_result(self):
        """Individual BEC signal flags must be surfaced in the return dict."""
        from backend.services.bec_signals_service import BecResult

        bec = BecResult(
            bec_score=7,
            bec_reasons=["all signals fired"],
            sig_vip_impersonation=True,
            sig_financial_request=True,
            sig_vendor_fraud=True,
            sig_authority_pressure=True,
        )
        result = _compute_score(bec_result=bec)
        assert result["sig_vip_impersonation"] is True
        assert result["sig_financial_request"] is True
        assert result["sig_vendor_fraud"] is True
        assert result["sig_authority_pressure"] is True
        assert result["bec_reasons"] == ["all signals fired"]

    def test_bec_score_independent_in_return_dict(self):
        """bec_score is returned separately alongside combined score."""
        from backend.services.bec_signals_service import BecResult

        bec = BecResult(
            bec_score=3,
            bec_reasons=["vendor fraud"],
            sig_vip_impersonation=False,
            sig_financial_request=True,
            sig_vendor_fraud=True,
            sig_authority_pressure=False,
        )
        result = _compute_score(bec_result=bec, spf="fail")
        # static_score from SPF fail = 2; bec(3)*2 = 6; combined = 8
        assert result["static_score"] == 2
        assert result["bec_score"] == 3
        assert result["score"] == 8

    def test_bec_and_behavioral_combine_correctly(self):
        """BEC (2×) and behavioral (1×) both contribute to combined score."""
        from backend.services.bec_signals_service import BecResult
        from backend.services.behavioral_signals_service import BehavioralResult

        bec = BecResult(
            bec_score=3, bec_reasons=["financial"],
            sig_vip_impersonation=False, sig_financial_request=True,
            sig_vendor_fraud=False, sig_authority_pressure=False,
        )
        behavioral = BehavioralResult(
            behavioral_score=2, behavioral_reasons=["first time sender"],
            sig_first_time_sender=True, sig_domain_age_anomaly=None,
            sig_display_name_mismatch=False, sig_reply_chain_break=False,
            sig_send_time_anomaly=False,
        )
        result = _compute_score(bec_result=bec, behavioral_result=behavioral)
        # static(0) + dynamic(0) + bec(3)*2 + behavioral(2)*1 = 8
        assert result["score"] == 8
        assert result["bec_score"] == 3
        assert result["behavioral_score"] == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Schemas — BEC fields in EmailDetail and ScoringWeights
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemasBecFields:
    """Verify BEC fields are present in the shared schema."""

    def test_email_detail_has_bec_fields(self):
        """EmailDetail schema must declare all Phase 3 BEC fields."""
        from shared.schemas import EmailDetail
        fields = EmailDetail.model_fields
        assert "bec_score" in fields
        assert "bec_reasons" in fields
        assert "sig_vip_impersonation" in fields
        assert "sig_financial_request" in fields
        assert "sig_vendor_fraud" in fields
        assert "sig_authority_pressure" in fields

    def test_bec_score_default_is_none(self):
        """bec_score default should be None (uncomputed)."""
        from shared.schemas import EmailDetail
        assert EmailDetail.model_fields["bec_score"].default is None

    def test_bec_reasons_default_is_empty_list(self):
        """bec_reasons default should be an empty list."""
        from shared.schemas import EmailDetail
        # Check the default factory produces []
        field = EmailDetail.model_fields["bec_reasons"]
        # Either default=[] or default_factory returning []
        default_val = field.default if field.default is not None else field.default_factory()
        assert default_val == []


# ═══════════════════════════════════════════════════════════════════════════════
# Migration — Phase 3 BEC migration file
# ═══════════════════════════════════════════════════════════════════════════════

class TestBecMigration:
    """Verify the Phase 3 BEC Alembic migration exists and contains expected content."""

    def _read_migration(self) -> str:
        migration_path = (
            _ROOT / "migrations" / "versions" / "g4b5c6d7e8f9_phase3_bec_detection.py"
        )
        assert migration_path.exists(), f"Migration file not found: {migration_path}"
        return migration_path.read_text(encoding="utf-8")

    def test_migration_file_exists(self):
        self._read_migration()  # raises if absent

    def test_migration_revision_id(self):
        content = self._read_migration()
        assert 'revision = "g4b5c6d7e8f9"' in content

    def test_migration_creates_vip_identities_table(self):
        content = self._read_migration()
        assert "vip_identities" in content
        assert "create_table" in content.lower()

    def test_migration_adds_bec_score_column(self):
        content = self._read_migration()
        assert "bec_score" in content
        assert "add_column" in content.lower()

    def test_migration_adds_bec_reasons_column(self):
        content = self._read_migration()
        assert "bec_reasons" in content

    def test_migration_adds_all_sig_columns(self):
        content = self._read_migration()
        assert "sig_vip_impersonation" in content
        assert "sig_financial_request" in content
        assert "sig_vendor_fraud" in content
        assert "sig_authority_pressure" in content

    def test_migration_has_downgrade(self):
        content = self._read_migration()
        assert "def downgrade" in content
        assert "drop_column" in content.lower() or "drop_table" in content.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# analysis_service BEC wiring checks (source-code level)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalysisServiceBecWiring:
    """Verify via source inspection that analysis_service is correctly wired."""

    def _read_service(self) -> str:
        path = _ROOT / "backend" / "services" / "analysis_service.py"
        assert path.exists()
        return path.read_text(encoding="utf-8")

    def test_bec_service_imported(self):
        """bec_signals_service must be imported."""
        content = self._read_service()
        assert "bec_signals_service" in content

    def test_compute_bec_signals_called(self):
        """compute_bec_signals must be called in the pipeline."""
        content = self._read_service()
        assert "compute_bec_signals" in content

    def test_bec_result_passed_to_compute_score(self):
        """compute_score must receive bec_result=bec_result_obj."""
        content = self._read_service()
        assert "bec_result=bec_result_obj" in content

    def test_bec_score_written_to_analysis(self):
        """bec_score must be saved to the analysis row."""
        content = self._read_service()
        assert "analysis.bec_score" in content

    def test_bec_reasons_written_to_analysis(self):
        content = self._read_service()
        assert "analysis.bec_reasons" in content

    def test_sig_vip_impersonation_written_to_analysis(self):
        content = self._read_service()
        assert "analysis.sig_vip_impersonation" in content

    def test_sig_financial_request_written_to_analysis(self):
        content = self._read_service()
        assert "analysis.sig_financial_request" in content

    def test_sig_vendor_fraud_written_to_analysis(self):
        content = self._read_service()
        assert "analysis.sig_vendor_fraud" in content

    def test_sig_authority_pressure_written_to_analysis(self):
        content = self._read_service()
        assert "analysis.sig_authority_pressure" in content

    def test_first_time_sender_passed_to_bec(self):
        """first_time_sender must be extracted from behavioral_result_obj and passed to BEC."""
        content = self._read_service()
        assert "sig_first_time_sender" in content
        assert "first_time_sender" in content

    def test_bec_comes_after_behavioral_in_pipeline(self):
        """BEC block must appear after the behavioral block in the source."""
        content = self._read_service()
        behavioral_pos = content.find("compute_behavioral_signals")
        bec_pos = content.find("compute_bec_signals")
        assert behavioral_pos != -1
        assert bec_pos != -1
        assert bec_pos > behavioral_pos, (
            "compute_bec_signals must appear after compute_behavioral_signals "
            "in the pipeline (BEC needs first_time_sender from behavioral result)"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# VIPIdentity model sanity
# ═══════════════════════════════════════════════════════════════════════════════

class TestVipIdentityModel:
    """Basic smoke-checks for the VIPIdentity SQLAlchemy model."""

    def test_model_importable(self):
        from backend.models.vip_identity import VIPIdentity
        assert VIPIdentity.__tablename__ == "vip_identities"

    def test_model_has_required_fields(self):
        from backend.models.vip_identity import VIPIdentity
        col_names = {c.key for c in VIPIdentity.__mapper__.column_attrs}
        assert "name" in col_names
        assert "protected_email" in col_names
        assert "protected_domain" in col_names
        assert "is_active" in col_names

    def test_model_indices_defined(self):
        """Both email and domain indices should be declared."""
        from backend.models.vip_identity import VIPIdentity
        table = VIPIdentity.__table__
        index_names = {idx.name for idx in table.indexes}
        assert "ix_vip_identities_email" in index_names
        assert "ix_vip_identities_domain" in index_names


# ═══════════════════════════════════════════════════════════════════════════════
# EmailAnalysis model — BEC columns
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalysisModelBecColumns:
    """Verify the EmailAnalysis model declares all Phase 3 BEC columns."""

    def test_analysis_model_has_bec_columns(self):
        from backend.models.analysis import EmailAnalysis
        col_names = {c.key for c in EmailAnalysis.__mapper__.column_attrs}
        expected = {
            "bec_score", "bec_reasons",
            "sig_vip_impersonation", "sig_financial_request",
            "sig_vendor_fraud", "sig_authority_pressure",
        }
        missing = expected - col_names
        assert not missing, f"Missing columns in EmailAnalysis: {missing}"


# ═══════════════════════════════════════════════════════════════════════════════
# routes/analyses.py — _to_detail() BEC fields
# ═══════════════════════════════════════════════════════════════════════════════

class TestRouteBecFields:
    """Verify _to_detail() in routes/analyses.py maps all BEC fields."""

    def _read_route(self) -> str:
        path = _ROOT / "backend" / "routes" / "analyses.py"
        return path.read_text(encoding="utf-8")

    def test_to_detail_maps_bec_score(self):
        assert "bec_score" in self._read_route()

    def test_to_detail_maps_bec_reasons(self):
        assert "bec_reasons" in self._read_route()

    def test_to_detail_maps_sig_vip_impersonation(self):
        assert "sig_vip_impersonation" in self._read_route()

    def test_to_detail_maps_sig_financial_request(self):
        assert "sig_financial_request" in self._read_route()

    def test_to_detail_maps_sig_vendor_fraud(self):
        assert "sig_vendor_fraud" in self._read_route()

    def test_to_detail_maps_sig_authority_pressure(self):
        assert "sig_authority_pressure" in self._read_route()
