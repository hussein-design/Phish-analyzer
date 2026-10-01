"""Phase 2 behavioral analysis tests.

Covers:
  - behavioral_signals_service.py — all 5 signals, cold-start behaviour,
    edge cases, and record_observation() history update logic
  - scoring_service.compute_score() — behavioral_result integration,
    independence from static/dynamic score, correct return keys

All tests are self-contained.  No real network calls, no real DB state:
  - DB interactions are replaced with AsyncMock sessions that return
    controlled data.
  - RDAP/WHOIS HTTP calls are patched via unittest.mock.patch.
  - The enrichment_cache singleton is patched to return None (cache miss)
    and have a no-op set(), so tests don't touch the SQLite file.

Run with:
    pip install pytest pytest-asyncio
    pytest tests/test_phase2_behavioral_analysis.py -v
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc(year=2024, month=6, day=1, hour=10) -> datetime:
    return datetime(year, month, day, hour, 0, 0, tzinfo=timezone.utc)


def _make_session(
    sender_history_row=None,
    any_history_row=None,
    thread_rows=None,
    send_hours=None,
) -> AsyncMock:
    """Build a minimal async SQLAlchemy session mock.

    scalar() is used for single-value queries; execute() for multi-row queries.
    We use side_effect lists so multiple calls within one test return different
    values in the order they're expected.
    """
    session = AsyncMock()

    # scalar() call sequence:
    #   1st call: any_history_row (cold-start guard for first_time_sender)
    #   2nd call: sender_history_row (specific sender check)
    #   3rd call: send_hours (get_send_hour_history)
    scalar_side_effects = [
        any_history_row,    # check for any recipient history
        sender_history_row, # check for this specific sender
        send_hours,         # send_hours list
    ]
    session.scalar = AsyncMock(side_effect=scalar_side_effects)

    # execute() is used for thread_history multi-row queries
    result_mock = MagicMock()
    if thread_rows is not None:
        result_mock.all.return_value = thread_rows
    else:
        result_mock.all.return_value = []
    session.execute = AsyncMock(return_value=result_mock)

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


# ── normalize helpers ─────────────────────────────────────────────────────────

class TestNormalizeHelpers:
    def test_normalize_addr_bare(self):
        from backend.services.behavioral_signals_service import _normalize_addr
        assert _normalize_addr("user@example.com") == "user@example.com"

    def test_normalize_addr_with_display_name(self):
        from backend.services.behavioral_signals_service import _normalize_addr
        assert _normalize_addr("Display Name <User@Example.COM>") == "user@example.com"

    def test_normalize_addr_empty(self):
        from backend.services.behavioral_signals_service import _normalize_addr
        assert _normalize_addr(None) == ""
        assert _normalize_addr("") == ""

    def test_normalize_thread_key_strips_re(self):
        from backend.services.behavioral_signals_service import _normalize_thread_key
        assert _normalize_thread_key("Re: Invoice #123") == "invoice #123"

    def test_normalize_thread_key_strips_fwd(self):
        from backend.services.behavioral_signals_service import _normalize_thread_key
        assert _normalize_thread_key("Fwd: Meeting Notes") == "meeting notes"

    def test_normalize_thread_key_chained_prefixes(self):
        from backend.services.behavioral_signals_service import _normalize_thread_key
        assert _normalize_thread_key("Re: Re: Fwd: Status Update") == "status update"

    def test_normalize_thread_key_no_prefix(self):
        from backend.services.behavioral_signals_service import _normalize_thread_key
        assert _normalize_thread_key("Project Kickoff") == "project kickoff"

    def test_is_reply_or_forward_true(self):
        from backend.services.behavioral_signals_service import _is_reply_or_forward
        assert _is_reply_or_forward("Re: hello") is True
        assert _is_reply_or_forward("Fwd: hello") is True
        assert _is_reply_or_forward("FW: hello") is True

    def test_is_reply_or_forward_false(self):
        from backend.services.behavioral_signals_service import _is_reply_or_forward
        assert _is_reply_or_forward("New invoice attached") is False
        assert _is_reply_or_forward(None) is False


# ── Signal 1: first_time_sender ───────────────────────────────────────────────

class TestFirstTimeSender:
    @pytest.mark.asyncio
    async def test_cold_start_returns_false(self):
        """When the recipient has NO prior history, first_time_sender must return False
        (cold-start guard — not enough data to distinguish new sender from new mailbox)."""
        from backend.services.behavioral_signals_service import _check_first_time_sender

        # scalar side_effects: [any_history=None, specific_sender=None]
        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=[None, None])

        result = await _check_first_time_sender(session, "alice@corp.com", "bob@external.com")
        assert result is False

    @pytest.mark.asyncio
    async def test_known_sender_returns_false(self):
        """Sender already in history → signal must NOT fire."""
        from backend.services.behavioral_signals_service import _check_first_time_sender

        # any_history_row = 1 (some history exists), sender_row = 5 (this sender known)
        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=[1, 5])

        result = await _check_first_time_sender(session, "alice@corp.com", "bob@external.com")
        assert result is False

    @pytest.mark.asyncio
    async def test_new_sender_with_existing_history_returns_true(self):
        """Recipient has history for OTHER senders but this sender is new → signal fires."""
        from backend.services.behavioral_signals_service import _check_first_time_sender

        # any_history_row = 42 (recipient has history), sender_row = None (this sender new)
        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=[42, None])

        result = await _check_first_time_sender(session, "alice@corp.com", "badactor@evil.com")
        assert result is True


# ── Signal 2: domain_age_anomaly ──────────────────────────────────────────────

class TestDomainAgeAnomaly:
    @pytest.mark.asyncio
    async def test_new_domain_fires(self):
        """Domain registered 5 days before email → should fire."""
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        email_date = _utc(2024, 6, 15)
        reg_date = _utc(2024, 6, 10)  # 5 days old

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=reg_date),
        ):
            result = await _check_domain_age_anomaly("evil.com", email_date, threshold_days=30)

        assert result is True

    @pytest.mark.asyncio
    async def test_old_domain_does_not_fire(self):
        """Domain registered 2 years before email → should not fire."""
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        email_date = _utc(2024, 6, 15)
        reg_date = _utc(2022, 1, 1)  # 2+ years old

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=reg_date),
        ):
            result = await _check_domain_age_anomaly("legit.com", email_date, threshold_days=30)

        assert result is False

    @pytest.mark.asyncio
    async def test_lookup_failure_returns_none(self):
        """RDAP/WHOIS lookup failure → signal returns None (undetermined, not False)."""
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=None),
        ):
            result = await _check_domain_age_anomaly("unknown.xyz", _utc(), threshold_days=30)

        assert result is None

    @pytest.mark.asyncio
    async def test_no_domain_returns_none(self):
        """No domain provided → None (cannot check age of nothing)."""
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        result = await _check_domain_age_anomaly(None, _utc(), threshold_days=30)
        assert result is None

    @pytest.mark.asyncio
    async def test_domain_registered_exactly_on_threshold_does_not_fire(self):
        """Domain registered exactly threshold_days old → should NOT fire (boundary)."""
        from backend.services.behavioral_signals_service import _check_domain_age_anomaly

        email_date = _utc(2024, 6, 30)
        reg_date = _utc(2024, 5, 31)  # exactly 30 days old

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=reg_date),
        ):
            result = await _check_domain_age_anomaly("borderline.com", email_date, threshold_days=30)

        # age_days = 30, which is NOT < 30, so signal should not fire
        assert result is False

    @pytest.mark.asyncio
    async def test_uses_enrichment_cache(self):
        """Cache hit returns stored value without calling RDAP."""
        from backend.services.behavioral_signals_service import _lookup_domain_registration_date

        reg_date = _utc(2024, 6, 10)

        # enrichment_cache is imported inside _lookup_domain_registration_date
        # so we must patch it at its source module location.
        with patch(
            "backend.services.enrichment.cache.EnrichmentCache.get",
            new=AsyncMock(return_value=reg_date.isoformat()),
        ), patch(
            "backend.services.enrichment.cache.EnrichmentCache.set",
            new=AsyncMock(),
        ):
            result = await _lookup_domain_registration_date("cached.com")

        assert result == reg_date

    @pytest.mark.asyncio
    async def test_cache_not_found_sentinel(self):
        """Cache 'not_found' sentinel → returns None without hitting RDAP."""
        from backend.services.behavioral_signals_service import _lookup_domain_registration_date

        with patch(
            "backend.services.enrichment.cache.EnrichmentCache.get",
            new=AsyncMock(return_value="not_found"),
        ), patch(
            "backend.services.enrichment.cache.EnrichmentCache.set",
            new=AsyncMock(),
        ):
            result = await _lookup_domain_registration_date("notfound.com")

        assert result is None


# ── Signal 3: display_name_mismatch ──────────────────────────────────────────

class TestDisplayNameMismatch:
    def _brand_domains(self) -> dict:
        return {
            "PayPal": ["paypal.com"],
            "Microsoft": ["microsoft.com", "microsoftonline.com"],
        }

    def test_brand_in_display_wrong_domain_fires(self):
        from backend.services.behavioral_signals_service import _check_display_name_mismatch
        result = _check_display_name_mismatch(
            from_addr="PayPal Support <noreply@evil-payments.com>",
            from_domain="evil-payments.com",
            brand_domains=self._brand_domains(),
        )
        assert result is True

    def test_legit_domain_does_not_fire(self):
        from backend.services.behavioral_signals_service import _check_display_name_mismatch
        result = _check_display_name_mismatch(
            from_addr="PayPal <service@paypal.com>",
            from_domain="paypal.com",
            brand_domains=self._brand_domains(),
        )
        assert result is False

    def test_lookalike_domain_fires(self):
        """Typosquat microsott.com should fire even without brand name in display."""
        from backend.services.behavioral_signals_service import _check_display_name_mismatch
        result = _check_display_name_mismatch(
            from_addr="IT Support <admin@microsott.com>",
            from_domain="microsott.com",
            brand_domains=self._brand_domains(),
            lookalike_threshold=82,
        )
        assert result is True

    def test_no_brand_domain_config_does_not_fire(self):
        from backend.services.behavioral_signals_service import _check_display_name_mismatch
        result = _check_display_name_mismatch(
            from_addr="Generic Sender <user@some-random-domain.com>",
            from_domain="some-random-domain.com",
            brand_domains={},
        )
        assert result is False

    def test_no_from_addr_returns_false(self):
        from backend.services.behavioral_signals_service import _check_display_name_mismatch
        result = _check_display_name_mismatch(
            from_addr=None,
            from_domain=None,
            brand_domains=self._brand_domains(),
        )
        assert result is False


# ── Signal 4: reply_chain_break ───────────────────────────────────────────────

class TestReplyChainBreak:
    @pytest.mark.asyncio
    async def test_non_reply_subject_returns_false(self):
        """A subject without Re:/Fwd: → signal must not fire regardless of history."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        session = AsyncMock()
        result = await _check_reply_chain_break(
            session,
            recipient="alice@corp.com",
            sender="bob@evil.com",
            subject="Invoice attached",
            message_id="<abc123@evil.com>",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_reply_no_thread_history_returns_false(self):
        """Reply subject, but NO thread history exists → neutral (not enough data)."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        result_mock = MagicMock()
        result_mock.all.return_value = []
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        result = await _check_reply_chain_break(
            session,
            recipient="alice@corp.com",
            sender="bob@evil.com",
            subject="Re: Project Update",
            message_id="<new@evil.com>",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_reply_known_sender_returns_false(self):
        """Reply from a sender already in thread history → no chain break."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "<orig@corp.com>"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="alice@corp.com",  # known sender
            subject="Re: Budget Review",
            message_id="<reply@corp.com>",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_reply_unknown_sender_fires(self):
        """Reply from an unknown sender when thread history exists → chain break fires."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "<orig@corp.com>"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="attacker@evil.com",  # NOT in thread history
            subject="Re: Budget Review",
            message_id="<hijack@evil.com>",
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_fwd_prefix_also_triggers_check(self):
        """Fwd: prefix is also treated as a reply chain check."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "<orig@corp.com>"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="attacker@evil.com",
            subject="Fwd: Budget Review",
            message_id="<fwd-hijack@evil.com>",
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_in_reply_to_match_suppresses_signal(self):
        """Unknown sender BUT In-Reply-To matches a known message_id → legitimate
        continuation, signal must NOT fire (tiebreaker suppression)."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "orig-message-id@corp.com"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        # attacker@evil.com is NOT a known sender in this thread,
        # but their In-Reply-To references a known message_id → suppress.
        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="newparticipant@partner.com",
            subject="Re: Budget Review",
            message_id="<new-reply@partner.com>",
            in_reply_to="orig-message-id@corp.com",  # matches known_row.message_id
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_in_reply_to_mismatch_still_fires(self):
        """Unknown sender AND In-Reply-To does NOT match any known message_id → fires."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "orig-message-id@corp.com"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="attacker@evil.com",
            subject="Re: Budget Review",
            message_id="<hijack@evil.com>",
            in_reply_to="some-unrelated-id@evil.com",  # not in known_message_ids
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_in_reply_to_none_falls_back_to_sender_check(self):
        """When In-Reply-To is absent, signal falls back to sender-only check (existing behavior)."""
        from backend.services.behavioral_signals_service import _check_reply_chain_break

        known_row = MagicMock()
        known_row.sender = "alice@corp.com"
        known_row.message_id = "orig-message-id@corp.com"

        result_mock = MagicMock()
        result_mock.all.return_value = [known_row]
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result_mock)

        # No In-Reply-To → sender check only → attacker fires
        result = await _check_reply_chain_break(
            session,
            recipient="carol@corp.com",
            sender="attacker@evil.com",
            subject="Re: Budget Review",
            message_id="<hijack@evil.com>",
            in_reply_to=None,
        )
        assert result is True


# ── Signal 5: send_time_anomaly ───────────────────────────────────────────────

class TestSendTimeAnomaly:
    def test_below_min_history_returns_false(self):
        """Below the minimum sample size → neutral (cold start for this signal)."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=3,
            historical_hours=[10, 11, 9],  # only 3, min is 5
            min_history=5,
            tolerance=2,
        )
        assert result is False

    def test_within_tolerance_returns_false(self):
        """Send hour within ±2h of a historical hour → normal."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=11,
            historical_hours=[10, 10, 10, 10, 10],  # consistently 10:00 UTC
            min_history=5,
            tolerance=2,
        )
        assert result is False

    def test_outside_tolerance_fires(self):
        """Send hour far outside all historical hours → anomaly fires."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=3,   # 3:00 AM UTC — way outside the 9-5 pattern
            historical_hours=[10, 11, 9, 10, 10],
            min_history=5,
            tolerance=2,
        )
        assert result is True

    def test_midnight_wraparound_not_flagged(self):
        """23:00 and 01:00 are only 2 hours apart — wraparound must work correctly."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=1,
            historical_hours=[23, 23, 23, 23, 23],  # always sends around midnight
            min_history=5,
            tolerance=2,
        )
        assert result is False

    def test_none_send_hour_returns_false(self):
        """No send hour (Date header missing) → neutral."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=None,
            historical_hours=[10, 10, 10, 10, 10],
            min_history=5,
            tolerance=2,
        )
        assert result is False

    def test_zero_tolerance_exact_match(self):
        """Tolerance=0 requires exact hour match."""
        from backend.services.behavioral_signals_service import _check_send_time_anomaly

        result = _check_send_time_anomaly(
            send_hour=11,
            historical_hours=[10, 10, 10, 10, 10],
            min_history=5,
            tolerance=0,
        )
        assert result is True  # 11 != 10 with zero tolerance

        result2 = _check_send_time_anomaly(
            send_hour=10,
            historical_hours=[10, 10, 10, 10, 10],
            min_history=5,
            tolerance=0,
        )
        assert result2 is False  # exact match


# ── compute_behavioral_signals() integration ─────────────────────────────────

class TestComputeBehavioralSignals:
    @pytest.mark.asyncio
    async def test_all_signals_false_on_cold_start(self):
        """Cold start (no history) → all history-dependent signals False, not True."""
        from backend.services.behavioral_signals_service import compute_behavioral_signals

        # Cold start: scalar always returns None
        session = AsyncMock()
        session.scalar = AsyncMock(return_value=None)
        result_mock = MagicMock()
        result_mock.all.return_value = []
        session.execute = AsyncMock(return_value=result_mock)

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=None),
        ):
            result = await compute_behavioral_signals(
                session=session,
                from_addr="sender@newdomain.com",
                from_domain="newdomain.com",
                subject="Hello",
                message_id="<abc@newdomain.com>",
                email_date=_utc(),
                recipient="alice@corp.com",
                brand_domains={},
            )

        assert result.sig_first_time_sender is False     # cold start guard
        assert result.sig_reply_chain_break is False     # no thread history
        assert result.sig_send_time_anomaly is False     # below min history
        assert result.sig_domain_age_anomaly is None     # lookup returned None
        assert result.behavioral_score == 0

    @pytest.mark.asyncio
    async def test_first_time_sender_contributes_score(self):
        """When first_time_sender fires, behavioral_score must be > 0."""
        from backend.services.behavioral_signals_service import compute_behavioral_signals

        # any_history=1 (mailbox has data), sender=None (new sender), send_hours=[]
        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=[1, None, []])
        result_mock = MagicMock()
        result_mock.all.return_value = []
        session.execute = AsyncMock(return_value=result_mock)

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=None),
        ):
            result = await compute_behavioral_signals(
                session=session,
                from_addr="newguy@external.com",
                from_domain="external.com",
                subject="Hello",
                message_id="<new@external.com>",
                email_date=_utc(),
                recipient="alice@corp.com",
                brand_domains={},
            )

        assert result.sig_first_time_sender is True
        assert result.behavioral_score >= 1
        assert len(result.behavioral_reasons) >= 1

    @pytest.mark.asyncio
    async def test_domain_age_anomaly_contributes_score(self):
        """New domain (5 days old) → behavioral_score reflects domain_age_anomaly."""
        from backend.services.behavioral_signals_service import compute_behavioral_signals

        email_date = _utc(2024, 6, 15)
        reg_date = _utc(2024, 6, 10)

        # Cold start for history signals
        session = AsyncMock()
        session.scalar = AsyncMock(return_value=None)
        result_mock = MagicMock()
        result_mock.all.return_value = []
        session.execute = AsyncMock(return_value=result_mock)

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=reg_date),
        ):
            result = await compute_behavioral_signals(
                session=session,
                from_addr="attacker@newdomain.com",
                from_domain="newdomain.com",
                subject="Urgent invoice",
                message_id="<x@newdomain.com>",
                email_date=email_date,
                recipient="victim@corp.com",
                brand_domains={},
            )

        assert result.sig_domain_age_anomaly is True
        assert result.behavioral_score >= 3  # domain_age default pts = 3

    @pytest.mark.asyncio
    async def test_display_name_mismatch_contributes_score(self):
        """PayPal brand in display, non-PayPal domain → display_name_mismatch fires."""
        from backend.services.behavioral_signals_service import compute_behavioral_signals

        session = AsyncMock()
        session.scalar = AsyncMock(return_value=None)
        result_mock = MagicMock()
        result_mock.all.return_value = []
        session.execute = AsyncMock(return_value=result_mock)

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=None),
        ):
            result = await compute_behavioral_signals(
                session=session,
                from_addr="PayPal Support <noreply@evil-pay.com>",
                from_domain="evil-pay.com",
                subject="Account suspended",
                message_id="<pp@evil-pay.com>",
                email_date=_utc(),
                recipient="victim@corp.com",
                brand_domains={"PayPal": ["paypal.com"]},
            )

        assert result.sig_display_name_mismatch is True
        assert result.behavioral_score >= 2  # display_name_mismatch pts = 2

    @pytest.mark.asyncio
    async def test_db_exception_returns_none_signal(self):
        """Any DB exception → affected signal returns None (undetermined), not crash."""
        from backend.services.behavioral_signals_service import compute_behavioral_signals

        session = AsyncMock()
        session.scalar = AsyncMock(side_effect=RuntimeError("DB error"))
        session.execute = AsyncMock(side_effect=RuntimeError("DB error"))

        with patch(
            "backend.services.behavioral_signals_service._lookup_domain_registration_date",
            new=AsyncMock(return_value=None),
        ):
            # Should not raise; should return a valid BehavioralResult.
            # Use a Re: subject so reply_chain_break actually calls session.execute.
            result = await compute_behavioral_signals(
                session=session,
                from_addr="someone@somewhere.com",
                from_domain="somewhere.com",
                subject="Re: Some thread that exists",  # triggers execute() call
                message_id=None,
                email_date=_utc(),
                recipient="alice@corp.com",
                brand_domains={},
            )

        # Signals that depend on DB should be None (error), not crash
        assert result.sig_first_time_sender is None
        assert result.sig_reply_chain_break is None
        assert result.sig_send_time_anomaly is None
        # behavioral_score should be 0 (no points from errored signals)
        assert result.behavioral_score == 0


# ── record_observation() ─────────────────────────────────────────────────────

class TestRecordObservation:
    @pytest.mark.asyncio
    async def test_new_sender_creates_history_row(self):
        """First observation for a (recipient, sender) pair → SenderHistory row added."""
        from backend.services.behavioral_signals_service import record_observation

        session = AsyncMock()
        # scalar returns None → no existing row
        session.scalar = AsyncMock(return_value=None)
        session.add = MagicMock()

        await record_observation(
            session=session,
            from_addr="bob@external.com",
            subject="Hello",
            message_id="<abc@external.com>",
            email_date=_utc(hour=10),
            recipient="alice@corp.com",
        )

        # session.add is called at least once (SenderHistory) and possibly
        # a second time (ThreadHistory for a non-empty thread_key).
        assert session.add.called

        # Find the SenderHistory call among all add() calls
        from backend.models.sender_history import SenderHistory
        sender_history_calls = [
            call[0][0]
            for call in session.add.call_args_list
            if isinstance(call[0][0], SenderHistory)
        ]
        assert len(sender_history_calls) == 1
        added = sender_history_calls[0]
        assert added.message_count == 1
        assert 10 in added.send_hours

    @pytest.mark.asyncio
    async def test_existing_sender_increments_count(self):
        """Subsequent observation → message_count incremented, send_hours appended."""
        from backend.services.behavioral_signals_service import record_observation
        from backend.models.sender_history import SenderHistory

        existing = SenderHistory(
            recipient="alice@corp.com",
            sender="bob@external.com",
            message_count=3,
            send_hours=[9, 10, 11],
        )

        session = AsyncMock()
        session.scalar = AsyncMock(return_value=existing)
        session.add = MagicMock()

        await record_observation(
            session=session,
            from_addr="bob@external.com",
            subject="Follow up",
            message_id="<follow@external.com>",
            email_date=_utc(hour=14),
            recipient="alice@corp.com",
        )

        assert existing.message_count == 4
        assert 14 in existing.send_hours

    @pytest.mark.asyncio
    async def test_empty_sender_is_skipped(self):
        """Missing from_addr → nothing should be written."""
        from backend.services.behavioral_signals_service import record_observation

        session = AsyncMock()
        session.add = MagicMock()

        await record_observation(
            session=session,
            from_addr=None,
            subject="Hello",
            message_id=None,
            email_date=_utc(),
            recipient="alice@corp.com",
        )

        session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_hours_capped_at_max(self):
        """send_hours list is capped at BEHAVIORAL_MAX_SEND_HOURS (FIFO drop)."""
        from backend.services.behavioral_signals_service import record_observation, MAX_SEND_HOURS
        from backend.models.sender_history import SenderHistory

        # Start with a list that's already at the cap
        existing = SenderHistory(
            recipient="alice@corp.com",
            sender="bob@external.com",
            message_count=MAX_SEND_HOURS,
            send_hours=list(range(MAX_SEND_HOURS)),  # [0, 1, 2, ..., 199]
        )

        session = AsyncMock()
        session.scalar = AsyncMock(return_value=existing)

        await record_observation(
            session=session,
            from_addr="bob@external.com",
            subject="one more",
            message_id=None,
            email_date=_utc(hour=7),
            recipient="alice@corp.com",
        )

        # Should still be at cap, not exceeding it
        assert len(existing.send_hours) == MAX_SEND_HOURS
        # New hour should be at the end; hour 0 (oldest) should be dropped
        assert existing.send_hours[-1] == 7
        assert 0 not in existing.send_hours


# ── scoring_service integration ───────────────────────────────────────────────

class TestScoringServiceBehavioralIntegration:
    def _call_compute(self, behavioral_result=None) -> dict:
        from backend.services.scoring_service import compute_score
        return compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
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
            behavioral_result=behavioral_result,
        )

    def test_no_behavioral_result_still_returns_keys(self):
        """When behavioral_result=None, all behavioral keys must be present with defaults."""
        result = self._call_compute(behavioral_result=None)

        assert "behavioral_score" in result
        assert "behavioral_reasons" in result
        assert "sig_first_time_sender" in result
        assert "sig_domain_age_anomaly" in result
        assert "sig_display_name_mismatch" in result
        assert "sig_reply_chain_break" in result
        assert "sig_send_time_anomaly" in result
        assert result["behavioral_score"] == 0
        assert result["behavioral_reasons"] == []

    def test_behavioral_score_independent_of_combined_score(self):
        """behavioral_score contributes to combined 'score' at 1× weight (Phase 3 merge).
        bec_score contributes at 2× weight — behavioral is the weaker evidence tier.
        Both are still surfaced as independent sub-scores alongside 'score'."""
        from backend.services.behavioral_signals_service import BehavioralResult

        behavioral = BehavioralResult(
            behavioral_score=5,
            behavioral_reasons=["test signal"],
            sig_first_time_sender=True,
            sig_domain_age_anomaly=None,
            sig_display_name_mismatch=False,
            sig_reply_chain_break=False,
            sig_send_time_anomaly=False,
        )
        result = self._call_compute(behavioral_result=behavioral)

        # Phase 3 merge: combined_score = static(0) + dynamic(0) + bec(0)*2 + behavioral(5)*1
        assert result["score"] == 5
        # Sub-scores still visible independently
        assert result["behavioral_score"] == 5
        assert result["static_score"] == 0
        assert result["dynamic_score"] == 0

    def test_behavioral_signals_visible_in_result(self):
        """Individual signal flags must be surfaced in the return dict."""
        from backend.services.behavioral_signals_service import BehavioralResult

        behavioral = BehavioralResult(
            behavioral_score=3,
            behavioral_reasons=["domain age anomaly"],
            sig_first_time_sender=False,
            sig_domain_age_anomaly=True,
            sig_display_name_mismatch=False,
            sig_reply_chain_break=None,
            sig_send_time_anomaly=False,
        )
        result = self._call_compute(behavioral_result=behavioral)

        assert result["sig_first_time_sender"] is False
        assert result["sig_domain_age_anomaly"] is True
        assert result["sig_display_name_mismatch"] is False
        assert result["sig_reply_chain_break"] is None
        assert result["sig_send_time_anomaly"] is False
        assert result["behavioral_reasons"] == ["domain age anomaly"]

    def test_behavioral_dict_input_also_works(self):
        """compute_score must accept a plain dict for behavioral_result, not only NamedTuple."""
        behavioral_dict = {
            "behavioral_score": 2,
            "behavioral_reasons": ["first time sender"],
            "sig_first_time_sender": True,
            "sig_domain_age_anomaly": None,
            "sig_display_name_mismatch": False,
            "sig_reply_chain_break": False,
            "sig_send_time_anomaly": False,
        }
        result = self._call_compute(behavioral_result=behavioral_dict)

        assert result["behavioral_score"] == 2
        assert result["sig_first_time_sender"] is True

    def test_existing_static_and_dynamic_scores_unchanged(self):
        """Adding behavioral_result must not change the static/dynamic calculation."""
        from backend.services.scoring_service import compute_score
        from backend.services.behavioral_signals_service import BehavioralResult

        behavioral = BehavioralResult(
            behavioral_score=5,
            behavioral_reasons=["test"],
            sig_first_time_sender=True,
            sig_domain_age_anomaly=None,
            sig_display_name_mismatch=False,
            sig_reply_chain_break=False,
            sig_send_time_anomaly=False,
        )

        # Static signal: SPF fail (2 pts)
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
            behavioral_result=behavioral,
        )

        assert result["static_score"] == 2
        assert result["dynamic_score"] == 0
        assert result["behavioral_score"] == 5
        # Phase 3 combined: static(2) + dynamic(0) + bec(0)*2 + behavioral(5)*1 = 7
        assert result["score"] == 7


# ── eml_parser helpers ────────────────────────────────────────────────────────

class TestEmlParserHelpers:
    def _make_parsed(self, date_str: str | None, to_str: str | None) -> tuple[dict, dict]:
        """Build a minimal parsed dict + headers dict for testing."""
        import email as _email

        lines = ["From: sender@example.com <sender@example.com>"]
        if date_str:
            lines.append(f"Date: {date_str}")
        if to_str:
            lines.append(f"To: {to_str}")
        lines.append("Subject: Test")
        lines.append("")
        lines.append("Body text")

        raw = "\n".join(lines).encode()
        parsed = {"_raw_email": raw}
        headers: dict = {}
        return parsed, headers

    def test_get_email_date_parses_rfc2822(self):
        from backend.services.eml_parser_service import get_email_date
        parsed, headers = self._make_parsed("Thu, 01 Jun 2023 10:30:00 +0000", None)
        result = get_email_date(parsed, headers)
        assert result is not None
        assert result.year == 2023
        assert result.month == 6
        assert result.tzinfo is not None

    def test_get_email_date_returns_none_on_missing(self):
        from backend.services.eml_parser_service import get_email_date
        parsed, headers = self._make_parsed(None, None)
        result = get_email_date(parsed, headers)
        # May return None or some value depending on email — just must not raise
        # (no Date header → None expected)
        assert result is None

    def test_get_recipient_bare_address(self):
        from backend.services.eml_parser_service import get_recipient
        parsed, headers = self._make_parsed(None, "alice@corp.com")
        result = get_recipient(parsed, headers)
        assert result == "alice@corp.com"

    def test_get_recipient_with_display_name(self):
        from backend.services.eml_parser_service import get_recipient
        parsed, headers = self._make_parsed(None, "Alice Smith <Alice@Corp.COM>")
        result = get_recipient(parsed, headers)
        assert result == "alice@corp.com"

    def test_get_recipient_no_to_header(self):
        from backend.services.eml_parser_service import get_recipient
        # Build parsed with no To header
        raw = b"From: sender@example.com\nSubject: Test\n\nBody"
        parsed = {"_raw_email": raw}
        result = get_recipient(parsed, {})
        assert result is None

    def test_get_in_reply_to_extracts_value(self):
        from backend.services.eml_parser_service import get_in_reply_to
        raw = (
            b"From: sender@example.com\n"
            b"To: alice@corp.com\n"
            b"Subject: Re: Test\n"
            b"In-Reply-To: <original-msg-id@corp.com>\n"
            b"\nBody"
        )
        parsed = {"_raw_email": raw}
        result = get_in_reply_to(parsed, {})
        # Angle brackets should be stripped
        assert result == "original-msg-id@corp.com"

    def test_get_in_reply_to_returns_none_when_absent(self):
        from backend.services.eml_parser_service import get_in_reply_to
        raw = b"From: sender@example.com\nSubject: Hello\n\nBody"
        parsed = {"_raw_email": raw}
        result = get_in_reply_to(parsed, {})
        assert result is None
