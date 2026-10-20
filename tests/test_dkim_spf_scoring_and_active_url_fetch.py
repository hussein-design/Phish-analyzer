"""Tests for Task 1 (DKIM/SPF conditional scoring) and Task 2 (active_url_fetch).

Score values changed by Task 1
──────────────────────────────
  dkim=fail+dmarc=pass : was +3 (dkim_fail+header_issue), now  0  (delta -3)
  dkim=fail+dmarc=fail : was +3 (dkim_fail+header_issue), now +2  (delta -1)
  dkim=fail+dmarc=none : was +3 (dkim_fail+header_issue), now +2  (delta -1)
  dkim=none            : was +2 (dkim_fail),              now  0  (delta -2)
  spf=fail+dmarc=pass  : was +3 (spf_fail+header_issue),  now  0  (delta -3)
  spf=fail+dmarc=fail  : was +3 (spf_fail+header_issue),  now +2  (delta -1)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _weights() -> dict:
    return {
        "brand_mismatch": 2, "spf_fail": 2, "dkim_fail": 2,
        "dmarc_fail": 2, "header_issue": 1, "url_bad_keyword": 2,
        "url_ip_host": 3, "attachment_executable": 3,
        "vt_malicious_threshold": 3, "vt_malicious_points": 4,
        "abuseipdb_high_score": 50, "abuseipdb_points": 3,
        "brand_domain_lookalike": 3, "brand_domain_lookalike_threshold": 82,
        "suspicious_tld": 2, "punycode_domain": 3, "url_shortener": 1,
        "attachment_double_extension": 4, "body_urgency_keyword": 1,
        "lure_category": 2, "anchor_mismatch": 3, "redirect_suspicious": 3,
        "macro_enabled": 4, "embedded_executable": 5,
        "mime_magic_mismatch": 3, "vt_hash_malicious_points": 5,
    }


def _compute(auth: dict, header_issues: list[str] | None = None) -> dict:
    from backend.services.scoring_service import compute_score
    return compute_score(
        from_addr="sender@example.com",
        from_domain="example.com",
        auth=auth,
        header_issues=header_issues or [],
        urls=[],
        attachments=[],
        abuse_result={},
        sender_ip=None,
        body_text="",
        scoring_weights=_weights(),
        brand_domains={},
        url_suspicious_keywords=[],
        suspicious_tlds=[],
        url_shorteners=[],
        urgency_keywords=[],
    )


def _auth(**kw) -> dict:
    base = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    base.update(kw)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: DKIM/SPF conditional scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestDkimSpfConditionalScoring:

    def test_dkim_fail_dmarc_pass_zero_points(self):
        """dkim=fail + dmarc=pass → 0 static points (informational only)."""
        r = _compute(_auth(dkim="fail", dmarc="pass"))
        assert r["static_score"] == 0, f"Got {r['static_score']}"
        reasons = r["static_reasons"]
        assert any("DMARC passed" in s for s in reasons), reasons
        assert "DKIM failed for this message" not in reasons

    def test_dkim_fail_dmarc_fail_scores_dkim_once(self):
        """dkim=fail + dmarc=fail → dkim_fail(2) + dmarc_fail(2) = 4, no dup."""
        r = _compute(_auth(dkim="fail", dmarc="fail"))
        assert r["static_score"] == 4, f"Got {r['static_score']}"
        dkim_reasons = [s for s in r["static_reasons"] if "DKIM" in s]
        assert len(dkim_reasons) == 1, dkim_reasons

    def test_dkim_fail_dmarc_none_scores(self):
        """dkim=fail + dmarc=unknown → dkim_fail(2) scored."""
        r = _compute(_auth(dkim="fail", dmarc="unknown"))
        assert r["static_score"] == 2, f"Got {r['static_score']}"
        assert "DKIM failed for this message" in r["static_reasons"]

    def test_dkim_none_is_unsigned_no_points(self):
        """dkim='none' → 0 points, no DKIM reason string."""
        r = _compute(_auth(dkim="none", dmarc="pass"))
        assert r["static_score"] == 0, f"Got {r['static_score']}"
        assert not any("DKIM" in s for s in r["static_reasons"])

    def test_spf_fail_dmarc_pass_zero_points(self):
        """spf=fail + dmarc=pass → 0 static points."""
        r = _compute(_auth(spf="fail", dmarc="pass"))
        assert r["static_score"] == 0, f"Got {r['static_score']}"
        reasons = r["static_reasons"]
        assert any("DMARC passed" in s for s in reasons), reasons

    def test_spf_fail_dmarc_fail_scores_spf_once(self):
        """spf=fail + dmarc=fail → spf_fail(2) + dmarc_fail(2) = 4, no dup."""
        r = _compute(_auth(spf="fail", dmarc="fail"))
        assert r["static_score"] == 4, f"Got {r['static_score']}"
        spf_reasons = [s for s in r["static_reasons"] if "SPF" in s]
        assert len(spf_reasons) == 1, spf_reasons

    def test_analyze_headers_no_auth_issues(self):
        """analyze_headers must not put SPF/DKIM/DMARC into issues list."""
        from unittest.mock import patch, MagicMock
        fake_msg = MagicMock()
        fake_msg.get_all.return_value = []
        with patch("email.message_from_bytes", return_value=fake_msg):
            from backend.services.eml_parser_service import analyze_headers
            with patch(
                "backend.services.eml_parser_service.extract_auth_from_raw",
                return_value=({"spf": "fail", "dkim": "fail", "dmarc": "fail"}, []),
            ):
                result = analyze_headers({"_raw_email": b"dummy"})
        for bad in ("SPF failed in Authentication-Results",
                    "DKIM failed in Authentication-Results",
                    "DMARC failed in Authentication-Results"):
            assert bad not in result["issues"], f"Should not appear: {bad!r}"

    def test_non_auth_header_issues_still_score(self):
        """Non-auth header issues still contribute header_issue points."""
        r = _compute(_auth(), header_issues=["Reply-To differs"])
        assert r["static_score"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: active_url_fetch
# ─────────────────────────────────────────────────────────────────────────────

class TestActiveUrlFetch:

    @pytest.mark.asyncio
    async def test_disabled_returns_no_data(self):
        """active_url_fetch=False → all results skipped, no redirect/page data."""
        from backend.services.url_intelligence_service import expand_urls
        results = await expand_urls(
            ["https://evil.example.com/", "http://1.2.3.4/x"],
            active_url_fetch=False,
        )
        assert len(results) == 2
        for r in results:
            assert r.is_redirect_suspicious is False
            assert r.redirect_count == 0
            assert r.page_title is None
            assert r.final_status_code is None
            assert r.error is not None

    @pytest.mark.asyncio
    async def test_disabled_makes_no_http_calls(self):
        """active_url_fetch=False → zero httpx calls."""
        from unittest.mock import patch
        from backend.services.url_intelligence_service import expand_urls
        with patch("httpx.AsyncClient") as mock_cls:
            await expand_urls(["https://evil.example.com/"], active_url_fetch=False)
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_tracking_pixel_skipped_when_enabled(self):
        """active_url_fetch=True still skips tracking pixel URLs."""
        from unittest.mock import patch
        from backend.services.url_intelligence_service import expand_urls
        pixel = "https://mail.corp.com/pixel?open=1&uid=abc"
        with patch("httpx.AsyncClient") as mock_cls:
            results = await expand_urls([pixel], active_url_fetch=True)
        mock_cls.assert_not_called()
        assert "pixel" in (results[0].error or "").lower() or \
               "tracking" in (results[0].error or "").lower()

    @pytest.mark.asyncio
    async def test_utm_tracking_skipped_when_enabled(self):
        """utm_ query params are a tracking signal — skip when active."""
        from unittest.mock import patch
        from backend.services.url_intelligence_service import expand_urls
        url = "https://news.example.com/article?utm_source=email"
        with patch("httpx.AsyncClient") as mock_cls:
            results = await expand_urls([url], active_url_fetch=True)
        mock_cls.assert_not_called()
        assert results[0].error is not None

    def test_is_tracking_pixel_patterns(self):
        """_is_tracking_pixel must match known tracking paths/params."""
        from backend.services.url_intelligence_service import _is_tracking_pixel
        assert _is_tracking_pixel("https://t.corp.com/pixel?uid=1")
        assert _is_tracking_pixel("https://mail.corp.com/open?id=x")
        assert _is_tracking_pixel("https://news.co/beacon?x=1")
        assert _is_tracking_pixel("https://x.com/track/click?id=1")
        assert not _is_tracking_pixel("https://paypal.com/signin")
        assert not _is_tracking_pixel("https://docs.google.com/spreadsheet/d/abc")

    def test_default_active_url_fetch_is_false(self):
        """expand_urls default for active_url_fetch must be False."""
        import inspect
        from backend.services.url_intelligence_service import expand_urls
        sig = inspect.signature(expand_urls)
        assert sig.parameters["active_url_fetch"].default is False

    def test_settings_read_active_url_fetch_default_false(self):
        """SettingsRead.active_url_fetch defaults to False."""
        from shared.schemas import SettingsRead
        assert SettingsRead().active_url_fetch is False

    def test_settings_update_accepts_active_url_fetch(self):
        """SettingsUpdate accepts active_url_fetch bool."""
        from shared.schemas import SettingsUpdate
        assert SettingsUpdate(active_url_fetch=True).active_url_fetch is True

    def test_migration_exists_with_downgrade(self):
        """Migration file must exist and have a downgrade."""
        path = _ROOT / "migrations" / "versions" / "j2k3l4m5n6o7_add_active_url_fetch.py"
        assert path.exists()
        src = path.read_text()
        assert 'revision = "j2k3l4m5n6o7"' in src
        assert "def downgrade" in src
        assert "drop_column" in src

    @pytest.mark.asyncio
    async def test_vt_malicious_url_skipped_when_enabled(self):
        """active_url_fetch=True + vt_malicious>0 → URL skipped, no HTTP call."""
        from unittest.mock import patch
        from backend.services.url_intelligence_service import expand_urls
        url = "https://evil.example.com/malware"
        with patch("httpx.AsyncClient") as mock_cls:
            results = await expand_urls(
                [url],
                active_url_fetch=True,
                vt_malicious_map={url: 5},
            )
        mock_cls.assert_not_called()
        assert "malicious" in (results[0].error or "").lower() or \
               "virustotal" in (results[0].error or "").lower()

    @pytest.mark.asyncio
    async def test_vt_malicious_zero_does_not_skip(self):
        """active_url_fetch=True + vt_malicious=0 → URL is attempted (may fail due to network)."""
        from unittest.mock import patch, AsyncMock, MagicMock
        from backend.services.url_intelligence_service import expand_urls
        url = "https://safe.example.com/"
        # Mock httpx to avoid real network calls
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.url = url
        mock_resp.aiter_bytes = AsyncMock(return_value=iter([b""]))
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            with patch(
                "backend.services.url_intelligence_service._is_private_host_async",
                return_value=False,
            ):
                results = await expand_urls(
                    [url],
                    active_url_fetch=True,
                    vt_malicious_map={url: 0},
                )
        # Should not have the "vt malicious" skip error
        assert "malicious" not in (results[0].error or "").lower()

    def test_settings_controller_wires_active_url_fetch(self):
        """settings_controller._save_settings must include active_url_fetch in payload."""
        path = _ROOT / "frontend" / "controllers" / "settings_controller.py"
        src = path.read_text()
        assert "active_url_fetch_payload" in src
        assert "active_url_fetch" in src
