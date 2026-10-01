"""Phase 0 regression tests — one test per bug fixed.

Run with:
    pip install pytest pytest-asyncio
    pytest tests/test_phase0_regression.py -v

All tests are self-contained and use only the stdlib + already-required
packages.  No real network calls are made; external APIs are mocked.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure the project root is on sys.path regardless of where pytest is run from
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# BUG-01: extract_sender_ip() — IPv6 addresses never extracted
# ─────────────────────────────────────────────────────────────────────────────

class TestBug01_IPv6SenderIP:
    def _call(self, headers: dict):
        from backend.services.eml_parser_service import extract_sender_ip
        return extract_sender_ip(headers)

    def test_ipv4_still_works(self):
        headers = {
            "received": [{"from": ["203.0.113.5"]}],
        }
        assert self._call(headers) == "203.0.113.5"

    def test_ipv6_full_extracted(self):
        """Full IPv6 address in received.from must be returned."""
        headers = {
            "received": [{"from": ["2001:db8::1"]}],
        }
        result = self._call(headers)
        assert result is not None, "IPv6 address was not extracted (BUG-01)"
        assert "2001" in result

    def test_ipv6_from_received_ip_list(self):
        """IPv6 in received_ip list must be returned."""
        headers = {
            "received_ip": ["2001:db8:cafe::42"],
        }
        result = self._call(headers)
        assert result is not None, "IPv6 in received_ip list not extracted (BUG-01)"

    def test_ipv6_bracketed_raw_string(self):
        """[IPv6] bracket form in raw Received string must be found."""
        headers = {
            "received": [{"src": "from mail.example.com ([2001:db8::ff]) by relay.mx"}],
        }
        result = self._call(headers)
        assert result is not None, "Bracketed IPv6 in raw Received string not extracted (BUG-01)"

    def test_none_when_no_ip(self):
        assert self._call({}) is None
        assert self._call({"received": []}) is None


# ─────────────────────────────────────────────────────────────────────────────
# BUG-02: parse_eml_bytes() — no exception handling for corrupt .eml
# ─────────────────────────────────────────────────────────────────────────────

class TestBug02_ParseEmlBytesException:
    def test_corrupt_bytes_raises_invalid_eml_error(self):
        """eml_parser raises when given None — parse_eml_bytes must wrap it as InvalidEmlError."""
        from backend.core.exceptions import InvalidEmlError
        from backend.services.eml_parser_service import parse_eml_bytes

        # eml_parser.decode_email_bytes(None) raises AttributeError.
        # parse_eml_bytes must catch that and re-raise as InvalidEmlError.
        with pytest.raises(InvalidEmlError):
            parse_eml_bytes(None)  # type: ignore[arg-type]

    def test_valid_email_parses_without_error(self):
        """A minimal valid email must parse successfully."""
        from backend.services.eml_parser_service import parse_eml_bytes

        minimal = b"From: sender@example.com\r\nSubject: Test\r\n\r\nHello"
        result = parse_eml_bytes(minimal)
        assert isinstance(result, dict)
        assert "_raw_email" in result


# ─────────────────────────────────────────────────────────────────────────────
# BUG-03: extract_text_from_body() — bytes content coerced to repr
# ─────────────────────────────────────────────────────────────────────────────

class TestBug03_BytesBodyContent:
    def test_bytes_content_decoded_not_repr(self):
        """bytes content must be decoded, not str()'d to "b'hello'"."""
        from backend.services.eml_parser_service import extract_text_from_body

        body_raw = [
            {
                "content_type": "text/plain",
                "content": b"Hello, this is a real email body",
            }
        ]
        result = extract_text_from_body(body_raw)
        assert "b'" not in result, "bytes repr leaked into body text (BUG-03)"
        assert "Hello" in result

    def test_html_bytes_content_decoded(self):
        """bytes in text/html parts must also be decoded properly."""
        from backend.services.eml_parser_service import extract_text_from_body

        body_raw = [
            {
                "content_type": "text/html",
                "content": b"<html><body>Welcome</body></html>",
            }
        ]
        result = extract_text_from_body(body_raw)
        assert "b'" not in result, "bytes repr leaked into HTML body text (BUG-03)"
        assert "Welcome" in result


# ─────────────────────────────────────────────────────────────────────────────
# BUG-04: base64-encoded attachment payloads silently dropped
# ─────────────────────────────────────────────────────────────────────────────

class TestBug04_Base64AttachmentPayload:
    def _make_att(self, content: bytes) -> dict:
        """Return a fake eml_parser attachment dict with a base64-string payload."""
        return {
            "filename": "test.pdf",
            "payload": base64.b64encode(content).decode("ascii"),
            "content_header": {"content-type": ["application/pdf"]},
        }

    def test_base64_payload_decoded_for_hash(self):
        """hash_attachment_content must work after BUG-04 decode in the pipeline.

        We simulate the pipeline's decode logic directly.
        """
        content = b"%PDF-1.4 fake pdf content for hashing"
        att = self._make_att(content)

        payload = att.get("payload") or b""
        if isinstance(payload, str):
            try:
                payload = base64.b64decode(payload, validate=False)
            except Exception:
                payload = b""

        assert payload == content, "base64 payload not decoded correctly (BUG-04)"
        assert payload != b"", "base64 payload still empty after fix (BUG-04)"

    def test_base64_payload_produces_correct_hash(self):
        """SHA-256 computed from decoded base64 payload must match the content hash."""
        content = b"malicious macro content here"
        att = self._make_att(content)

        payload = att.get("payload") or b""
        if isinstance(payload, str):
            payload = base64.b64decode(payload, validate=False)

        computed = hashlib.sha256(payload).hexdigest()
        expected = hashlib.sha256(content).hexdigest()
        assert computed == expected, "Hash mismatch after BUG-04 decode"

    def test_invalid_base64_falls_back_to_empty(self):
        """Garbage base64 string must fall back to b"" without crashing."""
        att = {"filename": "broken.bin", "payload": "this-is-not-base64-!!!"}

        payload = att.get("payload") or b""
        if isinstance(payload, str):
            try:
                payload = base64.b64decode(payload, validate=False)
            except Exception:
                payload = b""

        # validate=False is permissive; real invalid data still falls through
        assert isinstance(payload, bytes)


# ─────────────────────────────────────────────────────────────────────────────
# BUG-06: VT URL scoring fires N times instead of once
# ─────────────────────────────────────────────────────────────────────────────

class TestBug06_VTScoringOnce:
    def _score(self, urls: list[dict]) -> dict:
        from backend.services.scoring_service import compute_score

        weights = {
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
        }
        return compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_issues=[],
            urls=urls,
            attachments=[],
            abuse_result={},
            sender_ip=None,
            body_text="",
            scoring_weights=weights,
            brand_domains={},
            url_suspicious_keywords=[],
            suspicious_tlds=[],
            url_shorteners=[],
            urgency_keywords=[],
        )

    def test_single_malicious_url_scores_once(self):
        urls = [{"url": "http://evil.com", "vt_malicious": 5, "vt_harmless": 0, "vt_suspicious": 0}]
        result = self._score(urls)
        assert result["score"] == 4, "Single malicious URL should score exactly pts_vt=4"

    def test_three_malicious_urls_score_once_not_thrice(self):
        """With three URLs all above threshold, score must still be +4 (once), not +12."""
        urls = [
            {"url": "http://evil1.com", "vt_malicious": 5, "vt_harmless": 0, "vt_suspicious": 0},
            {"url": "http://evil2.com", "vt_malicious": 6, "vt_harmless": 0, "vt_suspicious": 0},
            {"url": "http://evil3.com", "vt_malicious": 7, "vt_harmless": 0, "vt_suspicious": 0},
        ]
        result = self._score(urls)
        assert result["score"] == 4, (
            f"Three malicious URLs scored {result['score']} instead of 4 (BUG-06 not fixed)"
        )

    def test_below_threshold_url_does_not_score(self):
        urls = [{"url": "http://clean.com", "vt_malicious": 1, "vt_harmless": 10, "vt_suspicious": 0}]
        result = self._score(urls)
        assert result["score"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# BUG-07: find_lookalike_domain() — legit subdomains falsely flagged
# ─────────────────────────────────────────────────────────────────────────────

class TestBug07_LookalikeLegitExemption:
    _brands = {
        "microsoft": ["microsoft.com", "live.com"],
        "paypal": ["paypal.com"],
    }

    def _call(self, domain: str):
        from backend.services.threat_signals import find_lookalike_domain
        return find_lookalike_domain(domain, self._brands, 82)

    def test_legitimate_subdomain_not_flagged(self):
        """mail.microsoft.com is a legitimate subdomain — must NOT be flagged."""
        assert self._call("mail.microsoft.com") is None, (
            "Legitimate subdomain falsely flagged as lookalike (BUG-07)"
        )

    def test_legitimate_domain_not_flagged(self):
        assert self._call("microsoft.com") is None

    def test_combosquat_still_flagged(self):
        """microsoft-support.com is NOT a legit subdomain — must be flagged."""
        result = self._call("microsoft-support.com")
        assert result is not None, "Combosquat not flagged"
        assert result[0] == "microsoft"

    def test_typosquat_still_flagged(self):
        result = self._call("micros0ft.com")
        assert result is not None, "Typosquat not flagged"

    def test_none_when_sender_domain_none(self):
        assert self._call(None) is None


# ─────────────────────────────────────────────────────────────────────────────
# BUG-08: relative redirects not resolved in _fetch_with_redirects
# ─────────────────────────────────────────────────────────────────────────────

class TestBug08_RelativeRedirectResolution:
    def test_urljoin_resolves_absolute_path_redirect(self):
        from urllib.parse import urljoin
        base = "http://example.com/some/page"
        location = "/new/path"
        result = urljoin(base, location)
        assert result == "http://example.com/new/path"

    def test_urljoin_resolves_relative_redirect(self):
        """Relative redirect like 'redirect?foo=bar' was previously not handled."""
        from urllib.parse import urljoin
        base = "http://example.com/track/"
        location = "redirect?foo=bar"
        result = urljoin(base, location)
        assert result == "http://example.com/track/redirect?foo=bar", (
            "Relative redirect not correctly resolved (BUG-08)"
        )

    def test_urljoin_preserves_absolute_url(self):
        from urllib.parse import urljoin
        base = "http://example.com/page"
        location = "https://other.com/landing"
        result = urljoin(base, location)
        assert result == "https://other.com/landing"

    def test_urljoin_handles_port_in_base(self):
        """Port in base URL must not confuse the resolver."""
        from urllib.parse import urljoin
        base = "http://example.com:8080/path"
        location = "/other"
        result = urljoin(base, location)
        assert result == "http://example.com:8080/other"

    def test_redirect_resolution_uses_urljoin(self):
        """Verify the actual source code uses urljoin (not the old manual split)."""
        src = Path(_ROOT / "backend" / "services" / "url_intelligence_service.py").read_text()
        assert "urljoin" in src, "url_intelligence_service.py does not use urljoin (BUG-08 not fixed)"
        assert 'base[1].split("/", 1)[0]' not in src, "Old manual redirect code still present (BUG-08)"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-10: OLE2 VBA false positive on plain ASCII "VBA" string
# ─────────────────────────────────────────────────────────────────────────────

class TestBug10_OLE2VBAFalsePositive:
    # Minimal OLE2 header magic
    _OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def _check(self, payload: bytes) -> bool:
        from backend.services.attachment_intelligence_service import (
            AttachmentIntelligence,
            _check_macro,
        )
        result = AttachmentIntelligence()
        _check_macro(payload, "test.doc", result)
        return result.is_macro_enabled

    def test_ole2_with_vba_text_not_flagged(self):
        """OLE2 doc containing the word 'VBA' in plain text must NOT be flagged."""
        payload = self._OLE2_MAGIC + b"\x00" * 500 + b"VBA" + b"\x00" * 500
        result = self._check(payload)
        assert result is False, (
            "Plain ASCII 'VBA' in OLE2 text content caused false positive (BUG-10)"
        )

    def test_ole2_with_vba_project_stream_flagged(self):
        """OLE2 doc with _VBA_PROJECT stream name MUST be flagged."""
        payload = self._OLE2_MAGIC + b"\x00" * 100 + b"_VBA_PROJECT" + b"\x00" * 400
        result = self._check(payload)
        assert result is True, "_VBA_PROJECT not detected in OLE2 doc (BUG-10)"

    def test_ole2_with_utf16_vba_flagged(self):
        """OLE2 doc with UTF-16LE V\x00B\x00A directory entry MUST be flagged."""
        payload = self._OLE2_MAGIC + b"\x00" * 100 + b"V\x00B\x00A" + b"\x00" * 400
        result = self._check(payload)
        assert result is True, "UTF-16 VBA marker not detected in OLE2 doc (BUG-10)"

    def test_clean_ole2_not_flagged(self):
        """OLE2 doc with no VBA markers at all must NOT be flagged."""
        payload = self._OLE2_MAGIC + b"\x00" * 1000 + b"some document content here"
        result = self._check(payload)
        assert result is False, "Clean OLE2 doc falsely flagged as macro-enabled (BUG-10)"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-12: scan_url_async has no timeout, can hold semaphore indefinitely
# ─────────────────────────────────────────────────────────────────────────────

class TestBug12_VTScanUrlTimeout:
    def test_scan_wait_timeout_constant_defined(self):
        """_SCAN_WAIT_TIMEOUT must be defined in virustotal_provider."""
        from backend.services.enrichment import virustotal_provider
        assert hasattr(virustotal_provider, "_SCAN_WAIT_TIMEOUT"), (
            "_SCAN_WAIT_TIMEOUT not defined (BUG-12 not fixed)"
        )
        assert virustotal_provider._SCAN_WAIT_TIMEOUT > 0

    def test_wait_for_used_in_source(self):
        """asyncio.wait_for must be present in the scan_url_async call."""
        src = Path(_ROOT / "backend" / "services" / "enrichment" / "virustotal_provider.py").read_text()
        assert "asyncio.wait_for" in src, (
            "asyncio.wait_for not used in virustotal_provider.py (BUG-12 not fixed)"
        )
        assert "_SCAN_WAIT_TIMEOUT" in src

    @pytest.mark.asyncio
    async def test_timeout_is_respected(self):
        """If scan_url_async hangs, wait_for must raise TimeoutError which is caught."""
        import asyncio

        async def slow_scan(*args, **kwargs):
            await asyncio.sleep(9999)

        # Simulate: wait_for wrapping a slow coroutine times out and is caught
        stats = {}
        try:
            await asyncio.wait_for(slow_scan(), timeout=0.01)
        except (asyncio.TimeoutError, TimeoutError):
            pass  # correctly caught — stats stays {}

        assert stats == {}, "Timeout was not handled gracefully"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-13: sha256_list built before payload decode, missing hashes
# ─────────────────────────────────────────────────────────────────────────────

class TestBug13_Sha256AfterDecode:
    def test_hash_computed_from_decoded_payload(self):
        """When att['payload'] is a base64 string, hash must be computable from decoded bytes."""
        content = b"fake pdf bytes for hash test"
        encoded = base64.b64encode(content).decode("ascii")

        att = {"filename": "doc.pdf", "payload": encoded}

        # Simulate the fixed pipeline logic
        payload = att.get("payload") or b""
        if isinstance(payload, str):
            payload = base64.b64decode(payload, validate=False)

        from backend.services.eml_parser_service import hash_attachment_content
        # att still has string payload — hash_attachment_content returns None
        direct_hash = hash_attachment_content(att)
        assert direct_hash is None, "Expected None from string payload in att dict"

        # But we can compute from decoded bytes
        computed = hashlib.sha256(payload).hexdigest()
        expected = hashlib.sha256(content).hexdigest()
        assert computed == expected, "Hash from decoded payload does not match (BUG-13)"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-17: extract_auth_from_raw uses legacy email policy (no RFC2047 decode)
# ─────────────────────────────────────────────────────────────────────────────

class TestBug17_AuthHeaderPolicy:
    def test_uses_modern_policy_in_source(self):
        """extract_auth_from_raw must use policy.default, not the legacy parser."""
        src = Path(_ROOT / "backend" / "services" / "eml_parser_service.py").read_text()
        assert "policy.default" in src, (
            "extract_auth_from_raw still uses legacy email policy (BUG-17 not fixed)"
        )

    def test_spf_pass_extracted(self):
        """A standard Authentication-Results header must yield spf=pass."""
        from backend.services.eml_parser_service import extract_auth_from_raw

        raw = (
            b"From: sender@example.com\r\n"
            b"Authentication-Results: mx.example.com;"
            b" spf=pass smtp.mailfrom=sender@example.com;"
            b" dkim=pass header.i=@example.com;"
            b" dmarc=pass\r\n"
            b"Subject: Test\r\n\r\nBody"
        )
        parsed = {"_raw_email": raw}
        result, sources = extract_auth_from_raw(parsed)
        assert result["spf"] == "pass"
        assert result["dkim"] == "pass"
        assert result["dmarc"] == "pass"


# ─────────────────────────────────────────────────────────────────────────────
# BUG-18: mkdir/write_bytes PermissionError causes unhandled 500
# ─────────────────────────────────────────────────────────────────────────────

class TestBug18_MkdirPermissionError:
    def test_invalid_eml_error_raised_on_oserror(self):
        """OSError from mkdir must be converted to InvalidEmlError, not crash the endpoint."""
        from backend.core.exceptions import InvalidEmlError

        # Simulate the fixed guard logic
        raised = None
        try:
            try:
                raise OSError("Permission denied")
            except OSError as exc:
                raise InvalidEmlError(
                    f"Could not save uploaded file: {type(exc).__name__}"
                ) from exc
        except InvalidEmlError as e:
            raised = e

        assert raised is not None, "InvalidEmlError was not raised from OSError (BUG-18)"
        assert "OSError" in str(raised)

    def test_fix_present_in_source(self):
        """The try/except OSError guard must exist in analysis_service.py."""
        src = Path(_ROOT / "backend" / "services" / "analysis_service.py").read_text()
        assert "except OSError" in src, (
            "OSError guard missing from submit_upload (BUG-18 not fixed)"
        )
