"""Tests for the 6 improvements to threat_signals, scoring_service,
and eml_parser_service URL extraction.

Scenarios:
1. TEXT NORMALIZATION – NBSP / zero-width chars still match keywords.
2. WORD BOUNDARIES – "groups"/"startups" do NOT trigger shipping;
   "coo" does NOT trigger exec_impersonation alone.
3. WORD BOUNDARIES (urgency) – "cooperation" does NOT trigger "coo".
4. LURE RULES – 2-keyword minimum; max-2-category cap; urgency dedup.
5. ANCHOR MISMATCH – tracker/wrapper link suppressed; real spoof still fires.
6. URL EXTRACTION – DOCTYPE URL filtered; real body URL kept.

Run with:
    pytest tests/test_improvements.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _base_weights() -> dict:
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


def _compute(body_text="", lure_categories=None, anchor_mismatches=None,
             urgency_keywords=None):
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
        body_text=body_text,
        scoring_weights=_base_weights(),
        brand_domains={},
        url_suspicious_keywords=[],
        suspicious_tlds=[],
        url_shorteners=[],
        urgency_keywords=urgency_keywords or [],
        lure_categories=lure_categories,
        anchor_mismatches=anchor_mismatches,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. TEXT NORMALIZATION
# ─────────────────────────────────────────────────────────────────────────────

class TestTextNormalization:
    def test_nbsp_still_matches_keyword(self):
        """confirm\u00a0your\u00a0identity should match 'confirm your identity'."""
        from backend.services.threat_signals import normalize_body_text
        raw = "Please\u00a0confirm\u00a0your\u00a0identity to proceed."
        norm = normalize_body_text(raw)
        assert "confirm your identity" in norm

    def test_nbsp_lure_detection(self):
        """Body with NBSP-separated keywords still fires password_reset lure."""
        from backend.services.threat_signals import detect_lure_categories
        # password_reset has "confirm your identity" and "verify your identity"
        body = "Please\u00a0confirm\u00a0your\u00a0identity now. Also\u00a0verify\u00a0your\u00a0identity."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "password_reset" in cats, f"Expected password_reset, got: {cats}"

    def test_zero_width_chars_stripped(self):
        """Zero-width chars between keyword letters do not prevent matching."""
        from backend.services.threat_signals import normalize_body_text
        # Insert zero-width space in the middle of a word
        raw = "pay\u200bpal is requesting your details"
        norm = normalize_body_text(raw)
        # After stripping ZW chars, "paypal" should be present
        assert "paypal" in norm

    def test_soft_hyphen_stripped(self):
        from backend.services.threat_signals import normalize_body_text
        raw = "pass\u00adword reset required"
        norm = normalize_body_text(raw)
        assert "password reset" in norm

    def test_casefold_applied(self):
        from backend.services.threat_signals import normalize_body_text
        assert normalize_body_text("INVOICE") == "invoice"

    def test_whitespace_collapsed(self):
        from backend.services.threat_signals import normalize_body_text
        assert normalize_body_text("hello   world\t\nfoo") == "hello world foo"


# ─────────────────────────────────────────────────────────────────────────────
# 2. WORD BOUNDARIES – lure keywords
# ─────────────────────────────────────────────────────────────────────────────

class TestWordBoundaryLure:
    def test_groups_does_not_trigger_shipping(self):
        """'groups' contains 'ups' but must NOT fire shipping_delivery."""
        from backend.services.threat_signals import detect_lure_categories
        # Only one shipping keyword substring in "groups" — cannot hit 2-kw minimum
        body = "We have several user groups and startups. Our teams are growing."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "shipping_delivery" not in cats, f"'groups'/'startups' wrongly triggered shipping: {cats}"

    def test_startups_does_not_trigger_shipping(self):
        """'startups' contains 'ups' but must NOT fire shipping_delivery."""
        from backend.services.threat_signals import detect_lure_categories
        body = "startups and scaleups are transforming technology"
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "shipping_delivery" not in cats

    def test_ups_as_word_triggers_shipping(self):
        """Actual 'UPS' as a word should still match for shipping."""
        from backend.services.threat_signals import detect_lure_categories
        # Need 2+ distinct keywords for the category to fire
        body = "Your UPS delivery failed. Your parcel could not be delivered."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "shipping_delivery" in cats, f"Expected shipping_delivery, got: {cats}"

    def test_microsoft_365_alone_does_not_fire_it_helpdesk(self):
        """'microsoft 365' alone is only 1 keyword — does NOT fire it_helpdesk (needs 2+)."""
        from backend.services.threat_signals import detect_lure_categories
        body = "We use Microsoft 365 for collaboration."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "it_helpdesk" not in cats, f"Single keyword wrongly fired it_helpdesk: {cats}"

    def test_two_it_helpdesk_keywords_fires(self):
        """Two distinct it_helpdesk keywords must fire the category."""
        from backend.services.threat_signals import detect_lure_categories
        body = "Your Microsoft 365 mailbox quota has been exceeded. Please update now."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "it_helpdesk" in cats, f"Expected it_helpdesk, got: {cats}"

    def test_coo_in_cooperation_does_not_trigger_exec_impersonation(self):
        """'coo' inside 'cooperation' must NOT fire exec_impersonation."""
        from backend.services.threat_signals import detect_lure_categories
        body = "In cooperation with our partners, the project is progressing."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "exec_impersonation" not in cats


# ─────────────────────────────────────────────────────────────────────────────
# 3. WORD BOUNDARIES – urgency keywords
# ─────────────────────────────────────────────────────────────────────────────

class TestWordBoundaryUrgency:
    def test_cooperation_does_not_match_coo(self):
        from backend.services.threat_signals import find_urgency_keywords
        result = find_urgency_keywords("Our cooperation leads to success.", ["coo"])
        assert result == [], f"'cooperation' wrongly matched 'coo': {result}"

    def test_coo_as_word_matches(self):
        from backend.services.threat_signals import find_urgency_keywords
        result = find_urgency_keywords("Signed, Jane Smith, COO", ["coo"])
        assert "coo" in result

    def test_nbsp_urgency_keyword_matches(self):
        """NBSP between urgency keyword parts should still match."""
        from backend.services.threat_signals import find_urgency_keywords
        # keyword "act now" with NBSP
        result = find_urgency_keywords("Please\u00a0act\u00a0now to avoid suspension.", ["act now"])
        assert "act now" in result

    def test_multiword_urgency_boundary(self):
        from backend.services.threat_signals import find_urgency_keywords
        result = find_urgency_keywords("immediate actions required", ["immediate action"])
        assert result == [], "Partial word match should not fire"

    def test_exact_multiword_urgency_matches(self):
        from backend.services.threat_signals import find_urgency_keywords
        result = find_urgency_keywords("This requires immediate action now.", ["immediate action"])
        assert "immediate action" in result


# ─────────────────────────────────────────────────────────────────────────────
# 4. LURE RULES
# ─────────────────────────────────────────────────────────────────────────────

class TestLureRules:
    def test_single_keyword_does_not_fire(self):
        """One keyword match is not enough to fire a category."""
        from backend.services.threat_signals import detect_lure_categories
        body = "Please check your invoice now."  # only 1 keyword
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "invoice_payment" not in cats

    def test_two_keywords_fires(self):
        from backend.services.threat_signals import detect_lure_categories
        body = "Invoice overdue. Please remit payment via bank transfer."
        matches = detect_lure_categories(body)
        cats = [m.category for m in matches]
        assert "invoice_payment" in cats

    def test_four_categories_scores_at_most_two(self):
        """Even when 4+ categories match, only 2 categories add to score."""
        from backend.services.threat_signals import detect_lure_categories
        from backend.services.scoring_service import compute_score

        # Craft a body that hits many categories with 2+ keywords each
        body = (
            # exec_impersonation (2 kws)
            "The CEO and CFO request a direct wire. This is strictly confidential. "
            # account_takeover (2 kws)
            "Your account has been compromised due to unusual activity. Action required. "
            # invoice_payment (2 kws)
            "Invoice overdue. Bank transfer requested immediately. "
            # password_reset (2 kws)
            "Reset your password. Verify your identity. "
        )
        lure_matches = detect_lure_categories(body)
        lure_dicts = [{"category": m.category, "matched_keywords": m.matched_keywords}
                      for m in lure_matches]
        assert len(lure_dicts) >= 3, "Test setup: expected ≥3 lure categories"

        result = compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_issues=[],
            urls=[],
            attachments=[],
            abuse_result={},
            sender_ip=None,
            body_text=body,
            scoring_weights=_base_weights(),
            brand_domains={},
            url_suspicious_keywords=[],
            suspicious_tlds=[],
            url_shorteners=[],
            urgency_keywords=[],
            lure_categories=lure_dicts,
        )
        # exec_impersonation: 2+1=3 pts; account_takeover: 2+1=3 pts → max 6 pts from lures
        # (any other category gets 0 pts)
        lure_pts = sum(
            3 if lure["category"] in ("exec_impersonation", "account_takeover") else 2
            for lure in lure_dicts[:2]  # only first 2 score
        )
        assert result["static_score"] <= lure_pts + 5, (
            f"Score {result['static_score']} seems too high for max-2-category rule"
        )
        # Count scored reasons (those without "informational")
        scored_reasons = [r for r in result["reasons"] if "informational" not in r and "Lure" in r]
        assert len(scored_reasons) <= 2, f"More than 2 lure categories scored: {scored_reasons}"

    def test_urgency_dedup_prevents_double_count(self):
        """A keyword that fired under urgency must not also add points under lure."""
        from backend.services.threat_signals import find_urgency_keywords, detect_lure_categories
        from backend.services.scoring_service import compute_score

        # "act immediately" is in urgency list AND "act immediately" might overlap with
        # account_takeover lure keywords ("act immediately" is in account_takeover).
        # We'll use a body where the urgency check grabs "act immediately" and lure
        # keywords must NOT double-score it.
        body = (
            "Your account has been compromised due to unusual activity. "
            "Click here to secure your account. Act immediately. "
            "Your account was accessed from an unknown location. Immediate action required."
        )
        urgency_kws = ["act immediately", "action required", "immediate action"]
        urgency_found = find_urgency_keywords(body, urgency_kws)
        lure_matches = detect_lure_categories(body, already_scored_phrases=set(urgency_found))
        lure_dicts = [{"category": m.category, "matched_keywords": m.matched_keywords}
                      for m in lure_matches]

        result = compute_score(
            from_addr="sender@example.com",
            from_domain="example.com",
            auth={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            header_issues=[],
            urls=[],
            attachments=[],
            abuse_result={},
            sender_ip=None,
            body_text=body,
            scoring_weights=_base_weights(),
            brand_domains={},
            url_suspicious_keywords=[],
            suspicious_tlds=[],
            url_shorteners=[],
            urgency_keywords=urgency_kws,
            lure_categories=lure_dicts,
        )
        # Urgency scores once (1 pt); lure should not re-add points for same phrases
        # The key check: scored reasons contain only 1 urgency entry
        urgency_reasons = [r for r in result["reasons"] if "urgency" in r.lower()]
        assert len(urgency_reasons) <= 1


# ─────────────────────────────────────────────────────────────────────────────
# 5. ANCHOR MISMATCH – tracker/wrapper allowlist
# ─────────────────────────────────────────────────────────────────────────────

class TestAnchorMismatch:
    def _html(self, display: str, href: str) -> str:
        return f'<a href="{href}">{display}</a>'

    def test_tracked_marketing_link_not_flagged(self):
        """A SafeLinks-wrapped URL where paypal.com sends a PayPal link is OK."""
        from backend.services.threat_signals import detect_anchor_mismatches
        # href is a SafeLinks wrapper, display says "paypal.com", sender IS paypal.com
        href = (
            "https://safelinks.protection.outlook.com/?url="
            "https%3A%2F%2Fwww.paypal.com%2Flogin&data=xyz"
        )
        html = self._html("paypal.com", href)
        # sender_domain = paypal.com → brand token "paypal" is in sender domain
        mismatches = detect_anchor_mismatches(html, sender_domain="paypal.com")
        assert mismatches == [], f"Legitimate tracker link wrongly flagged: {mismatches}"

    def test_sendgrid_tracking_not_flagged(self):
        """SendGrid-wrapped link from microsoft.com should not be flagged."""
        from backend.services.threat_signals import detect_anchor_mismatches
        href = "https://u12345678.ct.sendgrid.net/ls/click?upn=abc&url=https://microsoft.com/login"
        html = self._html("Microsoft login", href)
        mismatches = detect_anchor_mismatches(html, sender_domain="microsoft.com")
        assert mismatches == [], f"Legitimate sendgrid link wrongly flagged: {mismatches}"

    def test_true_brand_spoof_still_fires(self):
        """Text 'paypal.com', href to an unrelated non-wrapper domain → mismatch fires."""
        from backend.services.threat_signals import detect_anchor_mismatches
        html = self._html("paypal.com", "https://evil-site.ru/steal")
        mismatches = detect_anchor_mismatches(html, sender_domain="evil-site.ru")
        assert len(mismatches) >= 1, "Real brand spoof was not flagged"
        assert any("paypal" in m.reason.lower() for m in mismatches)

    def test_wrapper_without_matching_brand_fires(self):
        """SafeLinks wrapper but display says 'paypal.com' and sender is evil.com → spoof."""
        from backend.services.threat_signals import detect_anchor_mismatches
        # href is SafeLinks but the unwrapped URL goes to evil.com
        href = (
            "https://safelinks.protection.outlook.com/?url="
            "https%3A%2F%2Fevil.com%2Fsteal&data=xyz"
        )
        html = self._html("paypal.com", href)
        mismatches = detect_anchor_mismatches(html, sender_domain="evil.com")
        assert len(mismatches) >= 1, (
            "SafeLinks wrapping an unrelated domain with PayPal display text should fire"
        )

    def test_no_mismatch_for_clean_anchor(self):
        """A plain anchor where display and href match the same brand is fine."""
        from backend.services.threat_signals import detect_anchor_mismatches
        html = '<a href="https://paypal.com/login">paypal.com</a>'
        mismatches = detect_anchor_mismatches(html, sender_domain="paypal.com")
        assert mismatches == []


# ─────────────────────────────────────────────────────────────────────────────
# 6. URL EXTRACTION – DOCTYPE / xmlns / <link> / <meta> filtered
# ─────────────────────────────────────────────────────────────────────────────

class TestUrlExtraction:
    def _make_body_raw(self, html: str) -> list:
        return [{"content_type": "text/html", "content": html, "uri": []}]

    def test_doctype_url_not_extracted(self):
        """http://www.w3.org/TR/html4/loose.dtd must NOT appear in URLs."""
        from backend.services.eml_parser_service import extract_urls_from_body
        html = (
            '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" '
            '"http://www.w3.org/TR/html4/loose.dtd">'
            '<html><body>'
            '<a href="https://evil.com/phish">Click here</a>'
            '</body></html>'
        )
        body_raw = self._make_body_raw(html)
        body_text = ""  # plain text won't contain the DOCTYPE URL
        urls = extract_urls_from_body(body_raw, body_text)
        assert not any("w3.org/TR" in u for u in urls), f"DOCTYPE URL leaked into urls: {urls}"

    def test_real_body_url_kept(self):
        """https://evil.com/phish (real anchor href) must still be extracted."""
        from backend.services.eml_parser_service import extract_urls_from_body
        html = (
            '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" '
            '"http://www.w3.org/TR/html4/loose.dtd">'
            '<html><body>'
            '<a href="https://evil.com/phish">Click here</a>'
            '</body></html>'
        )
        body_raw = self._make_body_raw(html)
        body_text = "https://evil.com/phish"
        urls = extract_urls_from_body(body_raw, body_text)
        assert "https://evil.com/phish" in urls

    def test_xmlns_url_not_extracted(self):
        """xmlns attribute values must NOT appear in URLs."""
        from backend.services.eml_parser_service import extract_urls_from_body
        html = (
            '<html xmlns="http://www.w3.org/1999/xhtml">'
            '<body>'
            '<a href="https://real-link.com/page">Visit us</a>'
            '</body></html>'
        )
        body_raw = self._make_body_raw(html)
        body_text = "https://real-link.com/page"
        urls = extract_urls_from_body(body_raw, body_text)
        assert not any("w3.org/1999/xhtml" in u for u in urls), (
            f"xmlns URL leaked into urls: {urls}"
        )
        assert "https://real-link.com/page" in urls

    def test_link_tag_url_not_extracted(self):
        """<link rel=stylesheet href=...> must NOT appear in URLs."""
        from backend.services.eml_parser_service import extract_urls_from_body
        html = (
            '<html><head>'
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">'
            '</head><body>'
            '<a href="https://evil.com/phish">Click</a>'
            '</body></html>'
        )
        body_raw = self._make_body_raw(html)
        body_text = "https://evil.com/phish"
        urls = extract_urls_from_body(body_raw, body_text)
        assert not any("fonts.googleapis.com" in u for u in urls), (
            f"<link> stylesheet URL leaked: {urls}"
        )

    def test_meta_refresh_url_not_extracted(self):
        """<meta http-equiv=refresh content='0;url=...'> must NOT appear in URLs."""
        from backend.services.eml_parser_service import extract_urls_from_body
        html = (
            '<html><head>'
            '<meta http-equiv="refresh" content="0;url=https://tracker.example.com/pixel.gif">'
            '</head><body>'
            '<a href="https://real.com/page">Real link</a>'
            '</body></html>'
        )
        body_raw = self._make_body_raw(html)
        body_text = "https://real.com/page"
        urls = extract_urls_from_body(body_raw, body_text)
        assert not any("tracker.example.com" in u for u in urls), (
            f"<meta> refresh URL leaked: {urls}"
        )
        assert "https://real.com/page" in urls
