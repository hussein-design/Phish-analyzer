"""Tests for redirect-chain signal wrapper-unwrap logic.

Covers:
  1. _unwrap_known_wrapper correctly extracts destinations from SafeLinks,
     iris.microsoft.com, google.com/url, urldefense, proofpoint.
  2. _assess_redirect_suspicion does NOT fire for wrapper → normal domain.
  3. _assess_redirect_suspicion DOES fire for wrapper → raw IP.
  4. SafeLinks → google.com, microsoft.com (3 cases each) must not fire.
  5. iris.microsoft.com → microsoft.com (3 cases) must not fire.
  6. Excessive real hops (>2) fires.
  7. Destination is a URL shortener fires.
  8. Non-wrapper, non-suspicious redirect does not fire.

Score values affected by this change
──────────────────────────────────────
The old _assess_redirect_suspicion fired on ANY brand-token mismatch or ANY
2+ hop redirect.  The new logic fires only on IP host, shortener, or >2 real
hops.  Consequently:

  • SafeLinks → google.com   : was is_redirect_suspicious=True (brand mismatch
    because "google" in final_host but not original_host) → now False.  Score
    contribution: was +3, now +0.

  • SafeLinks → microsoft.com: was is_redirect_suspicious=True (brand mismatch)
    → now False.  Score contribution: was +3, now +0.

  • iris.microsoft.com → microsoft.com: was False (same token, same compact) →
    still False.  No change.

  • Wrapper → 1.2.3.4 (raw IP): was is_redirect_suspicious=False (no brand
    token in IP string) → now True.  Score contribution: was +0, now +3.

  • Non-wrapper, 3+ hop redirect to unrelated domain: was True (≥2 hop
    rule) → still True via >2 real hops rule.  No change in score.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlencode

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.services.url_intelligence_service import (
    _assess_redirect_suspicion,
    _unwrap_known_wrapper,
    UrlIntelligence,
)


# ─────────────────────────────────────────────────────────────────────────────
# _unwrap_known_wrapper unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestUnwrapKnownWrapper:

    def _sl(self, dest: str) -> str:
        """Build a typical SafeLinks URL wrapping *dest*."""
        return (
            "https://nam02.safelinks.protection.outlook.com/?"
            + urlencode({"url": dest, "data": "02|01|foo@corp.com|abc|def|1|0|"})
        )

    def test_safelinks_extracts_url_param(self):
        dest = "https://www.google.com/search?q=hello"
        sl = self._sl(dest)
        assert _unwrap_known_wrapper(sl) == dest

    def test_safelinks_microsoft_destination(self):
        dest = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        sl = self._sl(dest)
        assert _unwrap_known_wrapper(sl) == dest

    def test_safelinks_raw_ip_destination(self):
        dest = "http://1.2.3.4/evil"
        sl = self._sl(dest)
        assert _unwrap_known_wrapper(sl) == dest

    def test_iris_microsoft_extracts_url_param(self):
        dest = "https://www.microsoft.com/en-us/security"
        iris_url = (
            "https://go.iris.microsoft.com/api/v2/a/c?"
            + urlencode({"url": dest, "id": "abc123"})
        )
        assert _unwrap_known_wrapper(iris_url) == dest

    def test_iris_sub_wildcard_matches(self):
        """Any *.iris.microsoft.com subdomain must be unwrapped."""
        dest = "https://aka.ms/some-resource"
        iris_url = (
            "https://click.iris.microsoft.com/api/v2/a/c?"
            + urlencode({"url": dest})
        )
        assert _unwrap_known_wrapper(iris_url) == dest

    def test_google_url_redirect(self):
        dest = "https://example.com/landing"
        g_url = "https://www.google.com/url?" + urlencode({"q": dest, "sa": "t"})
        assert _unwrap_known_wrapper(g_url) == dest

    def test_urldefense_proofpoint(self):
        dest = "https://paypal.com/signin"
        pp_url = (
            "https://urldefense.proofpoint.com/v2/url?"
            + urlencode({"u": dest, "d": "AQ"})
        )
        assert _unwrap_known_wrapper(pp_url) == dest

    def test_urldefense_com(self):
        dest = "https://sharepoint.microsoft.com/sites/it"
        ud_url = "https://urldefense.com/v3?" + urlencode({"u": dest})
        assert _unwrap_known_wrapper(ud_url) == dest

    def test_non_wrapper_returns_none(self):
        assert _unwrap_known_wrapper("https://evil.example.com/phish") is None

    def test_empty_string_returns_none(self):
        assert _unwrap_known_wrapper("") is None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _result(original_url: str, redirect_count: int = 1,
            expanded_url: str | None = None,
            redirect_chain: list[str] | None = None) -> UrlIntelligence:
    r = UrlIntelligence(original_url=original_url)
    r.redirect_count = redirect_count
    r.expanded_url = expanded_url
    r.redirect_chain = redirect_chain or []
    return r


def _sl(dest: str) -> str:
    return (
        "https://nam02.safelinks.protection.outlook.com/?"
        + urlencode({"url": dest, "data": "02|01|foo@corp.com|abc|def|1|0|"})
    )


def _iris(dest: str) -> str:
    return (
        "https://go.iris.microsoft.com/api/v2/a/c?"
        + urlencode({"url": dest, "id": "abc"})
    )


# ─────────────────────────────────────────────────────────────────────────────
# _assess_redirect_suspicion — SafeLinks → normal domains (must NOT fire)
# ─────────────────────────────────────────────────────────────────────────────

class TestSafeLinksToNormalDomain:

    def test_safelinks_to_google_search(self):
        """SafeLinks → google.com must not fire the redirect-suspicious signal."""
        r = _result(_sl("https://www.google.com/search?q=test"), redirect_count=1,
                    expanded_url="https://www.google.com/search?q=test")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False, (
            f"SafeLinks → google.com should not fire; reason: {r.redirect_suspicious_reason}"
        )

    def test_safelinks_to_google_accounts(self):
        """SafeLinks → accounts.google.com must not fire."""
        r = _result(_sl("https://accounts.google.com/signin"), redirect_count=1,
                    expanded_url="https://accounts.google.com/signin")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_safelinks_to_google_docs(self):
        """SafeLinks → docs.google.com must not fire."""
        r = _result(_sl("https://docs.google.com/document/d/abc"), redirect_count=1,
                    expanded_url="https://docs.google.com/document/d/abc")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_safelinks_to_microsoft_login(self):
        """SafeLinks → login.microsoftonline.com must not fire."""
        r = _result(_sl("https://login.microsoftonline.com/common/oauth2/authorize"),
                    redirect_count=1,
                    expanded_url="https://login.microsoftonline.com/common/oauth2/authorize")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_safelinks_to_microsoft_sharepoint(self):
        """SafeLinks → sharepoint.microsoft.com must not fire."""
        r = _result(_sl("https://contoso.sharepoint.com/sites/hr"),
                    redirect_count=1,
                    expanded_url="https://contoso.sharepoint.com/sites/hr")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_safelinks_to_microsoft_teams(self):
        """SafeLinks → teams.microsoft.com must not fire."""
        r = _result(_sl("https://teams.microsoft.com/l/meeting/abc"),
                    redirect_count=1,
                    expanded_url="https://teams.microsoft.com/l/meeting/abc")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False


# ─────────────────────────────────────────────────────────────────────────────
# _assess_redirect_suspicion — iris.microsoft.com → microsoft.com (must NOT fire)
# ─────────────────────────────────────────────────────────────────────────────

class TestIrisToMicrosoftDomain:

    def test_iris_to_microsoft_security(self):
        """iris.microsoft.com → microsoft.com must not fire."""
        dest = "https://www.microsoft.com/en-us/security"
        r = _result(_iris(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False, (
            f"iris → microsoft.com should not fire; reason: {r.redirect_suspicious_reason}"
        )

    def test_iris_to_microsoft_learn(self):
        """iris.microsoft.com → learn.microsoft.com must not fire."""
        dest = "https://learn.microsoft.com/en-us/azure/security"
        r = _result(_iris(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_iris_to_microsoft_support(self):
        """iris.microsoft.com → support.microsoft.com must not fire."""
        dest = "https://support.microsoft.com/en-us/topic/12345"
        r = _result(_iris(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False


# ─────────────────────────────────────────────────────────────────────────────
# _assess_redirect_suspicion — wrapper → raw IP (MUST fire)
# ─────────────────────────────────────────────────────────────────────────────

class TestWrapperToRawIP:

    def test_safelinks_to_raw_ip_fires(self):
        """SafeLinks → raw IP address MUST fire is_redirect_suspicious."""
        dest = "http://1.2.3.4/malware"
        r = _result(_sl(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True, (
            "SafeLinks → raw IP should fire the redirect-suspicious signal"
        )
        assert r.redirect_suspicious_reason is not None
        assert "1.2.3.4" in r.redirect_suspicious_reason

    def test_iris_to_raw_ip_fires(self):
        """iris.microsoft.com → raw IP MUST fire."""
        dest = "http://10.20.30.40/payload"
        r = _result(_iris(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True
        assert "10.20.30.40" in (r.redirect_suspicious_reason or "")


# ─────────────────────────────────────────────────────────────────────────────
# _assess_redirect_suspicion — other firing conditions
# ─────────────────────────────────────────────────────────────────────────────

class TestOtherFiringConditions:

    def test_wrapper_to_shortener_fires(self):
        """SafeLinks → known URL shortener MUST fire."""
        dest = "https://bit.ly/3xABCDE"
        r = _result(_sl(dest), redirect_count=1, expanded_url=dest)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True
        assert "bit.ly" in (r.redirect_suspicious_reason or "")

    def test_non_wrapper_to_raw_ip_fires(self):
        """Direct URL (no wrapper) pointing to raw IP must also fire."""
        r = _result("http://5.6.7.8/evil", redirect_count=0,
                    expanded_url="http://5.6.7.8/evil")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True

    def test_excessive_hops_fires(self):
        """More than 2 real hops (no wrapper) must fire."""
        r = _result("https://legit-origin.com/track", redirect_count=3,
                    expanded_url="https://final-dest.com/landing",
                    redirect_chain=[
                        "https://hop1.example.com/",
                        "https://hop2.example.com/",
                        "https://final-dest.com/landing",
                    ])
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True
        assert "3" in (r.redirect_suspicious_reason or "")

    def test_safelinks_then_extra_hops_fires(self):
        """SafeLinks wrapper + 3 more real hops (total 4) must fire via >2 real hops."""
        dest = "https://final-dest.com/landing"
        r = _result(_sl(dest), redirect_count=4,
                    expanded_url=dest,
                    redirect_chain=[
                        dest,
                        "https://hop2.example.com/",
                        "https://hop3.example.com/",
                        dest,
                    ])
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is True

    def test_normal_2hop_redirect_does_not_fire(self):
        """A plain 2-hop redirect to a normal domain must not fire."""
        r = _result("https://origin.example.com/link", redirect_count=2,
                    expanded_url="https://destination.example.com/page")
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False

    def test_no_redirect_no_fire(self):
        """URL with no redirect at all must not fire."""
        r = _result("https://normal.example.com/page", redirect_count=0)
        _assess_redirect_suspicion(r)
        assert r.is_redirect_suspicious is False
