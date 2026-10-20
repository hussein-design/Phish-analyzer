"""Additional phishing-detection heuristics beyond the original CLI's rule
set: lookalike/typosquat domains, punycode homographs, suspicious TLDs,
URL shorteners, dangerous/double file extensions, urgency language, and
lure-category detection (invoice/payment, password-reset, IT helpdesk,
executive impersonation, account-takeover, shipping).

Each function is a pure, stdlib-only check so scoring_service can call them
without adding new runtime dependencies.
"""

from __future__ import annotations

import difflib
import re
from typing import NamedTuple

# Extensions that can execute code on Windows if double-clicked -- the
# original CLI only matched "exe/msdownload/script" as a MIME-type
# substring, which misses most of these entirely.
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".jar", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".dll", ".lnk",
    ".wsf", ".wsh", ".gadget", ".cpl", ".reg",
}

# Common "safe-looking" extensions attackers stack a dangerous one behind,
# e.g. "invoice.pdf.exe".
_COMMON_DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".jpg", ".jpeg", ".png", ".gif", ".csv", ".zip",
}

# MED-01: Cap HTML body size before any regex scanning to prevent ReDoS
_MAX_HTML_SCAN_BYTES = 512_000   # 512 KB — more than enough for any real email

# ── Text normalisation ───────────────────────────────────────────────────────
# Applied once at the call-site before any keyword matching so every check
# in this module sees the same cleaned form.  The raw text is kept separately
# for display / storage.

_ZW_CHARS = re.compile(
    r"[\u00ad"          # soft hyphen
    r"\u200b-\u200f"    # zero-width space / joiner / non-joiner / LTR / RTL
    r"\u2028\u2029"     # line/paragraph separator
    r"\ufeff"           # BOM / zero-width no-break space
    r"]"
)


def normalize_body_text(text: str) -> str:
    """Return a casefolded, whitespace-collapsed version of *text* suitable
    for keyword matching.

    Steps applied (none alter the meaning visible to a human reader):
    1. NBSP (U+00A0) → regular space.
    2. Zero-width and soft-hyphen characters removed.
    3. Unicode casefolding (handles ß → ss, etc.).
    4. Runs of whitespace collapsed to a single ASCII space.
    """
    if not text:
        return ""
    # 1. NBSP → space
    text = text.replace("\u00a0", " ")
    # 2. Zero-width / soft-hyphen characters stripped
    text = _ZW_CHARS.sub("", text)
    # 3. Casefold
    text = text.casefold()
    # 4. Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ── Lure category keyword sets ────────────────────────────────────────────────
# Each set covers the most common attacker vocabulary for that lure type.
# Matching uses case-insensitive word-boundary regex so "ups" does not
# match inside "groups" and "coo" does not match inside "cooperation".

LURE_KEYWORDS: dict[str, list[str]] = {
    "invoice_payment": [
        "invoice", "payment due", "payment required", "remittance",
        "overdue", "past due", "purchase order", "po number",
        "bank transfer", "wire transfer", "ach payment", "billing statement",
        "statement of account", "amount due", "pay now", "final notice",
        "outstanding balance", "receipt attached",
    ],
    "password_reset": [
        "password reset", "reset your password", "change your password",
        "verify your identity", "confirm your identity", "unusual sign-in",
        "suspicious login", "your account was accessed", "secure your account",
        "verify your account", "account verification", "one-time password",
        "one-time code", "authentication code", "2fa code", "mfa code",
        "temporary password",
    ],
    "it_helpdesk": [
        "it helpdesk", "help desk", "it support", "technical support",
        "system upgrade", "mailbox upgrade", "mailbox quota", "storage quota",
        "email quota exceeded", "email suspension", "account disabled",
        "office 365", "microsoft 365", "sharepoint", "onedrive",
        "teams notification", "voicemail", "new fax", "scanned document",
    ],
    "account_takeover": [
        "your account has been", "account compromised", "unusual activity",
        "unauthorized access", "login attempt", "sign-in attempt",
        "click here to secure", "confirm your details", "update your information",
        "action required", "immediate action", "act immediately",
        "your apple id", "your google account", "your paypal", "your amazon",
        "your netflix", "your bank account", "credit card declined",
    ],
    "exec_impersonation": [
        "ceo", "cfo", "coo", "president", "vice president", "executive",
        "board of directors", "on behalf of", "acting on behalf",
        "urgent request from", "direct wire", "confidential transfer",
        "do not discuss", "strictly confidential", "personal matter",
        "not to be shared", "private and confidential",
    ],
    "shipping_delivery": [
        "your package", "your shipment", "delivery notification",
        "delivery attempt failed", "delivery failed", "unable to deliver",
        "fedex", "ups", "dhl", "usps", "royal mail", "parcel",
        "tracking number", "customs fee", "shipping fee", "release fee",
        "reschedule delivery", "delivery address",
    ],
    "document_share": [
        "shared a document", "shared a file", "has shared with you",
        "google docs", "google drive", "dropbox", "wetransfer",
        "view document", "open document", "sign document", "docusign",
        "adobe sign", "requires your signature", "please review",
        "view attachment", "download attachment",
    ],
}

# ── Anchor-text vs href mismatch patterns ────────────────────────────────────
# Trusted-brand tokens whose presence in anchor text (but not in the real
# href host) is a strong spoofing signal.
TRUSTED_BRAND_TOKENS: list[str] = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "outlook", "office365", "onedrive", "sharepoint", "docusign",
    "fedex", "ups", "dhl", "usps", "wellsfargo", "chase", "citibank",
    "bankofamerica", "hsbc", "barclays",
]


class LureMatch(NamedTuple):
    category: str       # e.g. "invoice_payment"
    matched_keywords: list[str]


class AnchorMismatch(NamedTuple):
    display_text: str   # what the user sees
    href: str           # actual destination
    reason: str         # human-readable explanation


# ── Domain/URL helpers ────────────────────────────────────────────────────────

def domain_tld(domain: str | None) -> str | None:
    if not domain or "." not in domain:
        return None
    return "." + domain.rsplit(".", 1)[-1].lower()


def is_suspicious_tld(domain: str | None, suspicious_tlds: list[str]) -> bool:
    tld = domain_tld(domain)
    if not tld:
        return False
    return tld in {t.lower() for t in suspicious_tlds}


def is_punycode_domain(domain: str | None) -> bool:
    """IDN homograph domains are encoded as one or more xn-- labels, e.g.
    xn--mcrosoft-x2e.com rendering as a lookalike of microsoft.com."""
    if not domain:
        return False
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def is_url_shortener(url: str, shortener_domains: list[str]) -> bool:
    after_scheme = url.split("://", 1)[-1]
    host = after_scheme.split("/", 1)[0].split(":", 1)[0].lower()
    return host in {d.lower() for d in shortener_domains}


_LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _normalize_for_comparison(domain: str) -> str:
    return domain.translate(_LEETSPEAK_MAP)


def find_lookalike_domain(
    sender_domain: str | None,
    brand_domains: dict[str, list[str]],
    threshold_pct: int,
) -> tuple[str, str] | None:
    """Flags a sender domain that's a close-but-not-exact match to a known
    legitimate brand domain -- catches both typosquats (micros0ft.com, via
    leetspeak-normalized character similarity) and combosquats
    (paypal-secure-login.com, via a brand-name substring check), even when
    the brand name never appears in the display name (the original CLI's
    brand-mismatch check requires that)."""
    if not sender_domain:
        return None

    threshold = threshold_pct / 100
    normalized_sender = _normalize_for_comparison(sender_domain)
    normalized_compact = normalized_sender.replace("-", "").replace(".", "")
    best: tuple[str, str] | None = None
    best_ratio = 0.0

    # BUG-07 fix: check the legitimate-domain exemption BEFORE any brand
    # matching runs.  Previously the exemption was inside the per-brand loop
    # and came AFTER the brand_token substring check, meaning a genuine
    # subdomain like "microsoft-support.microsoft.com" would be flagged as a
    # lookalike before the exemption could fire.  Now we scan every brand's
    # legit list upfront so the per-brand logic only sees non-exempt domains.
    for _brand, _legit_domains in brand_domains.items():
        _legit_lowers = [d.lower() for d in _legit_domains]
        if any(
            sender_domain == d or sender_domain.endswith("." + d)
            for d in _legit_lowers
        ):
            return None

    for brand, legit_domains in brand_domains.items():
        legit_lowers = [d.lower() for d in legit_domains]

        brand_token = re.sub(r"[^a-z0-9]", "", brand.lower())
        if brand_token and brand_token in normalized_compact:
            return brand, legit_domains[0]

        for legit in legit_lowers:
            ratio = difflib.SequenceMatcher(None, normalized_sender, legit).ratio()
            if ratio >= threshold and ratio > best_ratio:
                best_ratio = ratio
                best = (brand, legit)

    return best


def has_dangerous_extension(filename: str | None) -> bool:
    if not filename:
        return False
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS)


def has_double_extension(filename: str | None) -> bool:
    """Catches "invoice.pdf.exe"-style disguises: a common document
    extension immediately followed by a dangerous one."""
    if not filename:
        return False
    parts = filename.lower().rsplit(".", 2)
    if len(parts) != 3:
        return False
    _, first_ext, second_ext = parts
    return f".{first_ext}" in _COMMON_DOCUMENT_EXTENSIONS and f".{second_ext}" in DANGEROUS_EXTENSIONS


def find_urgency_keywords(text: str, keywords: list[str]) -> list[str]:
    """Return the subset of *keywords* that appear in *text* as whole words.

    Uses word-boundary anchors so short tokens like "coo" do not match inside
    "cooperation".  Input text is normalised before matching; the original
    keyword strings (as provided) are returned in the hit list.
    """
    if not text or not keywords:
        return []
    norm = normalize_body_text(text)
    found = []
    for kw in keywords:
        pattern = r"(?<!\w)" + re.escape(kw.casefold()) + r"(?!\w)"
        if re.search(pattern, norm):
            found.append(kw)
    return found


# ── Phase-1 additions ─────────────────────────────────────────────────────────

def detect_lure_categories(
    body_text: str,
    already_scored_phrases: "set[str] | None" = None,
) -> list[LureMatch]:
    """Scan the email body for lure-category keywords.

    Rules (all new):
    - Text is normalised once (NBSP, zero-width chars, casefolded, whitespace
      collapsed) before matching.
    - Every keyword is matched with word-boundary anchors so "ups" does not
      fire inside "groups" and "coo" does not fire inside "cooperation".
    - A category fires ONLY when at least 2 DISTINCT keywords from it match.
    - Phrases that were already matched by the urgency-keyword check (passed in
      via *already_scored_phrases*) are excluded from scoring here to prevent
      double-counting; they still appear in matched_keywords so the reason
      string is informative.
    - At most 2 categories score points.  Categories beyond the first two are
      still returned in the list but carry ``scored=False`` in their NamedTuple
      (callers should check ``LureMatch.scored``).

    Returns a list of LureMatch named-tuples (only for categories with ≥2
    distinct keyword hits).  exec_impersonation and account_takeover are
    placed first so they absorb the 2-category scoring budget first.
    """
    if not body_text:
        return []

    norm = normalize_body_text(body_text)

    # Priority order: high-value lures score first
    _PRIORITY = ["exec_impersonation", "account_takeover"]
    ordered_cats = _PRIORITY + [c for c in LURE_KEYWORDS if c not in _PRIORITY]

    matches: list[LureMatch] = []

    for category in ordered_cats:
        keywords = LURE_KEYWORDS.get(category, [])
        # Use word-boundary matching
        hits: list[str] = []
        seen_kws: set[str] = set()
        for kw in keywords:
            if kw in seen_kws:
                continue
            pattern = r"(?<!\w)" + re.escape(kw.casefold()) + r"(?!\w)"
            if re.search(pattern, norm):
                seen_kws.add(kw)
                hits.append(kw)

        if len(hits) >= 2:
            matches.append(LureMatch(category=category, matched_keywords=hits))

    return matches


# ── Known URL-wrapper / tracker hosts ────────────────────────────────────────
# A mismatch where the href host is one of these well-known wrappers is NOT
# flagged as an anchor mismatch — provided the brand token also appears in
# either the sender's registered domain or the unwrapped destination URL.
# Real spoofs (e.g. text "paypal.com", href to an unrelated domain with none
# of these wrappers) still score 3 pts.

_WRAPPER_TRACKER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"safelinks\.protection\.outlook\.com", re.I),
    re.compile(r"iris\.microsoft\.com", re.I),
    re.compile(r"(?:^|\.)(google\.com)$", re.I),      # google.com/url redirect
    re.compile(r"list-manage\.com", re.I),
    re.compile(r"sendgrid\.net", re.I),
    re.compile(r"(?:^|\.)(hubspot\.com|hs-sites\.com|hsconnections\.com)", re.I),
    re.compile(r"mandrillapp\.com", re.I),
]


def _is_wrapper_host(host: str) -> bool:
    """Return True when *host* is a known URL-wrapper / tracker service."""
    return any(p.search(host) for p in _WRAPPER_TRACKER_PATTERNS)


def _unwrap_url(href: str) -> str | None:
    """Try to extract the real destination from a wrapper URL.

    Handles common patterns:
    - SafeLinks: ?url=<encoded>
    - Google: /url?q=<encoded>
    - Generic: url= / redirect_to= / dest= / target= query params
    """
    try:
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(href)
        qs = parse_qs(parsed.query)
        for key in ("url", "q", "redirect_to", "dest", "target", "u"):
            vals = qs.get(key)
            if vals:
                return unquote(vals[0])
    except Exception:
        pass
    return None


def detect_anchor_mismatches(
    html_body: str,
    sender_domain: "str | None" = None,
) -> list[AnchorMismatch]:
    """Parse HTML anchor tags and flag cases where the visible text implies a
    trusted brand or URL but the actual href points somewhere else.

    MED-01 fix: uses BeautifulSoup for parsing (avoids ReDoS from a
    hand-rolled regex with DOTALL on attacker-controlled HTML), and caps
    input size to _MAX_HTML_SCAN_BYTES.

    Three signals are checked:
    1. Anchor text contains a recognisable brand token but the href host does
       not contain that same token — classic phishing button disguise.
    2. Anchor text looks like a URL (starts with http/https) but differs from
       the href — the "displayed URL" trick.

    Allowlist (new):
    When the href host is a known wrapper/tracker (SafeLinks, Google /url,
    SendGrid, HubSpot, Mailchimp/list-manage, Mandrill), a mismatch is
    suppressed ONLY if the brand token also appears in:
      - the sender's registered domain, OR
      - the unwrapped destination URL host.
    If neither condition holds, it's still a real spoof and fires.
    """
    if not html_body:
        return []

    # MED-01: Cap input size to prevent ReDoS / resource exhaustion on crafted HTML
    if len(html_body) > _MAX_HTML_SCAN_BYTES:
        html_body = html_body[:_MAX_HTML_SCAN_BYTES]

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_body, "html.parser")
        anchors = soup.find_all("a", href=True)
    except Exception:
        # BeautifulSoup unavailable or parse failure — skip detection
        return []

    # Normalise sender domain for brand-token checks
    _sender = (sender_domain or "").lower().replace("-", "").replace(".", "")

    mismatches: list[AnchorMismatch] = []
    seen: set[tuple[str, str]] = set()

    for tag in anchors:
        href = (tag.get("href") or "").strip()
        display = tag.get_text(separator=" ", strip=True)[:200]

        if not href or not display:
            continue

        key = (display.lower()[:80], href.lower()[:120])
        if key in seen:
            continue
        seen.add(key)

        href_host = _href_host(href)
        display_lower = display.lower()

        # Signal 1: brand token in display text but not in href host
        for token in TRUSTED_BRAND_TOKENS:
            if token in display_lower.replace(" ", "").replace(".", ""):
                if href_host and token not in href_host.replace("-", "").replace(".", ""):
                    # Check wrapper/tracker allowlist
                    if _is_wrapper_host(href_host):
                        # Suppress only if brand token is in sender domain
                        # OR in the unwrapped destination host
                        if token in _sender:
                            break  # legitimate marketing mail from the brand
                        unwrapped = _unwrap_url(href)
                        if unwrapped:
                            unwrapped_host = _href_host(unwrapped) or ""
                            if token in unwrapped_host.replace("-", "").replace(".", ""):
                                break  # wrapper points to the brand's own domain
                        # Brand not found in sender or destination → real spoof
                    mismatches.append(AnchorMismatch(
                        display_text=display,
                        href=href,
                        reason=f"Display text implies '{token}' but href points to '{href_host}'",
                    ))
                    break

        # Signal 2: display text looks like a URL but differs from actual href
        if display_lower.startswith(("http://", "https://")):
            disp_host = _href_host(display)
            if disp_host and href_host and disp_host != href_host:
                mismatches.append(AnchorMismatch(
                    display_text=display,
                    href=href,
                    reason=f"Displayed URL host '{disp_host}' differs from actual href host '{href_host}'",
                ))

    return mismatches


def _href_host(url: str) -> str | None:
    """Extract the hostname from a URL string without importing urllib."""
    try:
        after_scheme = url.split("://", 1)
        if len(after_scheme) < 2:
            return None
        host = after_scheme[1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
        return host.lower().strip() or None
    except Exception:
        return None


def extract_html_bodies(parsed: dict) -> list[str]:
    """Return all text/html body parts from an eml_parser result dict."""
    from backend.services.eml_parser_service import normalize_body
    parts = normalize_body(parsed.get("body", {}))
    html_parts: list[str] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        ct = (part.get("content_type") or part.get("mime_type") or "").lower()
        content = part.get("content")
        if "text/html" in ct and content:
            if isinstance(content, list):
                content = " ".join(str(c) for c in content)
            html_parts.append(str(content))
    return html_parts
