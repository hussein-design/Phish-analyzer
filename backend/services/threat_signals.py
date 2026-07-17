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

# ── Lure category keyword sets ────────────────────────────────────────────────
# Each set covers the most common attacker vocabulary for that lure type.
# Matching is case-insensitive substring search over the full body text.

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

    for brand, legit_domains in brand_domains.items():
        legit_lowers = [d.lower() for d in legit_domains]

        # Exempt genuinely legitimate domains/subdomains (unnormalized --
        # normalizing here would make e.g. micros0ft.com == microsoft.com).
        if any(sender_domain == d or sender_domain.endswith("." + d) for d in legit_lowers):
            return None

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
    if not text or not keywords:
        return []
    lower = text.lower()
    found = []
    for kw in keywords:
        if re.search(re.escape(kw.lower()), lower):
            found.append(kw)
    return found


# ── Phase-1 additions ─────────────────────────────────────────────────────────

def detect_lure_categories(body_text: str) -> list[LureMatch]:
    """Scan the email body for lure-category keywords.

    Returns a list of LureMatch named-tuples for every category that fires
    at least one keyword hit.  Multiple categories can match simultaneously
    (e.g. a message can be both an invoice lure and an urgency lure).
    """
    if not body_text:
        return []

    lower = body_text.lower()
    matches: list[LureMatch] = []

    for category, keywords in LURE_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in lower]
        if hits:
            matches.append(LureMatch(category=category, matched_keywords=hits))

    return matches


def detect_anchor_mismatches(html_body: str) -> list[AnchorMismatch]:
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
