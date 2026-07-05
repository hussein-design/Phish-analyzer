"""Additional phishing-detection heuristics beyond the original CLI's rule
set: lookalike/typosquat domains, punycode homographs, suspicious TLDs,
URL shorteners, dangerous/double file extensions, and urgency language.

Each function is a pure, stdlib-only check so scoring_service can call them
without adding new runtime dependencies.
"""

from __future__ import annotations

import difflib
import re

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
