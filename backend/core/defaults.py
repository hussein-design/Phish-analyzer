"""Default scoring configuration, ported from the old config.yaml.

Used only to seed the single app_settings row on first run -- after that,
the DB row is the live source of truth, editable from the Settings dialog.
"""

DEFAULT_SCORING_WEIGHTS: dict[str, int] = {
    "brand_mismatch": 2,
    "spf_fail": 2,
    "dkim_fail": 2,
    "dmarc_fail": 2,
    "header_issue": 1,
    "url_bad_keyword": 2,
    "url_ip_host": 3,
    "attachment_executable": 3,
    "vt_malicious_threshold": 3,
    "vt_malicious_points": 4,
    "abuseipdb_high_score": 50,
    "abuseipdb_points": 3,
    "brand_domain_lookalike": 3,
    "brand_domain_lookalike_threshold": 82,
    "suspicious_tld": 2,
    "punycode_domain": 3,
    "url_shortener": 1,
    "attachment_double_extension": 4,
    "body_urgency_keyword": 1,
}

DEFAULT_SUSPICIOUS_TLDS: list[str] = [
    ".zip", ".mov", ".xyz", ".top", ".click", ".work", ".link", ".support",
    ".country", ".kim", ".cricket", ".science", ".gq", ".tk", ".ml",
    ".men", ".loan", ".download", ".stream",
]

DEFAULT_URL_SHORTENERS: list[str] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
]

DEFAULT_URGENCY_KEYWORDS: list[str] = [
    "act now", "urgent", "immediately", "account suspended", "account will be closed",
    "verify your account", "confirm your identity", "unusual activity",
    "limited time", "click here", "final notice", "restricted access",
]

DEFAULT_BRAND_DOMAINS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "paypal": ["paypal.com"],
    "sam's club": ["samsclub.com"],
}

DEFAULT_URL_SUSPICIOUS_KEYWORDS: list[str] = [
    "login",
    "verify",
    "update",
    "password",
    "secure",
    "invoice",
]
