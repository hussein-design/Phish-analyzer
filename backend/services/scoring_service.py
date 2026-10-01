"""Rules engine. Ports compute_score() from the original CLI and extends it
with several signals the CLI never had: lookalike/typosquat sender domains,
punycode/IDN homographs, suspicious TLDs, URL shorteners, dangerous/double
file extensions, and urgency language in the body. Reads weights from the
app_settings DB row (via the caller) instead of config.yaml.

Every url/attachment row-dict is mutated in place to record which indicator
tripped a rule, so the caller can persist those flags onto
UrlIndicator/AttachmentIndicator rows.
"""

from __future__ import annotations

import re

from backend.services import threat_signals

VERDICT_PHISHING = "phishing"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign"

_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _url_host(url: str) -> str:
    after_scheme = url.split("://", 1)[-1]
    return after_scheme.split("/", 1)[0].split(":", 1)[0]


def compute_score(
    *,
    from_addr: str | None,
    from_domain: str | None,
    auth: dict,
    header_issues: list[str],
    urls: list[dict],
    attachments: list[dict],
    abuse_result: dict,
    sender_ip: str | None,
    body_text: str,
    scoring_weights: dict,
    brand_domains: dict,
    url_suspicious_keywords: list[str],
    suspicious_tlds: list[str],
    url_shorteners: list[str],
    urgency_keywords: list[str],
    # Phase 1 additions — optional so old callers don't break
    lure_categories: list[dict] | None = None,
    anchor_mismatches: list[dict] | None = None,
    # Phase 1 dynamic analysis additions — optional; None means "not run"
    url_detonation_result: dict | None = None,
    attachment_detonation_result: dict | None = None,
) -> dict:
    score = 0
    reasons: list[str] = []

    pts_brand_mismatch = scoring_weights.get("brand_mismatch", 2)
    pts_spf_fail = scoring_weights.get("spf_fail", 2)
    pts_dkim_fail = scoring_weights.get("dkim_fail", 2)
    pts_dmarc_fail = scoring_weights.get("dmarc_fail", 2)
    pts_header_issue = scoring_weights.get("header_issue", 1)
    pts_url_keyword = scoring_weights.get("url_bad_keyword", 2)
    pts_url_ip_host = scoring_weights.get("url_ip_host", 3)
    pts_attach_exec = scoring_weights.get("attachment_executable", 3)
    vt_thresh = scoring_weights.get("vt_malicious_threshold", 3)
    vt_pts = scoring_weights.get("vt_malicious_points", 4)
    abuse_thresh = scoring_weights.get("abuseipdb_high_score", 50)
    abuse_pts = scoring_weights.get("abuseipdb_points", 3)
    pts_lookalike = scoring_weights.get("brand_domain_lookalike", 3)
    lookalike_threshold = scoring_weights.get("brand_domain_lookalike_threshold", 82)
    pts_suspicious_tld = scoring_weights.get("suspicious_tld", 2)
    pts_punycode = scoring_weights.get("punycode_domain", 3)
    pts_url_shortener = scoring_weights.get("url_shortener", 1)
    pts_double_ext = scoring_weights.get("attachment_double_extension", 4)
    pts_urgency = scoring_weights.get("body_urgency_keyword", 1)
    pts_lure_category = scoring_weights.get("lure_category", 2)
    pts_anchor_mismatch = scoring_weights.get("anchor_mismatch", 3)
    pts_macro_enabled = scoring_weights.get("macro_enabled", 4)
    pts_embedded_exe = scoring_weights.get("embedded_executable", 5)
    pts_mime_mismatch = scoring_weights.get("mime_magic_mismatch", 3)
    pts_vt_hash = scoring_weights.get("vt_hash_malicious_points", 5)
    pts_redirect_suspicious = scoring_weights.get("redirect_suspicious", 3)
    # Phase 1 dynamic analysis weights
    pts_urlscan_malicious   = scoring_weights.get("urlscan_malicious", 4)
    pts_urlscan_suspicious  = scoring_weights.get("urlscan_suspicious", 2)
    pts_dyn_att_malicious   = scoring_weights.get("dynamic_attachment_malicious", 5)
    pts_dyn_att_suspicious  = scoring_weights.get("dynamic_attachment_suspicious", 3)

    from_addr = from_addr or ""

    # Brand impersonation via display name (requires the brand name to
    # appear in the From display, e.g. "Microsoft Support" <bad@evil.com>).
    if "@" in from_addr and from_domain:
        display_lower = from_addr.lower()
        for brand, legit_domains in brand_domains.items():
            if brand.lower() in display_lower:
                if not any(ld.lower() in from_domain for ld in legit_domains):
                    score += pts_brand_mismatch
                    reasons.append(
                        f"Brand '{brand}' in display but sender domain "
                        f"'{from_domain}' not in legit domains {legit_domains}"
                    )
                break

    # Lookalike/typosquat/combosquat sender domain -- catches spoofs even
    # when the brand name never appears in the display name at all.
    is_lookalike_domain = False
    lookalike_of: str | None = None
    lookalike = threat_signals.find_lookalike_domain(
        from_domain, brand_domains, lookalike_threshold
    )
    if lookalike:
        brand, legit = lookalike
        is_lookalike_domain = True
        lookalike_of = legit
        score += pts_lookalike
        reasons.append(
            f"Sender domain '{from_domain}' closely resembles legitimate "
            f"domain '{legit}' ({brand}) without being it"
        )

    is_punycode_domain = threat_signals.is_punycode_domain(from_domain)
    if is_punycode_domain:
        score += pts_punycode
        reasons.append(
            f"Sender domain '{from_domain}' uses punycode encoding "
            f"(possible IDN homograph spoof)"
        )

    is_suspicious_sender_tld = threat_signals.is_suspicious_tld(from_domain, suspicious_tlds)
    if is_suspicious_sender_tld:
        score += pts_suspicious_tld
        reasons.append(f"Sender domain '{from_domain}' uses a commonly abused TLD")

    # Auth failures
    if auth.get("spf") == "fail":
        score += pts_spf_fail
        reasons.append("SPF failed for this message")
    if auth.get("dkim") == "fail":
        score += pts_dkim_fail
        reasons.append("DKIM failed for this message")
    if auth.get("dmarc") == "fail":
        score += pts_dmarc_fail
        reasons.append("DMARC failed for this message")

    # Header issues
    for issue in header_issues:
        score += pts_header_issue
        reasons.append(issue)

    # URL-based checks. Every qualifying URL gets its own flag set (so each
    # indicator row reflects its own state), but each rule only contributes
    # its point value once per analysis, not once per matching URL.
    keyword_hit = ip_host_hit = shortener_hit = url_tld_hit = url_punycode_hit = None
    redirect_suspicious_hit = None

    for u in urls:
        host = _url_host(u["url"])

        if any(k.lower() in u["url"].lower() for k in url_suspicious_keywords):
            u["is_suspicious_keyword"] = True
            keyword_hit = keyword_hit or u["url"]

        if _IP_HOST_RE.match(host):
            u["is_ip_host"] = True
            ip_host_hit = ip_host_hit or u["url"]

        if threat_signals.is_url_shortener(u["url"], url_shorteners):
            u["is_shortener"] = True
            shortener_hit = shortener_hit or u["url"]

        if threat_signals.is_suspicious_tld(host, suspicious_tlds):
            u["is_suspicious_tld"] = True
            url_tld_hit = url_tld_hit or u["url"]

        if threat_signals.is_punycode_domain(host):
            u["is_punycode"] = True
            url_punycode_hit = url_punycode_hit or u["url"]

        # Phase 4: redirect suspicious flag set by url_intelligence_service
        if u.get("is_redirect_suspicious") and not redirect_suspicious_hit:
            redirect_suspicious_hit = u["url"]

    if keyword_hit:
        score += pts_url_keyword
        reasons.append(f"URL contains suspicious keyword: {keyword_hit}")
    if ip_host_hit:
        score += pts_url_ip_host
        reasons.append(f"URL uses raw IP address as host: {ip_host_hit}")
    if shortener_hit:
        score += pts_url_shortener
        reasons.append(f"URL uses a link-shortening service: {shortener_hit}")
    if url_tld_hit:
        score += pts_suspicious_tld
        reasons.append(f"URL uses a commonly abused top-level domain: {url_tld_hit}")
    if url_punycode_hit:
        score += pts_punycode
        reasons.append(f"URL uses punycode encoding (possible IDN homograph): {url_punycode_hit}")
    if redirect_suspicious_hit:
        score += pts_redirect_suspicious
        reasons.append(f"Suspicious redirect chain detected: {redirect_suspicious_hit}")

    # Attachment checks -- same "flag every match, score once per rule" shape.
    exec_hit = None
    double_ext_hit = None

    for att in attachments:
        filename = att.get("filename")
        mime = (att.get("content_type") or "").lower()

        if threat_signals.has_dangerous_extension(filename) or any(
            x in mime for x in ["exe", "msdownload", "script"]
        ):
            att["is_executable_like"] = True
            exec_hit = exec_hit or (filename, mime)

        if threat_signals.has_double_extension(filename):
            att["is_double_extension"] = True
            double_ext_hit = double_ext_hit or filename

    if exec_hit:
        fn, mime = exec_hit
        score += pts_attach_exec
        reasons.append(f"Executable-like attachment: {fn} ({mime})")
    if double_ext_hit:
        score += pts_double_ext
        reasons.append(f"Attachment uses a disguised double extension: {double_ext_hit}")

    # Phase 3: static attachment intelligence scoring
    macro_hit = mime_mismatch_hit = embedded_exe_hit = None
    vt_hash_hit = None

    for att in attachments:
        if att.get("is_macro_enabled") and not macro_hit:
            macro_hit = att.get("filename", "unknown")
        if att.get("mime_magic_mismatch") and not mime_mismatch_hit:
            mime_mismatch_hit = att.get("filename", "unknown")
        if att.get("has_embedded_executable") and not embedded_exe_hit:
            embedded_exe_hit = att.get("filename", "unknown")
        mal = att.get("vt_hash_malicious", 0) or 0
        if mal > 0 and not vt_hash_hit:
            vt_hash_hit = (att.get("filename", "unknown"), mal)

    if macro_hit:
        score += pts_macro_enabled
        reasons.append(f"Macro-enabled Office document attached: {macro_hit}")
    if embedded_exe_hit:
        score += pts_embedded_exe
        reasons.append(f"Embedded executable detected in attachment: {embedded_exe_hit}")
    if mime_mismatch_hit:
        score += pts_mime_mismatch
        reasons.append(
            f"MIME type magic-byte mismatch in attachment: {mime_mismatch_hit} "
            "(declared type does not match actual file signature)"
        )
    if vt_hash_hit:
        fn, mal = vt_hash_hit
        score += pts_vt_hash
        reasons.append(f"VirusTotal: attachment '{fn}' flagged malicious by {mal} engines")

    # VirusTotal-based scoring
    # BUG-06 fix: score once per analysis, not once per matching URL.
    # Every other rule in this function follows the "hit-once" pattern;
    # the old loop incremented the score for EACH URL that exceeded the
    # threshold, inflating the score arbitrarily for emails with many URLs.
    vt_url_hit: tuple[str, int] | None = None
    for u in urls:
        mal = u.get("vt_malicious", 0) or 0
        if mal >= vt_thresh and vt_url_hit is None:
            vt_url_hit = (u["url"], mal)
    if vt_url_hit:
        hit_url, hit_mal = vt_url_hit
        score += vt_pts
        reasons.append(f"VirusTotal: URL {hit_url} flagged malicious by {hit_mal} engines")

    # AbuseIPDB-based scoring
    if abuse_result:
        abuse_score = abuse_result.get("abuse_score")
        if abuse_score is not None and abuse_score >= abuse_thresh:
            score += abuse_pts
            reasons.append(f"AbuseIPDB: sender IP {sender_ip} abuse score {abuse_score}")

    # Body urgency/social-engineering language
    urgency_found = threat_signals.find_urgency_keywords(body_text, urgency_keywords)
    if urgency_found:
        score += pts_urgency
        reasons.append(f"Body contains urgency/pressure language: {', '.join(urgency_found)}")

    # Phase 1: Lure-category scoring — each unique category fires once.
    # High-confidence categories (exec impersonation) score more.
    _HIGH_VALUE_LURES = {"exec_impersonation", "account_takeover"}
    if lure_categories:
        for lure in lure_categories:
            cat = lure.get("category", "")
            kws = lure.get("matched_keywords", [])
            pts = pts_lure_category + (1 if cat in _HIGH_VALUE_LURES else 0)
            score += pts
            reasons.append(
                f"Lure category '{cat}' detected — keywords: {', '.join(kws[:4])}"
                + (" …" if len(kws) > 4 else "")
            )

    # Phase 1: Anchor text vs href mismatch — score once regardless of count.
    if anchor_mismatches:
        score += pts_anchor_mismatch
        first = anchor_mismatches[0]
        reasons.append(
            f"Anchor text/href mismatch: {first.get('reason', 'display text differs from href')}"
            + (f" (+{len(anchor_mismatches) - 1} more)" if len(anchor_mismatches) > 1 else "")
        )

    # ── Static sub-score is everything computed above ─────────────────────────
    static_score = score
    static_reasons = list(reasons)

    # ── Phase 1 dynamic analysis scoring ─────────────────────────────────────
    # Dynamic signals are scored separately and added to the total.  The split
    # is preserved in the return dict so callers can show a clear breakdown.
    dynamic_score = 0
    dynamic_reasons: list[str] = []

    # URL detonation (urlscan.io)
    if url_detonation_result and url_detonation_result.get("status") == "done":
        ud_verdict = (url_detonation_result.get("verdict") or "").lower()
        ud_score   = url_detonation_result.get("score")
        ud_url     = url_detonation_result.get("final_url") or "submitted URL"

        if ud_verdict == "malicious" or url_detonation_result.get("malicious"):
            dynamic_score += pts_urlscan_malicious
            dynamic_reasons.append(
                f"urlscan.io: URL detonation verdict malicious "
                f"(score={ud_score}) — {ud_url}"
            )
        elif ud_verdict == "suspicious":
            dynamic_score += pts_urlscan_suspicious
            dynamic_reasons.append(
                f"urlscan.io: URL detonation verdict suspicious "
                f"(score={ud_score}) — {ud_url}"
            )

    # Attachment detonation (Hybrid Analysis / Any.run behavioral report)
    if attachment_detonation_result and attachment_detonation_result.get("status") == "done":
        ad_verdict = (attachment_detonation_result.get("verdict") or "").lower()
        ad_score   = attachment_detonation_result.get("score")
        ad_procs   = attachment_detonation_result.get("processes") or []
        ad_net     = attachment_detonation_result.get("network_calls") or []

        detail_parts: list[str] = []
        if ad_procs:
            detail_parts.append(f"processes: {', '.join(ad_procs[:3])}")
        if ad_net:
            detail_parts.append(f"network: {', '.join(ad_net[:3])}")
        detail = "; ".join(detail_parts)

        if ad_verdict == "malicious":
            dynamic_score += pts_dyn_att_malicious
            dynamic_reasons.append(
                f"Sandbox detonation verdict malicious (score={ad_score})"
                + (f" — {detail}" if detail else "")
            )
        elif ad_verdict in ("suspicious",):
            dynamic_score += pts_dyn_att_suspicious
            dynamic_reasons.append(
                f"Sandbox detonation verdict suspicious (score={ad_score})"
                + (f" — {detail}" if detail else "")
            )

    # Merge dynamic signals into the combined totals
    score += dynamic_score
    reasons.extend(dynamic_reasons)

    if score >= 9:
        verdict = VERDICT_PHISHING
    elif score >= 5:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_BENIGN

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "header_flags": {
            "is_lookalike_domain": is_lookalike_domain,
            "lookalike_of": lookalike_of,
            "is_punycode_domain": is_punycode_domain,
            "is_suspicious_sender_tld": is_suspicious_sender_tld,
        },
        "urgency_keywords_found": urgency_found,
        # Static vs dynamic contribution (Phase 1 dynamic analysis)
        "static_score":    static_score,
        "static_reasons":  static_reasons,
        "dynamic_score":   dynamic_score,
        "dynamic_reasons": dynamic_reasons,
    }
