"""Separated data-binding logic for ReportPage.

populate(page, detail) fills every card/label from the EmailDetail schema.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout

from frontend.widgets.report_widgets import Chip, auth_chip, body_label
from shared.schemas import EmailDetail


def populate(page, detail: EmailDetail) -> None:
    page._analysis_id = detail.id
    page._title_label.setText(
        f"{detail.filename}  —  {detail.subject or '(no subject)'}"
    )
    page._verdict_badge.set_verdict(detail.verdict.value if detail.verdict else None)
    page._score_ring.set_score(
        detail.score, detail.verdict.value if detail.verdict else None
    )

    _populate_overview(page, detail)
    _populate_headers(page, detail)
    _populate_urls(page, detail)
    _populate_attachments(page, detail)
    _populate_intel(page, detail)
    _populate_body(page, detail)


# ── Overview tab ──────────────────────────────────────────────────────────────

def _populate_overview(page, detail: EmailDetail) -> None:
    h = detail.header_info

    # ── Narrative story ───────────────────────────────────────────────────
    page._lbl_narrative.setText(_build_narrative(detail))

    # ── Summary KV ────────────────────────────────────────────────────────
    page._kv_summary.set_rows([
        ("From",       detail.from_addr),
        ("Subject",    detail.subject),
        ("Message-ID", detail.message_id),
        ("Uploaded",   detail.created_at.strftime("%Y-%m-%d  %H:%M:%S UTC")),
        ("Status",     detail.status.value if detail.status else "—"),
    ])

    # ── Auth chips ────────────────────────────────────────────────────────
    _clear_layout(page._auth_lyt)
    row = QHBoxLayout()
    row.setSpacing(10)
    row.setContentsMargins(0, 0, 0, 0)
    row.addWidget(auth_chip("SPF",   h.auth.spf))
    row.addWidget(auth_chip("DKIM",  h.auth.dkim))
    row.addWidget(auth_chip("DMARC", h.auth.dmarc))
    row.addStretch()
    page._auth_lyt.addLayout(row)

    for flag_text in _domain_flags(h):
        warn = Chip(f"⚠  {flag_text}", "warn")
        warn.setMaximumWidth(9999)
        page._auth_lyt.addWidget(warn)

    # ── Reasons ───────────────────────────────────────────────────────────
    if detail.reasons:
        page._lbl_reasons.setText(
            "\n".join(f"{i+1}.  {r}" for i, r in enumerate(detail.reasons))
        )
    else:
        page._lbl_reasons.setText("No specific red flags triggered by the current rules.")

    # ── Lure categories ───────────────────────────────────────────────────
    lures = detail.lure_categories or []
    if lures:
        lines = []
        for lure in lures:
            cat = lure.get("category", "unknown").replace("_", " ").title()
            kws = lure.get("matched_keywords", [])
            kw_str = ",  ".join(kws[:6]) + ("  …" if len(kws) > 6 else "")
            lines.append(f"⚠  {cat}\n     Keywords matched: {kw_str}")
        page._lbl_lures.setText("\n\n".join(lines))
    else:
        page._lbl_lures.setText("✓  No social engineering lure categories detected.")

    # ── Urgency ───────────────────────────────────────────────────────────
    if detail.urgency_keywords_found:
        page._lbl_urgency.setText(",  ".join(detail.urgency_keywords_found))
    else:
        page._lbl_urgency.setText("✓  None detected.")


def _build_narrative(detail: EmailDetail) -> str:
    """Return a plain-English story of the full analysis from start to finish."""
    h = detail.header_info
    verdict = detail.verdict.value if detail.verdict else "unknown"
    score = detail.score if detail.score is not None else 0
    lines: list[str] = []

    # ── Opening: what arrived ─────────────────────────────────────────────
    sender = detail.from_addr or "an unknown sender"
    subject = detail.subject or "(no subject)"
    lines.append(
        f"An email arrived from {sender} with the subject \"{subject}\". "
        f"It was submitted for analysis on "
        f"{detail.created_at.strftime('%Y-%m-%d at %H:%M UTC')}."
    )

    # ── Sender domain flags ───────────────────────────────────────────────
    domain_issues = _domain_flags(h)
    if domain_issues:
        lines.append(
            "The sender domain raised concern: " + "; ".join(domain_issues) + "."
        )
    else:
        if h.from_domain:
            lines.append(f"The sender domain ({h.from_domain}) did not match any known lookalike patterns.")

    # ── Authentication ────────────────────────────────────────────────────
    auth_issues = [
        p for p, v in [("SPF", h.auth.spf), ("DKIM", h.auth.dkim), ("DMARC", h.auth.dmarc)]
        if v in ("fail", "softfail")
    ]
    auth_pass = [
        p for p, v in [("SPF", h.auth.spf), ("DKIM", h.auth.dkim), ("DMARC", h.auth.dmarc)]
        if v == "pass"
    ]
    if auth_issues:
        lines.append(
            f"Email authentication checks failed for: {', '.join(auth_issues)}. "
            "This means the message may not have genuinely originated from the claimed sender domain."
        )
    elif auth_pass:
        lines.append(
            f"Authentication passed for {', '.join(auth_pass)}, "
            "which is consistent with a legitimate sender."
        )

    # ── Header anomalies ──────────────────────────────────────────────────
    if h.issues:
        lines.append(
            f"The email headers contained {len(h.issues)} anomaly(s): "
            + "; ".join(h.issues[:3])
            + ("." if len(h.issues) <= 3 else f", and {len(h.issues)-3} more.")
        )

    # ── URLs ──────────────────────────────────────────────────────────────
    url_count = len(detail.urls)
    if url_count:
        suspicious_urls = [
            u for u in detail.urls
            if u.is_suspicious_keyword or u.is_ip_host or u.is_shortener
               or u.is_suspicious_tld or u.is_punycode or u.is_redirect_suspicious
               or (u.vt_malicious or 0) > 0
        ]
        lines.append(
            f"The email contained {url_count} URL(s). "
            + (
                f"{len(suspicious_urls)} of them triggered suspicious indicators "
                f"(IP-based hosts, shorteners, malicious VT detections, or redirect chains)."
                if suspicious_urls else
                "None triggered any suspicious URL indicators."
            )
        )
    else:
        lines.append("No URLs were found in the email body.")

    # ── Attachments ───────────────────────────────────────────────────────
    att_count = len(detail.attachments)
    if att_count:
        dangerous_atts = [
            a for a in detail.attachments
            if a.is_macro_enabled or a.has_embedded_executable
               or a.is_double_extension or a.mime_magic_mismatch
               or (a.vt_hash_malicious or 0) > 0
        ]
        lines.append(
            f"There were {att_count} attachment(s). "
            + (
                f"{len(dangerous_atts)} raised static-analysis flags "
                "(macros, embedded executables, or MIME mismatches)."
                if dangerous_atts else
                "None raised any static-analysis flags."
            )
        )
    else:
        lines.append("The email had no attachments.")

    # ── Sender IP reputation ──────────────────────────────────────────────
    if detail.abuse_result and detail.abuse_result.abuse_score is not None:
        ab = detail.abuse_result
        ip = h.sender_ip or "the sender IP"
        if ab.abuse_score >= 50:
            lines.append(
                f"The sending server ({ip}) has a high AbuseIPDB confidence score of "
                f"{ab.abuse_score}%, with {ab.total_reports} abuse report(s) on record."
            )
        else:
            lines.append(
                f"The sending server ({ip}) had a low AbuseIPDB abuse score ({ab.abuse_score}%)."
            )
    elif h.sender_ip:
        lines.append(
            f"The sending server IP ({h.sender_ip}) was checked but no significant "
            "abuse reports were found."
        )

    # ── Social engineering ────────────────────────────────────────────────
    lures = detail.lure_categories or []
    urgency = detail.urgency_keywords_found or []
    anchors = detail.anchor_mismatches or []
    if lures or urgency or anchors:
        se_parts = []
        if lures:
            cats = ", ".join(
                l.get("category", "").replace("_", " ").title() for l in lures
            )
            se_parts.append(f"social engineering lure categories ({cats})")
        if urgency:
            se_parts.append(f"urgency/pressure language ({', '.join(urgency[:3])})")
        if anchors:
            se_parts.append(f"{len(anchors)} anchor text/href mismatch(es)")
        lines.append(
            "The message body contained " + "; ".join(se_parts) + "."
        )

    # ── Verdict ───────────────────────────────────────────────────────────
    verdict_sentences = {
        "phishing":   f"Based on a combined threat score of {score}, the email was classified as PHISHING. It shows multiple high-confidence indicators of a malicious campaign.",
        "suspicious": f"Based on a combined threat score of {score}, the email was classified as SUSPICIOUS. Some indicators were concerning but not conclusive — treat with caution.",
        "benign":     f"Based on a combined threat score of {score}, the email was classified as BENIGN. No significant threat indicators were found.",
    }
    lines.append(verdict_sentences.get(verdict, f"Final score: {score}."))

    return "\n\n".join(lines)


def _domain_flags(h) -> list[str]:
    flags = []
    if h.is_lookalike_domain:
        flags.append(f"Lookalike of {h.lookalike_of}")
    if h.is_punycode_domain:
        flags.append("Punycode / IDN homograph encoding")
    if h.is_suspicious_sender_tld:
        flags.append("Suspicious TLD")
    return flags


# ── Headers tab ───────────────────────────────────────────────────────────────

def _populate_headers(page, detail: EmailDetail) -> None:
    h = detail.header_info
    page._kv_headers.set_rows([
        ("From domain",        h.from_domain),
        ("Reply-To domain",    h.reply_domain),
        ("Return-Path domain", h.return_domain),
        ("Sender IP",          h.sender_ip),
        ("Reply-To",           h.reply_to),
        ("Return-Path",        h.return_path),
    ])

    page._lbl_hdr_issues.setText(
        "\n".join(f"⚠  {i}" for i in h.issues) if h.issues
        else "✓  No header anomalies detected."
    )

    mime_parts = detail.mime_parts or []
    page._lbl_mime.setText(
        "\n".join(f"•  {p}" for p in mime_parts) if mime_parts
        else "MIME structure data not available."
    )

    anchors = detail.anchor_mismatches or []
    if anchors:
        lines = [f"⚠  {len(anchors)} mismatch(es) detected:"]
        for am in anchors[:12]:
            disp = am.get("display_text", "")
            href = am.get("href", "")
            reason = am.get("reason", "")
            # Full values — word-wrap handles long lines
            lines.append(f'\n  Display:  "{disp}"\n  Href:     {href}\n  Reason:   {reason}')
        if len(anchors) > 12:
            lines.append(f"\n  … and {len(anchors) - 12} more")
        page._lbl_anchors.setText("\n".join(lines))
    else:
        page._lbl_anchors.setText("✓  No anchor text / href mismatches detected.")


# ── URLs tab ──────────────────────────────────────────────────────────────────

def _populate_urls(page, detail: EmailDetail) -> None:
    if not detail.urls:
        page._lbl_urls.setText("No URLs found in this email.")
        page._lbl_url_intel.setText("—")
        return

    url_lines = []
    for u in detail.urls:
        flags = []
        if u.is_suspicious_keyword: flags.append("suspicious keyword")
        if u.is_ip_host:            flags.append("raw IP host")
        if u.is_shortener:          flags.append("shortener")
        if u.is_suspicious_tld:     flags.append("suspicious TLD")
        if u.is_punycode:           flags.append("punycode")
        if u.vt_malicious:          flags.append(f"VT malicious={u.vt_malicious}")
        elif u.vt_suspicious:       flags.append(f"VT suspicious={u.vt_suspicious}")
        # Full URL — label word-wraps it
        flag_str = f"\n   [{',  '.join(flags)}]" if flags else "\n   [clean]"
        url_lines.append(f"•  {u.url}{flag_str}")

    page._lbl_urls.setText("\n\n".join(url_lines))

    intel = [
        u for u in detail.urls
        if u.expanded_url or u.page_title or u.redirect_count or u.is_redirect_suspicious
    ]
    if intel:
        lines = []
        for u in intel:
            lines.append(f"•  {u.url}")   # full URL, wraps
            if u.is_redirect_suspicious:
                lines.append("   ⚠  Suspicious redirect chain detected")
            if u.redirect_count:
                lines.append(f"   Hops:         {u.redirect_count}")
            if u.expanded_url and u.expanded_url != u.url:
                lines.append(f"   Final URL:    {u.expanded_url}")   # full, wraps
            if u.page_title:
                lines.append(f"   Page title:   {u.page_title}")
            if u.final_status_code:
                lines.append(f"   HTTP status:  {u.final_status_code}")
        page._lbl_url_intel.setText("\n".join(lines))
    else:
        page._lbl_url_intel.setText("No redirect chains or page intelligence data available.")


# ── Attachments tab ───────────────────────────────────────────────────────────

def _populate_attachments(page, detail: EmailDetail) -> None:
    if not detail.attachments:
        page._lbl_att_list.setText("No attachments found.")
        page._lbl_att_intel.setText("—")
        return

    att_lines = []
    for a in detail.attachments:
        sha_str = (a.sha256[:32] + "…") if a.sha256 else "N/A"
        att_lines.append(
            f"•  {a.filename or 'unknown'}\n"
            f"   Type:    {a.content_type or '?'}\n"
            f"   SHA-256: {sha_str}"
        )
    page._lbl_att_list.setText("\n\n".join(att_lines))

    intel_lines = []
    for att in detail.attachments:
        flags = []
        if att.is_macro_enabled:        flags.append("⚠  Macro-enabled Office document")
        if att.has_embedded_executable: flags.append("⚠  Embedded executable detected")
        if att.is_archive:              flags.append("Archive file")
        if att.mime_magic_mismatch:     flags.append("⚠  MIME magic-byte mismatch")
        if att.is_executable_like:      flags.append("⚠  Dangerous extension")
        if att.is_double_extension:     flags.append("⚠  Double extension (disguised name)")
        if att.vt_hash_malicious:
            flags.append(f"⚠  VT: {att.vt_hash_malicious} engine(s) flagged malicious")
        elif att.vt_hash_suspicious:
            flags.append(f"VT: {att.vt_hash_suspicious} suspicious")
        elif att.vt_hash_status == "ok":
            flags.append("✓  VT hash clean")

        intel_lines.append(f"•  {att.filename or 'unknown'}")
        intel_lines.extend(f"   {f}" for f in flags) if flags else intel_lines.append("   ✓  No threats detected")

        meta = att.file_metadata or {}
        inner = (meta.get("file_metadata") or meta) if isinstance(meta, dict) else {}
        if isinstance(inner, dict) and inner:
            items = [f"{k}: {v}" for k, v in inner.items() if v]
            if items:
                intel_lines.append(f"   Metadata: {' | '.join(items)}")

    page._lbl_att_intel.setText("\n".join(intel_lines))


# ── Intel tab ─────────────────────────────────────────────────────────────────

def _populate_intel(page, detail: EmailDetail) -> None:
    sender_ip = detail.header_info.sender_ip

    # VirusTotal
    vt_status = detail.vt_enrichment_status
    vt_hits = [u for u in detail.urls if (u.vt_malicious or 0) > 0 or (u.vt_suspicious or 0) > 0]

    if vt_status == "no_key":
        vt_text = "⚠  No VirusTotal API key configured.\n   Go to Settings → API Keys to add one."
    elif vt_status == "rate_limit":
        vt_text = f"⚠  Rate limit / quota exceeded.\n   {detail.vt_enrichment_error or ''}"
    elif vt_status == "error":
        vt_text = f"✗  Lookup failed: {detail.vt_enrichment_error or 'unknown error'}"
    elif vt_hits:
        lines = []
        for u in vt_hits:
            lines.append(
                f"⚠  {u.url}\n"
                f"   Malicious: {u.vt_malicious}  |  Suspicious: {u.vt_suspicious}  |  Harmless: {u.vt_harmless}"
            )
        vt_text = "\n\n".join(lines)
    elif detail.urls and vt_status == "ok":
        vt_text = f"✓  All {len(detail.urls)} URL(s) checked — no malicious detections."
    elif not detail.urls:
        vt_text = "ℹ  No URLs found in this email."
    else:
        vt_text = "ℹ  No VirusTotal results available."

    page._lbl_vt.setText(vt_text)

    # AbuseIPDB
    abuse_status = detail.abuse_enrichment_status
    if abuse_status == "no_key":
        abuse_text = "⚠  No AbuseIPDB API key configured.\n   Go to Settings → API Keys to add one."
    elif abuse_status == "rate_limit":
        abuse_text = f"⚠  Rate limit / quota exceeded.\n   {detail.abuse_enrichment_error or ''}"
    elif abuse_status == "error":
        abuse_text = f"✗  Lookup failed: {detail.abuse_enrichment_error or 'unknown error'}"
    elif detail.abuse_result:
        ab = detail.abuse_result
        prefix = "⚠  High abuse score detected\n\n" if (ab.abuse_score or 0) >= 50 else "✓  Low abuse score\n\n"
        abuse_text = (
            f"{prefix}"
            f"IP:       {sender_ip}\n"
            f"Score:    {ab.abuse_score}% confidence of abuse\n"
            f"Reports:  {ab.total_reports}\n"
            f"Country:  {ab.country_code or '—'}\n"
            f"ISP:      {ab.isp or '—'}"
        )
    elif not sender_ip:
        abuse_text = "ℹ  No sender IP found in headers."
    else:
        abuse_text = f"✓  {sender_ip} — no abuse reports on record."

    page._lbl_abuse.setText(abuse_text)

    # Shodan
    shodan = detail.shodan_result
    shodan_status = detail.shodan_enrichment_status
    if shodan:
        lines = []
        if shodan.org:      lines.append(f"Org:        {shodan.org}")
        if shodan.asn:      lines.append(f"ASN:        {shodan.asn}")
        if shodan.country:  lines.append(f"Country:    {shodan.country}" + (f",  {shodan.city}" if shodan.city else ""))
        if shodan.ports:    lines.append(f"Open ports: {',  '.join(str(p) for p in shodan.ports)}")
        if shodan.tags:     lines.append(f"Tags:       {',  '.join(shodan.tags)}")
        if shodan.hostnames: lines.append(f"Hostnames:  {',  '.join(shodan.hostnames)}")
        if shodan.vulns:
            cves = ",  ".join(shodan.vulns[:8]) + ("  …" if len(shodan.vulns) > 8 else "")
            lines.append(f"⚠  CVEs ({len(shodan.vulns)}): {cves}")
        page._lbl_shodan.setText("\n".join(lines) if lines else f"✓  {shodan.ip} — no notable findings.")
    elif shodan_status == "no_key":
        page._lbl_shodan.setText(
            "⚠  No Shodan API key configured.\n"
            "   Add one in Settings (InternetDB free lookup also returned no data for this IP)."
        )
    elif shodan_status == "no_data":
        page._lbl_shodan.setText(f"✓  {sender_ip or 'Sender IP'} — not indexed by Shodan / InternetDB.")
    elif shodan_status in ("error", "rate_limit"):
        page._lbl_shodan.setText(f"✗  Lookup failed: {detail.shodan_enrichment_error or 'unknown error'}")
    else:
        page._lbl_shodan.setText("Shodan data not available for this analysis.")


# ── Body tab ──────────────────────────────────────────────────────────────────

def _populate_body(page, detail: EmailDetail) -> None:
    page._lbl_body.setText(detail.body_preview or "[No body content]")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
        elif item.layout():
            _clear_layout(item.layout())
