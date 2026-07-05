"""Generates a professional DOCX analysis report on demand from a persisted
EmailAnalysis row.  The report is always built fresh from the DB so it
reflects any template changes without re-running the analysis.

Layout
------
  Cover / Summary
  1. Email Metadata
  2. Sender & Header Analysis
  3. Email Authentication (SPF / DKIM / DMARC)
  4. URL Indicators
  5. Attachment Indicators
  6. Threat Intelligence Enrichment
  7. Scoring & Verdict Reasoning
  8. Body Preview
  Appendix – Raw Authentication Headers
"""

from __future__ import annotations

import io
from datetime import timezone

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

from backend.models.analysis import EmailAnalysis

# ── Colour palette ────────────────────────────────────────────────────────────
_RED    = RGBColor(0xC0, 0x00, 0x00)   # phishing verdict / fail
_AMBER  = RGBColor(0xFF, 0x8C, 0x00)   # suspicious verdict / warn
_GREEN  = RGBColor(0x37, 0x86, 0x44)   # benign verdict / pass
_NAVY   = RGBColor(0x1F, 0x39, 0x64)   # section headings
_GREY   = RGBColor(0x59, 0x56, 0x59)   # secondary text / comments
_WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
_LTBLUE = RGBColor(0xD6, 0xE4, 0xF0)   # table header background

_VERDICT_COLOUR = {
    "phishing":  _RED,
    "suspicious": _AMBER,
    "benign":    _GREEN,
}

_VERDICT_LABEL = {
    "phishing":  "PHISHING  ⚠  High risk — treat with extreme caution",
    "suspicious": "SUSPICIOUS  ·  Needs manual review",
    "benign":    "LIKELY BENIGN  ·  No significant red flags detected",
    None:        "UNKNOWN  ·  Analysis incomplete",
}

_AUTH_COLOUR = {
    "pass":    _GREEN,
    "fail":    _RED,
    "softfail": _AMBER,
    "neutral": _GREY,
    "none":    _GREY,
    "unknown": _GREY,
}


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _set_cell_bg(cell, hex_colour: str) -> None:
    """Fill a table cell background with a hex colour string e.g. 'D6E4F0'."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_colour)
    tcPr.append(shd)


def _bold_run(para, text: str, colour: RGBColor | None = None) -> None:
    run = para.add_run(text)
    run.bold = True
    if colour:
        run.font.color.rgb = colour


def _coloured_run(para, text: str, colour: RGBColor) -> None:
    run = para.add_run(text)
    run.font.color.rgb = colour


def _comment_para(doc: Document, text: str) -> None:
    """Add a grey italicised explanatory comment paragraph."""
    p = doc.add_paragraph()
    run = p.add_run(f"ℹ  {text}")
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = _GREY


def _section_heading(doc: Document, title: str, level: int = 1) -> None:
    h = doc.add_heading(title, level=level)
    for run in h.runs:
        run.font.color.rgb = _NAVY


def _two_col_table(doc: Document, rows: list[tuple[str, str | None]],
                   comment_map: dict[str, str] | None = None) -> None:
    """Render a label/value table.  If a value is None or empty the cell shows
    'N/A' in grey and, if ``comment_map`` has a matching key, appends an
    explanatory comment row underneath.
    """
    tbl = doc.add_table(rows=0, cols=2)
    tbl.style = "Table Grid"
    tbl.autofit = True

    # Header row
    hdr = tbl.add_row()
    for i, txt in enumerate(("Field", "Value")):
        hdr.cells[i].text = txt
        hdr.cells[i].paragraphs[0].runs[0].bold = True
        hdr.cells[i].paragraphs[0].runs[0].font.color.rgb = _WHITE
        _set_cell_bg(hdr.cells[i], "1F3964")

    comment_map = comment_map or {}
    for label, value in rows:
        row = tbl.add_row()
        row.cells[0].text = label
        row.cells[0].paragraphs[0].runs[0].bold = True

        if value:
            row.cells[1].text = str(value)
        else:
            p = row.cells[1].paragraphs[0]
            run = p.add_run("N/A")
            run.font.color.rgb = _GREY
            run.italic = True

        # Explanatory comment as a sub-row when value is absent
        if not value and label in comment_map:
            cmt_row = tbl.add_row()
            _set_cell_bg(cmt_row.cells[0], "F2F2F2")
            _set_cell_bg(cmt_row.cells[1], "F2F2F2")
            cmt_row.cells[0].text = ""
            p = cmt_row.cells[1].paragraphs[0]
            run = p.add_run(f"ℹ  {comment_map[label]}")
            run.italic = True
            run.font.size = Pt(9)
            run.font.color.rgb = _GREY

    doc.add_paragraph()   # breathing room after table


def _auth_badge_para(doc: Document, label: str, verdict: str) -> None:
    """Render a single auth result as  LABEL: VERDICT  with colour coding."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.2)
    _bold_run(p, f"{label}: ")
    colour = _AUTH_COLOUR.get(verdict.lower(), _GREY)
    _coloured_run(p, verdict.upper(), colour)


# ── Public API ────────────────────────────────────────────────────────────────

def build_docx_report(analysis: EmailAnalysis) -> bytes:
    doc = Document()

    # ── Global font ───────────────────────────────────────────────────────────
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    # ── Cover / title block ───────────────────────────────────────────────────
    title = doc.add_heading("Phishing Email Analysis Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Verdict banner
    verdict_key = analysis.verdict  # "phishing" | "suspicious" | "benign" | None
    banner = doc.add_paragraph()
    banner.alignment = WD_ALIGN_PARAGRAPH.CENTER
    banner_run = banner.add_run(_VERDICT_LABEL.get(verdict_key, "UNKNOWN"))
    banner_run.bold = True
    banner_run.font.size = Pt(14)
    banner_run.font.color.rgb = _VERDICT_COLOUR.get(verdict_key, _GREY)

    # Score
    score_para = doc.add_paragraph()
    score_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _bold_run(score_para, "Suspicion score: ")
    score_para.add_run(
        str(analysis.score) if analysis.score is not None else "N/A"
    )

    doc.add_paragraph()  # spacer

    # ── Section 1 — Email Metadata ────────────────────────────────────────────
    _section_heading(doc, "1. Email Metadata")

    created = (
        analysis.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if analysis.created_at else None
    )
    _two_col_table(doc, [
        ("Filename",   analysis.filename),
        ("Subject",    analysis.subject),
        ("From",       analysis.from_addr),
        ("Message-ID", analysis.message_id),
        ("Analysed at", created),
    ], comment_map={
        "Subject":    "No Subject header was present in the email.",
        "Message-ID": "No Message-ID header was found. Legitimate bulk mail always carries one; "
                      "its absence can indicate a manually crafted or spoofed message.",
    })

    # ── Section 2 — Sender & Header Analysis ─────────────────────────────────
    _section_heading(doc, "2. Sender & Header Analysis")

    header_comments = {
        "Reply-To domain":
            "No Reply-To header present — replies go to the From address (normal for most "
            "legitimate email).",
        "Return-Path domain":
            "No Return-Path header present in the stored headers. This can happen with "
            "internal/relay emails or when the MTA strips it.",
        "Sender IP":
            "Could not extract a sender IP from the Received chain. This is common for "
            "emails that originated inside the same mail infrastructure (no external hop).",
    }

    header_rows = [
        ("From domain",       analysis.from_domain),
        ("Reply-To domain",   analysis.reply_domain),
        ("Return-Path domain", analysis.return_domain),
        ("Sender IP",         analysis.sender_ip),
    ]

    # Lookalike / punycode / suspicious TLD flags
    if analysis.is_lookalike_domain:
        header_rows.append(("⚠ Lookalike domain",
                            f"'{analysis.from_domain}' closely resembles "
                            f"'{analysis.lookalike_of}' — possible typosquat or combosquat"))
    if analysis.is_punycode_domain:
        header_rows.append(("⚠ Punycode / IDN domain",
                            f"'{analysis.from_domain}' uses xn-- encoding — "
                            "possible homograph spoof"))
    if analysis.is_suspicious_sender_tld:
        header_rows.append(("⚠ Suspicious sender TLD",
                            f"The TLD of '{analysis.from_domain}' is commonly abused in "
                            "phishing campaigns"))

    _two_col_table(doc, header_rows, comment_map=header_comments)

    # Header anomalies list
    if analysis.header_issues:
        doc.add_paragraph("Header anomalies detected:", style="List Bullet")
        for issue in analysis.header_issues:
            doc.add_paragraph(issue, style="List Bullet 2")
    else:
        _comment_para(doc,
            "No header anomalies detected. The From, Reply-To, and Return-Path domains are "
            "consistent with each other (or absent), and authentication results do not indicate "
            "a mismatch.")

    # ── Section 3 — Email Authentication ─────────────────────────────────────
    _section_heading(doc, "3. Email Authentication (SPF / DKIM / DMARC)")

    for proto, value in [("SPF", analysis.spf), ("DKIM", analysis.dkim),
                         ("DMARC", analysis.dmarc)]:
        _auth_badge_para(doc, proto, value or "unknown")

    # Explanatory comments for unknown results
    if analysis.spf == "unknown":
        _comment_para(doc,
            "SPF result is unknown. This means no Authentication-Results, Received-SPF, or "
            "ARC-Authentication-Results header was found in the email. This is normal for "
            "internal emails that never left the organisation's own mail servers.")
    if analysis.dkim == "unknown":
        _comment_para(doc,
            "DKIM result is unknown. Either no DKIM signature was present, or no "
            "Authentication-Results header reported on it. Internal and some older mail "
            "senders do not sign with DKIM.")
    if analysis.dmarc == "unknown":
        _comment_para(doc,
            "DMARC result is unknown. This is expected when the sending domain has no DMARC "
            "policy published, or when the email did not pass through a gateway that evaluates "
            "DMARC.")
    if analysis.dkim == "fail":
        _comment_para(doc,
            "DKIM FAIL typically means the email body or headers were modified in transit "
            "after the signature was applied (e.g. by a mailing list, disclaimer injector, or "
            "forwarder). It can also indicate the message was crafted to impersonate the "
            "signing domain.")
    if analysis.spf == "fail":
        _comment_para(doc,
            "SPF FAIL means the sending mail server is not listed as an authorised sender "
            "for the From domain. This is a strong phishing signal.")

    # ── Section 4 — URL Indicators ────────────────────────────────────────────
    _section_heading(doc, "4. URL Indicators")

    if analysis.urls:
        url_tbl = doc.add_table(rows=0, cols=4)
        url_tbl.style = "Table Grid"

        hdr_row = url_tbl.add_row()
        for i, txt in enumerate(("URL", "Flags", "VT Malicious", "VT Suspicious")):
            hdr_row.cells[i].text = txt
            hdr_row.cells[i].paragraphs[0].runs[0].bold = True
            hdr_row.cells[i].paragraphs[0].runs[0].font.color.rgb = _WHITE
            _set_cell_bg(hdr_row.cells[i], "1F3964")

        for u in analysis.urls:
            flags = []
            if u.is_suspicious_keyword: flags.append("suspicious keyword")
            if u.is_ip_host:            flags.append("raw IP host")
            if u.is_shortener:          flags.append("URL shortener")
            if u.is_suspicious_tld:     flags.append("suspicious TLD")
            if u.is_punycode:           flags.append("punycode")

            r = url_tbl.add_row()
            r.cells[0].text = u.url
            r.cells[1].text = ", ".join(flags) if flags else "—"
            r.cells[2].text = str(u.vt_malicious) if u.vt_malicious else "—"
            r.cells[3].text = str(u.vt_suspicious) if u.vt_suspicious else "—"

            # Highlight dangerous rows
            if u.vt_malicious and u.vt_malicious > 0:
                _set_cell_bg(r.cells[2], "FFD7D7")
            if flags:
                _set_cell_bg(r.cells[1], "FFF3CD")

        doc.add_paragraph()
        _comment_para(doc,
            "VT columns show '—' when no VirusTotal API key is configured or the URL "
            "returned zero detections. Configure your API key in Settings to enable "
            "live URL scanning.")
    else:
        doc.add_paragraph("No URLs were extracted from the email body.")
        _comment_para(doc,
            "URL extraction searches both the plain-text body and eml_parser's pre-parsed "
            "URI list. An empty result means the email contained no HTTP/HTTPS links, or "
            "the body could not be decoded (e.g. a non-text attachment with no readable part).")

    # ── Section 5 — Attachment Indicators ────────────────────────────────────
    _section_heading(doc, "5. Attachment Indicators")

    if analysis.attachments:
        att_tbl = doc.add_table(rows=0, cols=4)
        att_tbl.style = "Table Grid"

        hdr_row = att_tbl.add_row()
        for i, txt in enumerate(("Filename", "Content-Type", "SHA-256", "Flags")):
            hdr_row.cells[i].text = txt
            hdr_row.cells[i].paragraphs[0].runs[0].bold = True
            hdr_row.cells[i].paragraphs[0].runs[0].font.color.rgb = _WHITE
            _set_cell_bg(hdr_row.cells[i], "1F3964")

        for att in analysis.attachments:
            flags = []
            if att.is_executable_like:  flags.append("⚠ dangerous extension")
            if att.is_double_extension: flags.append("⚠ double extension")

            r = att_tbl.add_row()
            r.cells[0].text = att.filename or "unknown"
            r.cells[1].text = att.content_type or "unknown"
            r.cells[2].text = (att.sha256[:16] + "…") if att.sha256 else "N/A"
            r.cells[3].text = ", ".join(flags) if flags else "—"

            if flags:
                _set_cell_bg(r.cells[3], "FFD7D7")

        doc.add_paragraph()
        _comment_para(doc,
            "Content-Type shows 'unknown' when eml_parser could not determine the MIME type "
            "of the attachment (e.g. for inline message/rfc822 parts with no explicit "
            "Content-Type header). SHA-256 is truncated here; the full hash is in the "
            "Global Hashes section if present.")
    else:
        doc.add_paragraph("No attachments found in this email.")
        _comment_para(doc,
            "If you expected attachments, the email may use inline parts (Content-Disposition: "
            "inline) which are treated as body parts rather than attachments by eml_parser.")

    # ── Section 6 — Threat Intelligence Enrichment ────────────────────────────
    _section_heading(doc, "6. Threat Intelligence Enrichment")

    has_enrichment = False

    # VirusTotal
    vt_hits = [u for u in analysis.urls
               if (u.vt_malicious or 0) > 0 or (u.vt_suspicious or 0) > 0]
    if vt_hits:
        has_enrichment = True
        doc.add_paragraph("VirusTotal flagged URLs:", style="List Bullet")
        for u in vt_hits:
            doc.add_paragraph(
                f"{u.url}  →  malicious={u.vt_malicious}, "
                f"suspicious={u.vt_suspicious}, harmless={u.vt_harmless}",
                style="List Bullet 2",
            )
    elif analysis.urls:
        _comment_para(doc,
            "VirusTotal was queried for all extracted URLs but returned zero detections. "
            "This means all engines reported the URLs as harmless or unrated — OR no "
            "VirusTotal API key is configured (check Settings).")
    else:
        _comment_para(doc,
            "No URLs were found in this email so VirusTotal was not queried.")

    # AbuseIPDB
    if analysis.abuse_score is not None:
        has_enrichment = True
        p = doc.add_paragraph()
        _bold_run(p, "AbuseIPDB — Sender IP: ")
        p.add_run(f"{analysis.sender_ip or 'N/A'}  →  ")
        colour = _RED if (analysis.abuse_score or 0) >= 50 else (
                 _AMBER if (analysis.abuse_score or 0) >= 10 else _GREEN)
        _coloured_run(p, f"abuse score {analysis.abuse_score}", colour)
        p.add_run(
            f"  |  {analysis.abuse_total_reports or 0} reports  "
            f"|  {analysis.abuse_country or 'N/A'}  "
            f"|  ISP: {analysis.abuse_isp or 'N/A'}"
        )
    elif analysis.sender_ip:
        _comment_para(doc,
            f"AbuseIPDB was not queried for sender IP {analysis.sender_ip}. "
            "This means no AbuseIPDB API key is configured. Add one in Settings to enable "
            "sender IP reputation checks.")
    else:
        _comment_para(doc,
            "No sender IP could be extracted from the Received chain so AbuseIPDB was "
            "not queried. This is expected for internal emails with no external hop.")

    if not has_enrichment and not analysis.urls and analysis.abuse_score is None:
        doc.add_paragraph(
            "No external enrichment data is available for this email."
        )

    # ── Section 7 — Scoring & Verdict Reasoning ───────────────────────────────
    _section_heading(doc, "7. Scoring & Verdict Reasoning")

    score_tbl = doc.add_table(rows=0, cols=2)
    score_tbl.style = "Table Grid"
    hdr_row = score_tbl.add_row()
    for i, txt in enumerate(("Field", "Value")):
        hdr_row.cells[i].text = txt
        hdr_row.cells[i].paragraphs[0].runs[0].bold = True
        hdr_row.cells[i].paragraphs[0].runs[0].font.color.rgb = _WHITE
        _set_cell_bg(hdr_row.cells[i], "1F3964")

    score_row = score_tbl.add_row()
    score_row.cells[0].text = "Total suspicion score"
    score_row.cells[1].text = str(analysis.score if analysis.score is not None else "N/A")

    verdict_row = score_tbl.add_row()
    verdict_row.cells[0].text = "Verdict"
    vp = verdict_row.cells[1].paragraphs[0]
    vc = _VERDICT_COLOUR.get(analysis.verdict, _GREY)
    run = vp.add_run(analysis.verdict.upper() if analysis.verdict else "UNKNOWN")
    run.bold = True
    run.font.color.rgb = vc

    doc.add_paragraph()

    if analysis.reasons:
        reasons = [r.reason_text for r in analysis.reasons]
        doc.add_paragraph("The following signals contributed to this verdict:")
        for reason in reasons:
            doc.add_paragraph(reason, style="List Bullet")
    else:
        doc.add_paragraph(
            "No specific red flags were triggered by the current rule set."
        )
        _comment_para(doc,
            "A score of zero means the email did not match any of the configured detection "
            "rules: no brand impersonation, no auth failures, no suspicious URLs or "
            "attachments, and no urgency language. This does not guarantee the email is "
            "legitimate — novel phishing techniques may evade rule-based detection.")

    # Urgency language
    if analysis.urgency_keywords_found:
        doc.add_paragraph()
        p = doc.add_paragraph()
        _bold_run(p, "Urgency / pressure language detected: ")
        p.add_run(", ".join(analysis.urgency_keywords_found))
    else:
        _comment_para(doc,
            "No urgency or pressure phrases were detected in the body text. The absence "
            "of urgency language does not rule out phishing — sophisticated attackers "
            "often use neutral, professional language.")

    # ── Section 8 — Body Preview ──────────────────────────────────────────────
    _section_heading(doc, "8. Body Preview (first 800 characters)")

    body = analysis.body_text or ""
    if body:
        preview = body[:800].strip()
        if len(body) > 800:
            preview += "\n[… truncated …]"
        doc.add_paragraph(preview)
    else:
        doc.add_paragraph("[No readable body text was extracted from this email.]")
        _comment_para(doc,
            "Body extraction attempts text/plain first, then text/html (with tag stripping). "
            "An empty result usually means the email is a non-text format such as a "
            "meeting invite (text/calendar) or contains only an attached message with no "
            "outer body.")

    # ── Appendix — Raw Authentication Headers ─────────────────────────────────
    if analysis.auth_headers_raw:
        _section_heading(doc, "Appendix — Raw Authentication Headers", level=2)
        _comment_para(doc,
            "These are the exact header values used to determine SPF/DKIM/DMARC results. "
            "Authentication-Results is written by the final receiving mail server and is "
            "the most authoritative source. ARC-Authentication-Results entries are added "
            "by intermediate hops (highest i= is most recent).")
        for h in analysis.auth_headers_raw:
            p = doc.add_paragraph(style="List Bullet")
            run = p.add_run(h)
            run.font.size = Pt(8)
            run.font.name = "Courier New"
            run.font.color.rgb = _GREY

    # ── Footer note ───────────────────────────────────────────────────────────
    doc.add_paragraph()
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer_p.add_run(
        "Generated by Phish Analyzer Desktop  ·  Results are indicative only  ·  "
        "Always apply human judgement before acting on automated verdicts."
    )
    run.font.size = Pt(8)
    run.font.color.rgb = _GREY
    run.italic = True

    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()
