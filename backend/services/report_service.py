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
_RED    = RGBColor(0xC0, 0x00, 0x00)
_AMBER  = RGBColor(0xFF, 0x8C, 0x00)
_GREEN  = RGBColor(0x37, 0x86, 0x44)
_NAVY   = RGBColor(0x1F, 0x39, 0x64)
_GREY   = RGBColor(0x59, 0x56, 0x59)
_WHITE  = RGBColor(0xFF, 0xFF, 0xFF)

_VERDICT_COLOUR = {
    "phishing":   _RED,
    "suspicious": _AMBER,
    "benign":     _GREEN,
}

_VERDICT_LABEL = {
    "phishing":   "PHISHING  ⚠  High risk — treat with extreme caution",
    "suspicious": "SUSPICIOUS  ·  Requires manual review",
    "benign":     "LIKELY BENIGN  ·  No significant indicators detected",
    None:         "UNKNOWN  ·  Analysis incomplete",
}

# All known SPF/DKIM/DMARC result values with appropriate colours.
# "permerror" = permanent error in policy (misconfiguration) → amber
# "temperror" = transient DNS error during check → amber
# "none"      = no record published                          → grey
# "neutral"   = policy explicitly neither pass nor fail      → grey
# "policy"    = DMARC disposition applied                    → amber
_AUTH_COLOUR = {
    "pass":      _GREEN,
    "fail":      _RED,
    "softfail":  _AMBER,
    "permerror": _AMBER,
    "temperror": _AMBER,
    "policy":    _AMBER,
    "neutral":   _GREY,
    "none":      _GREY,
    "unknown":   _GREY,
}

# Human-readable explanation for each auth result shown in the report.
_AUTH_EXPLANATION = {
    "pass":      "{proto} passed — the sending server is authorised and the message is authentic.",
    "fail":      "{proto} failed — the message does not originate from an authorised source. This is a strong phishing indicator.",
    "softfail":  "{proto} soft-fail — the sending server is not listed as authorised, but the domain owner has not requested rejection. Treat with caution.",
    "permerror": "{proto} permanent error — there is a misconfiguration in the domain's {proto} policy record that prevented evaluation.",
    "temperror": "{proto} temporary error — a transient DNS lookup failure prevented evaluation. This may resolve on retry.",
    "policy":    "{proto} policy — the message was handled according to the domain's published policy.",
    "neutral":   "{proto} neutral — the domain's policy makes no assertion about this result.",
    "none":      "{proto} none — no {proto} record is published for this domain.",
    "unknown":   "{proto} result could not be determined from the available headers.",
}


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _set_cell_bg(cell, hex_colour: str) -> None:
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


def _note_para(doc: Document, text: str) -> None:
    """Add a small grey italicised note — used only when genuinely informative."""
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = _GREY


def _section_heading(doc: Document, title: str, level: int = 1) -> None:
    h = doc.add_heading(title, level=level)
    for run in h.runs:
        run.font.color.rgb = _NAVY


def _two_col_table(doc: Document, rows: list[tuple[str, str | None]]) -> None:
    """Render a label/value table. Missing values show as 'N/A'."""
    tbl = doc.add_table(rows=0, cols=2)
    tbl.style = "Table Grid"
    tbl.autofit = True

    hdr = tbl.add_row()
    for i, txt in enumerate(("Field", "Value")):
        hdr.cells[i].text = txt
        hdr.cells[i].paragraphs[0].runs[0].bold = True
        hdr.cells[i].paragraphs[0].runs[0].font.color.rgb = _WHITE
        _set_cell_bg(hdr.cells[i], "1F3964")

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

    doc.add_paragraph()


def _auth_badge_para(doc: Document, label: str, verdict: str) -> None:
    """Render  LABEL: VERDICT  with colour, then a plain-English explanation."""
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.2)
    _bold_run(p, f"{label}: ")
    colour = _AUTH_COLOUR.get(verdict.lower(), _GREY)
    _coloured_run(p, verdict.upper(), colour)

    # Add explanation on the same paragraph after the verdict badge.
    explanation_template = _AUTH_EXPLANATION.get(verdict.lower(), "")
    if explanation_template:
        explanation = explanation_template.replace("{proto}", label)
        run = p.add_run(f"  —  {explanation}")
        run.font.size = Pt(9.5)
        run.font.color.rgb = _GREY


# ── Public API ────────────────────────────────────────────────────────────────

def build_docx_report(analysis: EmailAnalysis) -> bytes:
    doc = Document()

    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    # ── Cover / title block ───────────────────────────────────────────────────
    title = doc.add_heading("Phishing Email Analysis Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    verdict_key = analysis.verdict
    banner = doc.add_paragraph()
    banner.alignment = WD_ALIGN_PARAGRAPH.CENTER
    banner_run = banner.add_run(_VERDICT_LABEL.get(verdict_key, "UNKNOWN"))
    banner_run.bold = True
    banner_run.font.size = Pt(14)
    banner_run.font.color.rgb = _VERDICT_COLOUR.get(verdict_key, _GREY)

    score_para = doc.add_paragraph()
    score_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _bold_run(score_para, "Suspicion score: ")
    score_para.add_run(str(analysis.score) if analysis.score is not None else "N/A")

    doc.add_paragraph()

    # ── Section 1 — Email Metadata ────────────────────────────────────────────
    _section_heading(doc, "1. Email Metadata")

    created = (
        analysis.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if analysis.created_at else None
    )
    _two_col_table(doc, [
        ("Filename",    analysis.filename),
        ("Subject",     analysis.subject or "— (no subject)"),
        ("From",        analysis.from_addr),
        ("Message-ID",  analysis.message_id),
        ("Analysed at", created),
    ])

    # ── Section 2 — Sender & Header Analysis ─────────────────────────────────
    _section_heading(doc, "2. Sender & Header Analysis")

    header_rows = [
        ("From domain",        analysis.from_domain),
        ("Reply-To domain",    analysis.reply_domain),
        ("Return-Path domain", analysis.return_domain),
        ("Sender IP",          analysis.sender_ip),
    ]

    if analysis.is_lookalike_domain:
        header_rows.append((
            "⚠ Lookalike domain",
            f"'{analysis.from_domain}' closely resembles '{analysis.lookalike_of}'"
            " — possible typosquat or combosquat attack",
        ))
    if analysis.is_punycode_domain:
        header_rows.append((
            "⚠ Punycode / IDN domain",
            f"'{analysis.from_domain}' uses international encoding — possible homograph spoof",
        ))
    if analysis.is_suspicious_sender_tld:
        header_rows.append((
            "⚠ Suspicious sender TLD",
            f"The TLD of '{analysis.from_domain}' is commonly associated with phishing campaigns",
        ))

    _two_col_table(doc, header_rows)

    if analysis.header_issues:
        doc.add_paragraph("Header anomalies detected:")
        for issue in analysis.header_issues:
            doc.add_paragraph(issue, style="List Bullet")
        doc.add_paragraph()
    else:
        doc.add_paragraph("No header anomalies detected.")
        doc.add_paragraph()

    # ── Section 3 — Email Authentication ─────────────────────────────────────
    _section_heading(doc, "3. Email Authentication (SPF / DKIM / DMARC)")

    for proto, value in [("SPF", analysis.spf), ("DKIM", analysis.dkim), ("DMARC", analysis.dmarc)]:
        _auth_badge_para(doc, proto, value or "unknown")

    doc.add_paragraph()

    # ── Section 4 — URL Indicators ────────────────────────────────────────────
    _section_heading(doc, "4. URL Indicators")

    if analysis.urls:
        # Determine if VT data is present in any URL row.
        vt_ran = analysis.vt_enrichment_status in ("ok", "no_data")

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
            if u.is_punycode:           flags.append("punycode domain")

            r = url_tbl.add_row()
            r.cells[0].text = u.url
            r.cells[1].text = ", ".join(flags) if flags else "—"
            r.cells[2].text = str(u.vt_malicious) if (u.vt_malicious or 0) > 0 else "—"
            r.cells[3].text = str(u.vt_suspicious) if (u.vt_suspicious or 0) > 0 else "—"

            if (u.vt_malicious or 0) > 0:
                _set_cell_bg(r.cells[2], "FFD7D7")
            if (u.vt_suspicious or 0) > 0:
                _set_cell_bg(r.cells[3], "FFF3CD")
            if flags:
                _set_cell_bg(r.cells[1], "FFF3CD")

        doc.add_paragraph()

        # Only add a note if VT didn't run — never add a note when results are present.
        if not vt_ran:
            vt_status = analysis.vt_enrichment_status
            if vt_status == "no_key":
                _note_para(doc, "VirusTotal columns show '—' — no API key is configured.")
            elif vt_status == "rate_limit":
                _note_para(doc, "VirusTotal columns show '—' — daily quota was reached during this analysis.")
            elif vt_status == "error":
                _note_para(doc, f"VirusTotal columns show '—' — enrichment error: {analysis.vt_enrichment_error or 'unknown'}.")
    else:
        doc.add_paragraph("No URLs were extracted from this email.")

    # ── Section 5 — Attachment Indicators ────────────────────────────────────
    _section_heading(doc, "5. Attachment Indicators")

    if analysis.attachments:
        att_tbl = doc.add_table(rows=0, cols=4)
        att_tbl.style = "Table Grid"

        hdr_row = att_tbl.add_row()
        for i, txt in enumerate(("Filename", "Content-Type", "SHA-256 (partial)", "Flags")):
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
    else:
        doc.add_paragraph("No attachments found in this email.")
        doc.add_paragraph()

    # ── Section 6 — Threat Intelligence Enrichment ───────────────────────────
    _section_heading(doc, "6. Threat Intelligence Enrichment")

    has_enrichment = False

    # ── VirusTotal ────────────────────────────────────────────────────────
    vt_status = analysis.vt_enrichment_status
    vt_error  = analysis.vt_enrichment_error
    vt_hits   = [u for u in analysis.urls
                 if (u.vt_malicious or 0) > 0 or (u.vt_suspicious or 0) > 0]

    if vt_status == "no_key":
        _note_para(doc, "VirusTotal: not queried — no API key configured.")
    elif vt_status == "rate_limit":
        _note_para(doc, "VirusTotal: daily quota reached — results unavailable for this analysis.")
    elif vt_status == "error":
        _note_para(doc, f"VirusTotal: enrichment failed — {vt_error or 'unknown error'}.")
    elif vt_hits:
        has_enrichment = True
        p = doc.add_paragraph()
        _bold_run(p, "VirusTotal — Malicious URLs detected:")
        for u in vt_hits:
            doc.add_paragraph(
                f"{u.url}  →  malicious={u.vt_malicious}, "
                f"suspicious={u.vt_suspicious}, harmless={u.vt_harmless}",
                style="List Bullet",
            )
    elif analysis.urls and vt_status == "ok":
        has_enrichment = True
        doc.add_paragraph(
            "VirusTotal: all extracted URLs were checked — no malicious detections found."
        )
    elif analysis.urls and vt_status == "no_data":
        doc.add_paragraph(
            "VirusTotal: URLs submitted for analysis — no results returned "
            "(URLs may be unrated or too new to have detections)."
        )
    elif not analysis.urls:
        doc.add_paragraph("VirusTotal: no URLs found in this email — scan not performed.")
    # If vt_status is None (old analysis), say nothing — no misleading text.

    # ── AbuseIPDB ─────────────────────────────────────────────────────────
    abuse_status = analysis.abuse_enrichment_status
    abuse_error  = analysis.abuse_enrichment_error

    if analysis.abuse_score is not None:
        has_enrichment = True
        p = doc.add_paragraph()
        _bold_run(p, "AbuseIPDB — Sender IP reputation: ")
        p.add_run(f"{analysis.sender_ip or 'N/A'}  →  ")
        colour = (
            _RED   if (analysis.abuse_score or 0) >= 50 else
            _AMBER if (analysis.abuse_score or 0) >= 10 else
            _GREEN
        )
        _coloured_run(p, f"abuse confidence score: {analysis.abuse_score}%", colour)
        p.add_run(
            f"  |  total reports: {analysis.abuse_total_reports or 0}"
            f"  |  country: {analysis.abuse_country or 'N/A'}"
            f"  |  ISP: {analysis.abuse_isp or 'N/A'}"
        )
    elif abuse_status == "no_key":
        _note_para(doc, "AbuseIPDB: not queried — no API key configured.")
    elif abuse_status == "rate_limit":
        _note_para(doc, "AbuseIPDB: daily quota reached — results unavailable for this analysis.")
    elif abuse_status == "error":
        _note_para(doc, f"AbuseIPDB: enrichment failed — {abuse_error or 'unknown error'}.")
    elif not analysis.sender_ip or abuse_status == "no_data":
        doc.add_paragraph(
            "AbuseIPDB: no sender IP found in email headers — reputation check not performed."
        )
    elif abuse_status in ("ok", None) and analysis.sender_ip:
        has_enrichment = True
        doc.add_paragraph(
            f"AbuseIPDB: {analysis.sender_ip} — no abuse reports on record."
        )

    doc.add_paragraph()

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
    run = vp.add_run(analysis.verdict.upper() if analysis.verdict else "UNKNOWN")
    run.bold = True
    run.font.color.rgb = _VERDICT_COLOUR.get(analysis.verdict, _GREY)

    doc.add_paragraph()

    if analysis.reasons:
        doc.add_paragraph("Indicators that contributed to this verdict:")
        for reason in [r.reason_text for r in analysis.reasons]:
            doc.add_paragraph(reason, style="List Bullet")
    else:
        doc.add_paragraph("No specific indicators were triggered by the current detection rules.")

    if analysis.urgency_keywords_found:
        doc.add_paragraph()
        p = doc.add_paragraph()
        _bold_run(p, "Urgency / pressure language detected: ")
        p.add_run(", ".join(analysis.urgency_keywords_found))

    doc.add_paragraph()

    # ── Section 8 — Body Preview ──────────────────────────────────────────────
    _section_heading(doc, "8. Body Preview")

    body = analysis.body_text or ""
    if body:
        preview = body[:800].strip()
        if len(body) > 800:
            preview += "\n[… content continues …]"
        doc.add_paragraph(preview)
    else:
        doc.add_paragraph("No readable body text was extracted from this email.")

    # ── Appendix — Raw Authentication Headers ─────────────────────────────────
    if analysis.auth_headers_raw:
        _section_heading(doc, "Appendix — Raw Authentication Headers", level=2)
        for h in analysis.auth_headers_raw:
            p = doc.add_paragraph(style="List Bullet")
            run = p.add_run(h)
            run.font.size = Pt(8)
            run.font.name = "Courier New"
            run.font.color.rgb = _GREY

    # ── Footer ────────────────────────────────────────────────────────────────
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
