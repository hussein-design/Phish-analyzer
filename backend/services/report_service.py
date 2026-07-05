"""Port of export_docx_report() from the CLI. Generates the DOCX on demand
from the persisted analysis row rather than storing a blob, so the report
always reflects the current template and the DB stays lean.
"""

from __future__ import annotations

import io

from docx import Document
from docx.shared import Pt

from backend.models.analysis import EmailAnalysis

VERDICT_DISPLAY = {
    "phishing": "phishing (high suspicion)",
    "suspicious": "suspicious (needs manual review)",
    "benign": "likely benign (based on current checks)",
}


def verdict_display(verdict: str | None) -> str:
    if verdict is None:
        return "unknown"
    return VERDICT_DISPLAY.get(verdict, verdict)


def _add_kv_row(table, label: str, value) -> None:
    row = table.add_row().cells
    row[0].text = label
    row[1].text = "" if value is None else str(value)


def build_docx_report(analysis: EmailAnalysis) -> bytes:
    doc = Document()

    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    doc.add_heading("Phishing Email Analysis Report", level=0)

    doc.add_heading("Summary", level=1)
    p = doc.add_paragraph()
    p.add_run("Verdict: ").bold = True
    p.add_run(verdict_display(analysis.verdict))
    p = doc.add_paragraph()
    p.add_run("Suspicion score: ").bold = True
    p.add_run(str(analysis.score if analysis.score is not None else "N/A"))

    doc.add_heading("Email Details", level=1)
    table = doc.add_table(rows=0, cols=2)
    table.style = "Light List"
    _add_kv_row(table, "From", analysis.from_addr)
    _add_kv_row(table, "Subject", analysis.subject)
    _add_kv_row(table, "Message-ID", analysis.message_id)
    _add_kv_row(table, "Uploaded", analysis.created_at)

    doc.add_heading("Header & Sender Analysis", level=1)
    table_h = doc.add_table(rows=0, cols=2)
    table_h.style = "Light List"
    _add_kv_row(table_h, "From domain", analysis.from_domain)
    _add_kv_row(table_h, "Reply-To domain", analysis.reply_domain)
    _add_kv_row(table_h, "Return-Path domain", analysis.return_domain)
    _add_kv_row(table_h, "Sender IP (Received chain)", analysis.sender_ip)
    _add_kv_row(table_h, "SPF", analysis.spf)
    _add_kv_row(table_h, "DKIM", analysis.dkim)
    _add_kv_row(table_h, "DMARC", analysis.dmarc)
    if analysis.is_lookalike_domain:
        _add_kv_row(table_h, "Lookalike domain", f"Resembles {analysis.lookalike_of}")
    if analysis.is_punycode_domain:
        _add_kv_row(table_h, "Punycode domain", "Yes (possible IDN homograph)")
    if analysis.is_suspicious_sender_tld:
        _add_kv_row(table_h, "Suspicious sender TLD", "Yes")

    if analysis.auth_headers_raw:
        doc.add_paragraph("Authentication headers:", style="List Bullet")
        for h in analysis.auth_headers_raw:
            doc.add_paragraph(h, style="List Bullet 2")

    if analysis.header_issues:
        doc.add_paragraph("Header issues:", style="List Bullet")
        for issue in analysis.header_issues:
            doc.add_paragraph(issue, style="List Bullet 2")

    doc.add_heading("Indicators", level=1)
    if analysis.urls:
        doc.add_paragraph("URLs:", style="List Bullet")
        for u in analysis.urls:
            doc.add_paragraph(u.url, style="List Bullet 2")
    else:
        doc.add_paragraph("URLs: None found")

    if analysis.attachments:
        doc.add_paragraph("Attachments:", style="List Bullet")
        for att in analysis.attachments:
            flags = []
            if att.is_executable_like:
                flags.append("dangerous extension")
            if att.is_double_extension:
                flags.append("double extension")
            flag_suffix = f" [{', '.join(flags)}]" if flags else ""
            doc.add_paragraph(
                f"{att.filename} ({att.content_type}), sha256={att.sha256 or 'N/A'}{flag_suffix}",
                style="List Bullet 2",
            )
    else:
        doc.add_paragraph("Attachments: None")

    hashes = analysis.global_hashes or {}
    if any(hashes.get(k) for k in ("md5", "sha1", "sha256")):
        doc.add_paragraph("Global email hashes:", style="List Bullet")
        for kind in ("md5", "sha1", "sha256"):
            for h in hashes.get(kind, []):
                doc.add_paragraph(f"{kind.upper()}: {h}", style="List Bullet 2")

    doc.add_heading("Threat Intel Enrichment", level=1)
    if analysis.urls:
        doc.add_paragraph("VirusTotal URL results:", style="List Bullet")
        for u in analysis.urls:
            doc.add_paragraph(
                f"{u.url} -> malicious={u.vt_malicious}, harmless={u.vt_harmless}, "
                f"suspicious={u.vt_suspicious}",
                style="List Bullet 2",
            )
    else:
        doc.add_paragraph("VirusTotal URL results: none (no URLs or VT key missing)")

    if analysis.abuse_score is not None:
        doc.add_paragraph("AbuseIPDB sender IP:", style="List Bullet")
        doc.add_paragraph(
            f"{analysis.sender_ip} -> score={analysis.abuse_score}, "
            f"reports={analysis.abuse_total_reports}, country={analysis.abuse_country}, "
            f"ISP={analysis.abuse_isp}",
            style="List Bullet 2",
        )
    else:
        doc.add_paragraph("AbuseIPDB sender IP: not enriched (no IP or key missing)")

    if analysis.urgency_keywords_found:
        doc.add_heading("Urgency / Pressure Language", level=1)
        doc.add_paragraph(", ".join(analysis.urgency_keywords_found))

    doc.add_heading("Reasons for Verdict", level=1)
    if analysis.reasons:
        for r in analysis.reasons:
            doc.add_paragraph(r.reason_text, style="List Bullet")
    else:
        doc.add_paragraph("No specific red flags triggered by current rules.")

    doc.add_heading("Body Preview", level=1)
    body = analysis.body_text or ""
    preview = body[:500] + ("..." if len(body) > 500 else "")
    doc.add_paragraph(preview)

    buffer = io.BytesIO()
    doc.save(buffer)
    return buffer.getvalue()
