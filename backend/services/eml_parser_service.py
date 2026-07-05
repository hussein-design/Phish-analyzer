"""Port of the .eml parsing/analysis logic from the original CLI (main.py),
unchanged in behavior. Kept sync -- callers run these via run_in_executor
since eml_parser/BeautifulSoup are sync libraries.
"""

from __future__ import annotations

import email
import hashlib
import re
from email.utils import parseaddr

import eml_parser
from bs4 import BeautifulSoup

URL_REGEX = re.compile(r"https?://[^\s\"'>]+")


def parse_eml_bytes(raw_email: bytes) -> dict:
    ep = eml_parser.EmlParser(
        include_raw_body=True,
        include_attachment_data=True,
        parse_attachments=True,
    )
    parsed = ep.decode_email_bytes(raw_email)
    parsed["_raw_email"] = raw_email
    return parsed


def normalize_body(body_raw) -> list:
    if isinstance(body_raw, list):
        return body_raw
    if isinstance(body_raw, dict):
        return [body_raw]
    return []


def extract_text_from_body(body_raw) -> str:
    """Prefer text/plain, then text/html, then older plain/html keys."""
    parts = normalize_body(body_raw)

    for part in parts:
        if not isinstance(part, dict):
            continue
        ct = (part.get("content_type") or part.get("mime_type") or "").lower()
        content = part.get("content")
        if not content:
            continue
        if isinstance(content, list):
            content = " ".join(content)
        if "text/plain" in ct:
            return content

    for part in parts:
        if not isinstance(part, dict):
            continue
        ct = (part.get("content_type") or part.get("mime_type") or "").lower()
        content = part.get("content")
        if not content:
            continue
        if isinstance(content, list):
            content = " ".join(content)
        if "text/html" in ct:
            soup = BeautifulSoup(content, "html.parser")
            return soup.get_text(separator=" ")

    if isinstance(body_raw, dict):
        if body_raw.get("plain"):
            text = body_raw["plain"]
            if isinstance(text, list):
                text = " ".join(text)
            return text
        if body_raw.get("html"):
            html = body_raw["html"]
            if isinstance(html, list):
                html = " ".join(html)
            soup = BeautifulSoup(html, "html.parser")
            return soup.get_text(separator=" ")

    return ""


def extract_urls_from_text(text: str) -> list[str]:
    return sorted(set(URL_REGEX.findall(text)))


def hash_attachment_content(att: dict) -> str | None:
    payload = att.get("payload")
    if isinstance(payload, (bytes, bytearray)):
        return hashlib.sha256(payload).hexdigest()

    hashes = att.get("hash") or att.get("hashes")
    if isinstance(hashes, dict):
        if "sha256" in hashes:
            return hashes["sha256"]
        for key in ("md5", "sha1"):
            if key in hashes:
                return hashes[key]
    return None


def extract_global_hashes(parsed: dict) -> dict:
    hashes = parsed.get("hashes", {}) or parsed.get("hash", {})
    return {
        "md5": hashes.get("md5", []),
        "sha1": hashes.get("sha1", []),
        "sha256": hashes.get("sha256", []),
    }


def extract_domain(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return None


def extract_sender_ip(headers: dict) -> str | None:
    received = headers.get("received")
    entries: list = []
    if isinstance(received, list):
        entries = received
    elif isinstance(received, (str, dict)):
        entries = [received]

    for entry in reversed(entries):
        line = str(entry)
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        if match:
            return match.group(0)
    return None


def extract_auth_from_raw(parsed: dict) -> tuple[dict, list[str]]:
    """Parse SPF/DKIM/DMARC from raw headers using Python's email library."""
    raw_email = parsed.get("_raw_email")
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    sources: list[str] = []

    if not raw_email:
        return result, sources

    msg = email.message_from_bytes(raw_email)

    header_names = [
        "Authentication-Results",
        "ARC-Authentication-Results",
        "Authentication-Results-Original",
        "Received-SPF",
    ]

    for name in header_names:
        values = msg.get_all(name) or []
        for v in values:
            sources.append(f"{name}: {v}")
            lower = v.lower()

            if "spf=pass" in lower and result["spf"] == "unknown":
                result["spf"] = "pass"
            elif any(x in lower for x in ["spf=fail", "spf=softfail"]) and result["spf"] == "unknown":
                result["spf"] = "fail"

            if name.lower() == "received-spf":
                if "pass" in lower and result["spf"] == "unknown":
                    result["spf"] = "pass"
                elif any(x in lower for x in ["fail", "softfail"]) and result["spf"] == "unknown":
                    result["spf"] = "fail"

            if "dkim=pass" in lower and result["dkim"] == "unknown":
                result["dkim"] = "pass"
            elif "dkim=fail" in lower and result["dkim"] == "unknown":
                result["dkim"] = "fail"

            if "dmarc=pass" in lower and result["dmarc"] == "unknown":
                result["dmarc"] = "pass"
            elif "dmarc=fail" in lower and result["dmarc"] == "unknown":
                result["dmarc"] = "fail"

    return result, sources


def get_message_id(parsed: dict, headers: dict) -> str | None:
    msg_id = headers.get("message-id")
    if msg_id:
        return msg_id

    raw_email = parsed.get("_raw_email")
    if not raw_email:
        return None

    msg = email.message_from_bytes(raw_email)
    return msg.get("Message-ID")


def analyze_headers(parsed: dict) -> dict:
    """From/Reply-To/Return-Path, sender IP, SPF/DKIM/DMARC, header issues."""
    headers = parsed.get("header", {}) or {}
    raw_email = parsed.get("_raw_email")
    msg = email.message_from_bytes(raw_email) if raw_email else None

    from_addr = msg.get("From") if msg else headers.get("from")
    reply_to = msg.get("Reply-To") if msg else headers.get("reply-to")
    return_path = msg.get("Return-Path") if msg else headers.get("return-path")

    from_domain = extract_domain(from_addr)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    sender_ip = extract_sender_ip(headers)
    auth, auth_sources = extract_auth_from_raw(parsed)

    issues = []

    if from_domain and reply_domain and from_domain != reply_domain:
        issues.append(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
        )
    if from_domain and return_domain and from_domain != return_domain:
        issues.append(
            f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})"
        )
    if auth["spf"] == "fail":
        issues.append("SPF failed in Authentication-Results / Received-SPF")
    if auth["dkim"] == "fail":
        issues.append("DKIM failed in Authentication-Results")
    if auth["dmarc"] == "fail":
        issues.append("DMARC failed in Authentication-Results")

    return {
        "from_addr": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "sender_ip": sender_ip,
        "auth": auth,
        "auth_headers": auth_sources,
        "issues": issues,
    }
