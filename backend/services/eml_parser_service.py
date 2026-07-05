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
    """Extract readable text from the email body.

    eml_parser returns body as a list of MIME part dicts.  We prefer
    text/plain (no stripping needed).  If only text/html is present we strip
    tags with BeautifulSoup.  Falls back to legacy dict-style keys for older
    eml_parser builds.
    """
    parts = normalize_body(body_raw)

    # Pass 1: prefer text/plain
    for part in parts:
        if not isinstance(part, dict):
            continue
        ct = (part.get("content_type") or part.get("mime_type") or "").lower()
        content = part.get("content")
        if not content:
            continue
        if isinstance(content, list):
            content = " ".join(str(c) for c in content)
        if "text/plain" in ct:
            return str(content)

    # Pass 2: fall back to text/html, strip tags
    for part in parts:
        if not isinstance(part, dict):
            continue
        ct = (part.get("content_type") or part.get("mime_type") or "").lower()
        content = part.get("content")
        if not content:
            continue
        if isinstance(content, list):
            content = " ".join(str(c) for c in content)
        if "text/html" in ct:
            soup = BeautifulSoup(content, "html.parser")
            return soup.get_text(separator=" ")

    # Pass 3: legacy dict-style body keys (older eml_parser builds)
    if isinstance(body_raw, dict):
        if body_raw.get("plain"):
            text = body_raw["plain"]
            if isinstance(text, list):
                text = " ".join(str(t) for t in text)
            return str(text)
        if body_raw.get("html"):
            html = body_raw["html"]
            if isinstance(html, list):
                html = " ".join(str(h) for h in html)
            soup = BeautifulSoup(html, "html.parser")
            return soup.get_text(separator=" ")

    return ""


def extract_urls_from_body(body_raw, body_text: str) -> list[str]:
    """Extract all URLs from the email body using two sources:

    1. eml_parser's pre-parsed ``uri`` list on each body part — catches URLs
       that the regex misses because they are split across folded lines or
       encoded inside HTML attributes.
    2. Regex over the plain-text representation as a safety net for any URL
       that eml_parser's own parser didn't recognise.

    Returns a deduplicated, sorted list.
    """
    seen: set[str] = set()
    urls: list[str] = []

    parts = normalize_body(body_raw)
    for part in parts:
        if not isinstance(part, dict):
            continue
        # eml_parser stores pre-extracted URLs in the 'uri' key as a list
        for uri in part.get("uri", []) or []:
            uri_str = str(uri).strip()
            if uri_str.startswith(("http://", "https://")) and uri_str not in seen:
                seen.add(uri_str)
                urls.append(uri_str)

    # Also run regex over the full body text for any URLs eml_parser missed
    for match in URL_REGEX.findall(body_text):
        if match not in seen:
            seen.add(match)
            urls.append(match)

    return sorted(urls)


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


def get_attachment_content_type(att: dict) -> str | None:
    """Extract content-type from an eml_parser attachment dict.

    eml_parser does NOT set a top-level ``content-type`` or ``content_type``
    key on attachment dicts — it stores MIME headers under
    ``att['content_header']['content-type']`` as a list.  This helper
    normalises that so the rest of the code gets a plain string or None.
    """
    # Try top-level keys first (future eml_parser versions / other parsers)
    ct = att.get("content-type") or att.get("content_type")
    if ct:
        return str(ct).split(";")[0].strip()

    # eml_parser actual location: content_header dict
    ch = att.get("content_header") or {}
    ct_list = ch.get("content-type") or ch.get("content_type")
    if isinstance(ct_list, list) and ct_list:
        # Value is like ["message/rfc822"] or ["application/pdf; name=foo.pdf"]
        return ct_list[0].split(";")[0].strip()
    if isinstance(ct_list, str):
        return ct_list.split(";")[0].strip()

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
    """Return the originating sender IP from the parsed eml_parser headers dict.

    eml_parser builds a structured ``received_ip`` list (all IPs seen across
    Received chains) and a ``received`` list of structured dicts, each with a
    ``from`` key that holds the IP(s) for that hop.  We prefer the last entry
    in ``received`` that carries a real IPv4 address in its ``from`` field,
    which corresponds to the first external hop that handed the message to the
    receiving infrastructure — i.e. the actual sender IP.

    Falls back to the last IPv4 in ``received_ip`` if the structured path
    yields nothing, and finally tries a regex over the raw ``received`` strings
    for maximum compatibility with unusual eml_parser builds.
    """
    # --- Strategy 1: structured received list from eml_parser ---
    received_list = headers.get("received")
    if isinstance(received_list, list):
        # Iterate from the last (outermost) hop backwards; take the first
        # entry whose "from" field contains a dotted-decimal IPv4.
        ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        for entry in reversed(received_list):
            if not isinstance(entry, dict):
                continue
            from_fields = entry.get("from", [])
            if isinstance(from_fields, str):
                from_fields = [from_fields]
            for field in from_fields:
                if ipv4_re.match(str(field).strip()):
                    return str(field).strip()

    # --- Strategy 2: received_ip list pre-built by eml_parser ---
    received_ips = headers.get("received_ip")
    if isinstance(received_ips, list):
        ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        for ip in reversed(received_ips):
            if ipv4_re.match(str(ip).strip()):
                return str(ip).strip()

    # --- Strategy 3: regex over raw Received strings (last resort) ---
    if isinstance(received_list, list):
        for entry in reversed(received_list):
            line = entry.get("src", "") if isinstance(entry, dict) else str(entry)
            match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if match:
                return match.group(0)

    return None


def _parse_auth_verdict(header_value: str) -> dict:
    """Extract SPF/DKIM/DMARC verdicts from a single Authentication-Results-style header value.

    Returns a dict with keys 'spf', 'dkim', 'dmarc', each either a verdict
    string ('pass', 'fail', 'softfail', 'neutral', 'none', 'permerror',
    'temperror') or None if the header doesn't mention that protocol.
    """
    verdicts: dict[str, str | None] = {"spf": None, "dkim": None, "dmarc": None}
    lower = header_value.lower()

    for proto in ("spf", "dkim", "dmarc"):
        # Match  proto=<result>  where result is a single token
        m = re.search(rf"\b{proto}=(pass|fail|softfail|neutral|none|permerror|temperror)\b", lower)
        if m:
            verdicts[proto] = m.group(1)

    return verdicts


def _arc_index(header_value: str) -> int:
    """Return the i= sequence number from an ARC-Authentication-Results value, or -1."""
    m = re.match(r"\s*i\s*=\s*(\d+)", header_value.strip())
    return int(m.group(1)) if m else -1


def extract_auth_from_raw(parsed: dict) -> tuple[dict, list[str]]:
    """Parse SPF/DKIM/DMARC from the email's authentication result headers.

    Priority / selection logic
    --------------------------
    1. ``Authentication-Results`` — written by the **final receiving MTA** that
       the target mailbox trusts.  When multiple instances are present (rare but
       possible after re-delivery) we collect all of them and merge: the first
       non-None verdict for each protocol wins.

    2. ``ARC-Authentication-Results`` — written by intermediate MTAs; each copy
       carries an ``i=N`` sequence number.  We select **only the entry with the
       highest i=** (the most recent arc hop) and use its verdicts as a
       second-priority source, filling in any protocol that step 1 left as None.

    3. ``Authentication-Results-Original`` — a preserved copy from before
       re-wrapping; used only to fill remaining unknowns.

    4. ``Received-SPF`` — plain-text SPF result, consulted last for SPF only.

    The returned ``result`` dict uses ``"unknown"`` for any protocol that could
    not be determined (no header, or header present but protocol not mentioned).
    """
    raw_email = parsed.get("_raw_email")
    result: dict[str, str] = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    sources: list[str] = []

    if not raw_email:
        return result, sources

    msg = email.message_from_bytes(raw_email)

    # ---------- 1. Authentication-Results (final MTA) ----------
    auth_results = msg.get_all("Authentication-Results") or []
    for v in auth_results:
        sources.append(f"Authentication-Results: {v}")
        verdicts = _parse_auth_verdict(v)
        for proto in ("spf", "dkim", "dmarc"):
            if result[proto] == "unknown" and verdicts[proto] is not None:
                result[proto] = verdicts[proto]

    # ---------- 2. ARC-Authentication-Results (highest i= only) ----------
    arc_values = msg.get_all("ARC-Authentication-Results") or []
    for v in arc_values:
        sources.append(f"ARC-Authentication-Results: {v}")

    if arc_values:
        # Pick the entry with the highest i= sequence number
        best_arc = max(arc_values, key=_arc_index)
        arc_verdicts = _parse_auth_verdict(best_arc)
        for proto in ("spf", "dkim", "dmarc"):
            if result[proto] == "unknown" and arc_verdicts[proto] is not None:
                result[proto] = arc_verdicts[proto]

    # ---------- 3. Authentication-Results-Original ----------
    orig_values = msg.get_all("Authentication-Results-Original") or []
    for v in orig_values:
        sources.append(f"Authentication-Results-Original: {v}")
        verdicts = _parse_auth_verdict(v)
        for proto in ("spf", "dkim", "dmarc"):
            if result[proto] == "unknown" and verdicts[proto] is not None:
                result[proto] = verdicts[proto]

    # ---------- 4. Received-SPF (SPF only, last resort) ----------
    spf_values = msg.get_all("Received-SPF") or []
    for v in spf_values:
        sources.append(f"Received-SPF: {v}")
        if result["spf"] == "unknown":
            lower = v.lower()
            # Received-SPF value starts with the verdict word
            m = re.match(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", lower)
            if m:
                result["spf"] = m.group(1)

    return result, sources


def get_message_id(parsed: dict, headers: dict) -> str | None:
    """Return the Message-ID header value.

    eml_parser stores the raw header dict under parsed['header']['header']
    (inner dict), with values as lists.  The outer parsed['header'] dict
    only has a small set of decoded keys (subject, from, to, date, received).
    We read the inner dict first, then fall back to Python's email.Message.
    """
    inner = headers.get("header", {}) or {}
    msg_id = inner.get("message-id")
    if isinstance(msg_id, list) and msg_id:
        return msg_id[0].strip()
    if isinstance(msg_id, str) and msg_id:
        return msg_id.strip()

    raw_email = parsed.get("_raw_email")
    if not raw_email:
        return None
    msg = email.message_from_bytes(raw_email)
    return msg.get("Message-ID")


def get_subject(parsed: dict, headers: dict) -> str | None:
    """Return the decoded Subject header value.

    eml_parser's outer header dict has a 'subject' key that is already
    decoded (handles RFC2047 encoded-words).  Use that first; fall back to
    the inner raw header dict (list value), then to Python's email.Message.
    """
    # Outer dict has 'subject' as a decoded string (preferred)
    subj = headers.get("subject")
    if subj and isinstance(subj, str):
        return subj.strip()

    # Inner dict stores raw list values
    inner = headers.get("header", {}) or {}
    subj_raw = inner.get("subject")
    if isinstance(subj_raw, list) and subj_raw:
        return subj_raw[0].strip()
    if isinstance(subj_raw, str) and subj_raw:
        return subj_raw.strip()

    raw_email = parsed.get("_raw_email")
    if not raw_email:
        return None
    msg = email.message_from_bytes(raw_email)
    return msg.get("Subject")


def _first_header_value(msg, inner: dict, name: str) -> str | None:
    """Return the first value of a header, checking Python's email.Message first,
    then the eml_parser inner header dict (which stores values as lists or strings).

    ``name`` should be in canonical capitalisation (e.g. 'Reply-To').
    """
    # Python email.Message (handles folded/encoded headers properly)
    val = msg.get(name) if msg is not None else None
    if val is not None:
        return val.strip()

    # eml_parser inner header dict uses lowercase keys; values may be lists
    key = name.lower()
    raw = inner.get(key)
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw[0].strip() if raw else None
    return str(raw).strip()


def analyze_headers(parsed: dict) -> dict:
    """From/Reply-To/Return-Path, sender IP, SPF/DKIM/DMARC, header issues."""
    headers = parsed.get("header", {}) or {}
    # eml_parser nests the full raw-header dict one level deeper
    inner_headers = headers.get("header", {}) or {}
    raw_email = parsed.get("_raw_email")
    msg = email.message_from_bytes(raw_email) if raw_email else None

    from_addr = _first_header_value(msg, inner_headers, "From")
    reply_to = _first_header_value(msg, inner_headers, "Reply-To")
    return_path = _first_header_value(msg, inner_headers, "Return-Path")

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
