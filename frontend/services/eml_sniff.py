"""Cheap client-side pre-validation so an obviously-bad file fails fast with
a toast instead of round-tripping to the backend. Reads only the first ~8KB
-- bounded, so this stays non-blocking even for a huge attachment-laden
.eml -- and is intentionally run synchronously on the UI thread.
"""

from __future__ import annotations

import re
from pathlib import Path

_SNIFF_BYTES = 8192
_HEADER_LINE_RE = re.compile(rb"^[!-9;-~]+:\s?")
_KNOWN_HEADERS = (b"from:", b"received:", b"subject:", b"date:", b"message-id:")


def looks_like_eml(path: str) -> tuple[bool, str | None]:
    """Returns (ok, reason_if_not_ok)."""
    p = Path(path)

    if p.suffix.lower() != ".eml":
        return False, f"Only .eml files are supported (got {p.suffix or 'no extension'})"

    try:
        with p.open("rb") as f:
            chunk = f.read(_SNIFF_BYTES)
    except OSError as exc:
        return False, f"Could not read file: {exc}"

    if not chunk:
        return False, "File is empty"

    lower = chunk.lower()
    if not any(h in lower for h in _KNOWN_HEADERS):
        return False, "File does not look like a valid email (no recognizable headers found)"

    first_line = chunk.split(b"\n", 1)[0].strip(b"\r")
    if not (_HEADER_LINE_RE.match(first_line) or first_line.startswith(b"From ")):
        return False, "File does not start with a valid email header"

    return True, None
