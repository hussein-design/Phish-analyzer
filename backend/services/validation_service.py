"""Validates an uploaded file is actually a parseable .eml before it's
persisted or handed to eml_parser -- extension alone is never trusted.
"""

from __future__ import annotations

import email
from email import policy

from backend.core.exceptions import InvalidEmlError

_REQUIRED_ANY_HEADERS = ("from", "received", "subject", "date", "message-id")


def validate_eml_upload(filename: str, raw_bytes: bytes) -> None:
    if not filename.lower().endswith(".eml"):
        raise InvalidEmlError(f"Only .eml files are accepted, got: {filename}")

    if not raw_bytes:
        raise InvalidEmlError("Uploaded file is empty")

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    if not any(msg.get(h) for h in _REQUIRED_ANY_HEADERS):
        raise InvalidEmlError(
            "File does not look like a valid RFC822 email (no recognizable headers found)"
        )
