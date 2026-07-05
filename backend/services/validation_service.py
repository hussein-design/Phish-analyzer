"""Validates an uploaded file is actually a parseable .eml before it's
persisted or handed to eml_parser -- extension alone is never trusted.
"""

from __future__ import annotations

import email
from email import policy

from backend.core.exceptions import InvalidEmlError

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024   # 25 MB hard ceiling
_REQUIRED_ANY_HEADERS = ("from", "received", "subject", "date", "message-id")


def validate_eml_upload(filename: str, raw_bytes: bytes) -> None:
    # Check the original (pre-sanitisation) filename ends with .eml.
    # _sanitize_filename in analysis_service appends .eml to any filename that
    # lacks it, so by the time this function runs the name always ends in .eml —
    # but we want to reject files that were never .eml files to begin with.
    # The route handler passes the raw client-supplied filename here before
    # sanitisation happens, so this check is still meaningful.
    if not filename.lower().endswith(".eml"):
        raise InvalidEmlError(f"Only .eml files are accepted, got: {filename}")

    if not raw_bytes:
        raise InvalidEmlError("Uploaded file is empty")

    if len(raw_bytes) > _MAX_UPLOAD_BYTES:
        mb = len(raw_bytes) / (1024 * 1024)
        raise InvalidEmlError(
            f"File is too large ({mb:.1f} MB). Maximum allowed size is "
            f"{_MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    if not any(msg.get(h) for h in _REQUIRED_ANY_HEADERS):
        raise InvalidEmlError(
            "File does not look like a valid RFC822 email (no recognizable headers found)"
        )
