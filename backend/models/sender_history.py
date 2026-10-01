"""Sender history table for Phase 2 behavioral analysis.

Tracks every (recipient, sender) pair seen over time, enabling:
  - first_time_sender detection (message_count == 1 after the current email)
  - send_time_anomaly detection (send_hours stores a JSON list of UTC hours)

Per-recipient tracking is important: the same sender may be known to one
mailbox but a total stranger to another in a shared-deployment scenario.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SenderHistory(Base):
    __tablename__ = "sender_history"
    __table_args__ = (
        # Primary lookup: recipient + sender
        Index("ix_sender_history_recipient_sender", "recipient", "sender", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # The mailbox that received the email (normalized to lowercase).
    recipient: Mapped[str] = mapped_column(String(512), nullable=False)

    # The From address (normalized to lowercase bare address, no display name).
    sender: Mapped[str] = mapped_column(String(512), nullable=False)

    # Wall-clock timestamps of first and most recent observation.
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Running count of emails from this sender to this recipient.
    # Starts at 1 on insert; incremented on every subsequent observation.
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # JSON list of UTC hours (0-23) when this sender sent emails.
    # Used by send_time_anomaly to detect out-of-pattern send times.
    # Stored as a plain list — we never need range queries on individual hours.
    # Max stored: BEHAVIORAL_MAX_SEND_HOURS (default 200) — capped in service.
    send_hours: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=list)
