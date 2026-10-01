"""Thread history table for Phase 2 behavioral analysis.

Tracks every message seen in each thread (by recipient × normalized subject
key), enabling reply_chain_break detection: an email with a Re:/Fwd: prefix
is suspicious when neither the sender nor any message-ID match the prior
history for that thread.

Thread key: the subject with Re:/Fwd: prefixes stripped and whitespace
normalized, lowercased.  This is cheap to compute and collision-resistant
enough for BEC detection purposes — two genuinely unrelated subjects that
hash to the same key are far less likely than the false-positive cost of
stricter keying.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ThreadHistory(Base):
    __tablename__ = "thread_history"
    __table_args__ = (
        # Fast lookup for all messages in a thread seen by a recipient.
        Index("ix_thread_history_recipient_key", "recipient", "thread_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # The mailbox that received the email (normalized lowercase).
    recipient: Mapped[str] = mapped_column(String(512), nullable=False)

    # Normalized subject used as the thread key (Re:/Fwd: stripped, lowercased).
    thread_key: Mapped[str] = mapped_column(String(512), nullable=False)

    # The From address of this message (normalized lowercase bare address).
    sender: Mapped[str] = mapped_column(String(512), nullable=False)

    # The Message-ID header value, stored to correlate In-Reply-To chains later.
    # Nullable because some emails legitimately lack a Message-ID.
    message_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The In-Reply-To header value of this message — the Message-ID it is
    # replying to.  Used by _check_reply_chain_break as a tiebreaker:
    # if a subject collides but In-Reply-To matches a known message_id in
    # this thread, the email is a legitimate continuation (not injection).
    in_reply_to: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
