from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    __table_args__ = (
        Index("ix_email_analyses_created_at", "created_at"),
        Index("ix_email_analyses_status", "status"),
        Index("ix_email_analyses_verdict", "verdict"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))

    status: Mapped[str] = mapped_column(String(16), default="PENDING")
    error_message: Mapped[str | None] = mapped_column(Text, default=None)

    message_id: Mapped[str | None] = mapped_column(String(512), default=None)
    subject: Mapped[str | None] = mapped_column(Text, default=None)

    from_addr: Mapped[str | None] = mapped_column(Text, default=None)
    from_domain: Mapped[str | None] = mapped_column(String(255), default=None)
    reply_to: Mapped[str | None] = mapped_column(Text, default=None)
    reply_domain: Mapped[str | None] = mapped_column(String(255), default=None)
    return_path: Mapped[str | None] = mapped_column(Text, default=None)
    return_domain: Mapped[str | None] = mapped_column(String(255), default=None)
    sender_ip: Mapped[str | None] = mapped_column(String(64), default=None)

    spf: Mapped[str] = mapped_column(String(16), default="unknown")
    dkim: Mapped[str] = mapped_column(String(16), default="unknown")
    dmarc: Mapped[str] = mapped_column(String(16), default="unknown")
    auth_headers_raw: Mapped[list[str]] = mapped_column(JSON, default=list)
    header_issues: Mapped[list[str]] = mapped_column(JSON, default=list)

    is_lookalike_domain: Mapped[bool] = mapped_column(Boolean, default=False)
    lookalike_of: Mapped[str | None] = mapped_column(String(255), default=None)
    is_punycode_domain: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspicious_sender_tld: Mapped[bool] = mapped_column(Boolean, default=False)
    urgency_keywords_found: Mapped[list[str]] = mapped_column(JSON, default=list)

    abuse_score: Mapped[int | None] = mapped_column(Integer, default=None)
    abuse_total_reports: Mapped[int | None] = mapped_column(Integer, default=None)
    abuse_country: Mapped[str | None] = mapped_column(String(8), default=None)
    abuse_isp: Mapped[str | None] = mapped_column(Text, default=None)

    global_hashes: Mapped[dict] = mapped_column(
        JSON, default=lambda: {"md5": [], "sha1": [], "sha256": []}
    )
    body_text: Mapped[str | None] = mapped_column(Text, default=None)

    score: Mapped[int | None] = mapped_column(Integer, default=None)
    verdict: Mapped[str | None] = mapped_column(String(16), default=None)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    urls: Mapped[list["UrlIndicator"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    attachments: Mapped[list["AttachmentIndicator"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", lazy="selectin"
    )
    reasons: Mapped[list["ScoreReason"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="ScoreReason.order_index",
    )


from backend.models.attachment_indicator import AttachmentIndicator  # noqa: E402
from backend.models.score_reason import ScoreReason  # noqa: E402
from backend.models.url_indicator import UrlIndicator  # noqa: E402
