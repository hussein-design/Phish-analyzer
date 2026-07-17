from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base


class AttachmentIndicator(Base):
    __tablename__ = "attachment_indicators"
    __table_args__ = (
        Index("ix_attachment_indicators_analysis_id", "analysis_id"),
        Index("ix_attachment_indicators_sha256", "sha256"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("email_analyses.id", ondelete="CASCADE")
    )

    filename: Mapped[str | None] = mapped_column(Text, default=None)
    content_type: Mapped[str | None] = mapped_column(String(255), default=None)
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    is_executable_like: Mapped[bool] = mapped_column(Boolean, default=False)
    is_double_extension: Mapped[bool] = mapped_column(Boolean, default=False)

    # Phase 2: VirusTotal hash reputation
    vt_hash_malicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_hash_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_hash_status: Mapped[str | None] = mapped_column(String(16), default=None)

    # Phase 3 (reserved): static analysis flags set by attachment_intelligence_service
    is_macro_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    has_embedded_executable: Mapped[bool] = mapped_column(Boolean, default=False)
    is_archive: Mapped[bool] = mapped_column(Boolean, default=False)
    mime_magic_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    # Store extracted metadata as a JSON blob (author, creation date, app, etc.)
    file_metadata: Mapped[dict | None] = mapped_column(
        __import__("sqlalchemy").JSON, default=None
    )

    analysis: Mapped["EmailAnalysis"] = relationship(back_populates="attachments")


from backend.models.analysis import EmailAnalysis  # noqa: E402
