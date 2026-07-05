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

    analysis: Mapped["EmailAnalysis"] = relationship(back_populates="attachments")


from backend.models.analysis import EmailAnalysis  # noqa: E402
