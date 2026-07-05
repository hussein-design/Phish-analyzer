from __future__ import annotations

from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base


class ScoreReason(Base):
    __tablename__ = "score_reasons"
    __table_args__ = (Index("ix_score_reasons_analysis_id", "analysis_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("email_analyses.id", ondelete="CASCADE")
    )

    reason_text: Mapped[str] = mapped_column(Text)
    order_index: Mapped[int] = mapped_column(Integer, default=0)

    analysis: Mapped["EmailAnalysis"] = relationship(back_populates="reasons")


from backend.models.analysis import EmailAnalysis  # noqa: E402
