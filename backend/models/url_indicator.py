from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base


class UrlIndicator(Base):
    __tablename__ = "url_indicators"
    __table_args__ = (Index("ix_url_indicators_analysis_id", "analysis_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("email_analyses.id", ondelete="CASCADE")
    )

    url: Mapped[str] = mapped_column(Text)
    vt_malicious: Mapped[int] = mapped_column(Integer, default=0)
    vt_harmless: Mapped[int] = mapped_column(Integer, default=0)
    vt_suspicious: Mapped[int] = mapped_column(Integer, default=0)
    is_suspicious_keyword: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ip_host: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shortener: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspicious_tld: Mapped[bool] = mapped_column(Boolean, default=False)
    is_punycode: Mapped[bool] = mapped_column(Boolean, default=False)

    # Phase 2: URL reputation enrichment
    # expanded_url: final destination after following all redirects
    expanded_url: Mapped[str | None] = mapped_column(Text, default=None)
    # page_title: <title> of the resolved page, useful for brand-spoof detection
    page_title: Mapped[str | None] = mapped_column(String(512), default=None)
    # redirect_count: number of HTTP redirects followed
    redirect_count: Mapped[int] = mapped_column(Integer, default=0)
    # final_status_code: HTTP status code at the final destination
    final_status_code: Mapped[int | None] = mapped_column(Integer, default=None)
    # is_redirect_suspicious: final domain differs significantly from original
    is_redirect_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)

    analysis: Mapped["EmailAnalysis"] = relationship(back_populates="urls")


from backend.models.analysis import EmailAnalysis  # noqa: E402
