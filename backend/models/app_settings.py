from __future__ import annotations

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


class AppSettingsRecord(Base):
    """Single-row table: exactly one settings object, editable wholesale
    from the Settings dialog. A generic key/value table would be
    over-engineering for a value this shaped."""

    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scoring_weights: Mapped[dict] = mapped_column(JSON)
    brand_domains: Mapped[dict] = mapped_column(JSON)
    url_suspicious_keywords: Mapped[list[str]] = mapped_column(JSON)
    suspicious_tlds: Mapped[list[str]] = mapped_column(JSON, default=list)
    url_shorteners: Mapped[list[str]] = mapped_column(JSON, default=list)
    urgency_keywords: Mapped[list[str]] = mapped_column(JSON, default=list)

    virustotal_key: Mapped[str | None] = mapped_column(String(255), default=None)
    abuseipdb_key: Mapped[str | None] = mapped_column(String(255), default=None)
    shodan_key: Mapped[str | None] = mapped_column(String(255), default=None)
    # Phase 5: sandbox provider settings
    sandbox_provider: Mapped[str | None] = mapped_column(String(32), default=None)
    sandbox_api_key: Mapped[str | None] = mapped_column(String(255), default=None)
