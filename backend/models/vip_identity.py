"""VIP / protected-identity table for Phase 3 BEC detection.

Admins populate this table (via a future settings UI or direct DB edit) with
the names, email addresses, and domains of people whose identities are
frequently impersonated in BEC attacks against this organisation — typically:
  - CEO / CFO / COO / Board members
  - Finance team members with wire-transfer authority
  - IT administrators
  - Key external partners (auditors, legal counsel, major vendors)

The vip_impersonation signal in bec_signals_service compares the From display
name and sending domain against every row in this table.

FIELDS
------
name            Human-readable label, e.g. "Jane Smith (CFO)"
protected_email The real email address of this person, e.g. "jane.smith@corp.com".
                May be None if only a domain-level match is needed.
protected_domain The organisation domain(s) this person legitimately sends from,
                e.g. "corp.com".  A sender whose display name matches this VIP
                entry but whose domain is NOT protected_domain is flagged.
title           Optional role/title for display in the UI, e.g. "Chief Financial Officer".
is_active       Allow disabling an entry without deleting it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class VIPIdentity(Base):
    __tablename__ = "vip_identities"
    __table_args__ = (
        # Fast lookup by protected_email for impersonation checks
        Index("ix_vip_identities_email", "protected_email"),
        # Fast lookup by protected_domain
        Index("ix_vip_identities_domain", "protected_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Human-readable label shown in the UI and in alert reasons.
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # The real email address.  Stored lowercase, no display-name wrapper.
    # Nullable — some entries may only protect a domain (e.g. whole exec team).
    protected_email: Mapped[str | None] = mapped_column(
        String(512), nullable=True, default=None
    )

    # The legitimate sending domain for this identity.  Emails whose display
    # name or address matches this VIP but whose From domain is NOT this domain
    # (and is not a legitimate subdomain of it) trigger vip_impersonation.
    protected_domain: Mapped[str] = mapped_column(String(255), nullable=False)

    # Optional role label for UI display ("CEO", "CFO", "Finance Manager", etc.)
    title: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)

    # Soft-delete: set is_active=False instead of deleting to preserve audit trail.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
