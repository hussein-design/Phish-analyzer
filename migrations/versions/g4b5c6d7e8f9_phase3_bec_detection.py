"""Phase 3 BEC detection — vip_identities table and bec_score columns.

Revision ID: g4b5c6d7e8f9
Revises: f3a4b5c6d7e8
Create Date: 2026-10-01

Schema additions
----------------
1. vip_identities table — admin-configurable protected-identity list used by
   the vip_impersonation BEC signal.  DB-backed so admins can add/remove
   entries without a code deploy.

2. email_analyses columns:
   - bec_score       (Integer, nullable) — BEC signal sub-score
   - bec_reasons     (JSON list)         — reasons that fired
   - sig_vip_impersonation      (Boolean, nullable)
   - sig_financial_request      (Boolean, nullable)
   - sig_vendor_fraud           (Boolean, nullable)
   - sig_authority_pressure     (Boolean, nullable)

These mirror the behavioral_* pattern added in migration e2f3a4b5c6d7 so the
API and UI can surface each signal independently.
"""

from alembic import op
import sqlalchemy as sa

revision = "g4b5c6d7e8f9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── vip_identities ────────────────────────────────────────────────────────
    op.create_table(
        "vip_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("protected_email", sa.String(512), nullable=True),
        sa.Column("protected_domain", sa.String(255), nullable=False),
        sa.Column("title", sa.String(128), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_vip_identities_email", "vip_identities", ["protected_email"]
    )
    op.create_index(
        "ix_vip_identities_domain", "vip_identities", ["protected_domain"]
    )

    # ── email_analyses: BEC scoring columns ───────────────────────────────────
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(sa.Column("bec_score", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("bec_reasons", sa.JSON(), nullable=True, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("sig_vip_impersonation", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_financial_request", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_vendor_fraud", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_authority_pressure", sa.Boolean(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("sig_authority_pressure")
        batch_op.drop_column("sig_vendor_fraud")
        batch_op.drop_column("sig_financial_request")
        batch_op.drop_column("sig_vip_impersonation")
        batch_op.drop_column("bec_reasons")
        batch_op.drop_column("bec_score")

    op.drop_index("ix_vip_identities_domain", table_name="vip_identities")
    op.drop_index("ix_vip_identities_email", table_name="vip_identities")
    op.drop_table("vip_identities")
