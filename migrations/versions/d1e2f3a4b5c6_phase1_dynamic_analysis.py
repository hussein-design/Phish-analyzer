"""Phase 1 dynamic analysis — urlscan.io detonation, Hybrid Analysis behavioral
report, and static/dynamic score split columns.

Revision ID: d1e2f3a4b5c6
Revises: c3d4e5f6a7b8
Create Date: 2026-10-01
"""

from alembic import op
import sqlalchemy as sa

revision = "d1e2f3a4b5c6"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── email_analyses: urlscan.io URL detonation columns ────────────────────
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("urlscan_status", sa.String(16), nullable=True)
        )
        batch_op.add_column(
            sa.Column("urlscan_error", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("urlscan_screenshot_url", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("urlscan_verdict", sa.String(32), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "urlscan_redirect_chain",
                sa.JSON(),
                nullable=True,
                server_default="[]",
            )
        )
        # attachment behavioral detonation columns
        batch_op.add_column(
            sa.Column("dynamic_attachment_status", sa.String(16), nullable=True)
        )
        batch_op.add_column(
            sa.Column("dynamic_attachment_verdict", sa.String(32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("dynamic_attachment_score", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("dynamic_attachment_report_url", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "dynamic_attachment_tags",
                sa.JSON(),
                nullable=True,
                server_default="[]",
            )
        )
        batch_op.add_column(
            sa.Column("dynamic_attachment_error", sa.Text(), nullable=True)
        )
        # static vs dynamic score split
        batch_op.add_column(
            sa.Column("static_score", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("dynamic_score", sa.Integer(), nullable=True)
        )

    # ── app_settings: urlscan.io API key ─────────────────────────────────────
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("urlscan_key", sa.String(255), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("urlscan_key")

    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("dynamic_score")
        batch_op.drop_column("static_score")
        batch_op.drop_column("dynamic_attachment_error")
        batch_op.drop_column("dynamic_attachment_tags")
        batch_op.drop_column("dynamic_attachment_report_url")
        batch_op.drop_column("dynamic_attachment_score")
        batch_op.drop_column("dynamic_attachment_verdict")
        batch_op.drop_column("dynamic_attachment_status")
        batch_op.drop_column("urlscan_redirect_chain")
        batch_op.drop_column("urlscan_verdict")
        batch_op.drop_column("urlscan_screenshot_url")
        batch_op.drop_column("urlscan_error")
        batch_op.drop_column("urlscan_status")
