"""Phase 3 – Sandbox detonation and email_analyses sandbox result columns

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # app_settings: sandbox provider + API key
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("sandbox_provider", sa.String(32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_api_key", sa.String(255), nullable=True)
        )

    # email_analyses: sandbox detonation result columns
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("sandbox_status", sa.String(16), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_provider", sa.String(32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_verdict", sa.String(32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_score", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_report_url", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sandbox_tags", sa.JSON(), nullable=True, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("sandbox_error", sa.Text(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("sandbox_error")
        batch_op.drop_column("sandbox_tags")
        batch_op.drop_column("sandbox_report_url")
        batch_op.drop_column("sandbox_score")
        batch_op.drop_column("sandbox_verdict")
        batch_op.drop_column("sandbox_provider")
        batch_op.drop_column("sandbox_status")

    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("sandbox_api_key")
        batch_op.drop_column("sandbox_provider")
