"""Add active_url_fetch to app_settings.

Revision ID: j2k3l4m5n6o7
Revises: i1j2k3l4m5n6
Create Date: 2026-10-19

Schema additions
----------------
app_settings.active_url_fetch  (BOOLEAN, server_default FALSE, NOT NULL)

When False (the default) the url_intelligence_service skips all outbound
HTTP requests to URL targets in emails.  VT/urlscan providers are unaffected.

Downgrade: drop the column.
"""

from alembic import op
import sqlalchemy as sa

revision = "j2k3l4m5n6o7"
down_revision = "i1j2k3l4m5n6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "active_url_fetch",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("active_url_fetch")
