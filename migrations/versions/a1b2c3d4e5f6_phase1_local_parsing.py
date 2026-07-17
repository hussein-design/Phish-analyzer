"""Phase 1 – local parsing: MIME parts, lure categories, anchor mismatches

Revision ID: a1b2c3d4e5f6
Revises: 03dadcfda136
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f6"
down_revision = "03dadcfda136"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("mime_parts", sa.JSON(), nullable=True, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("lure_categories", sa.JSON(), nullable=True, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("anchor_mismatches", sa.JSON(), nullable=True, server_default="[]")
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("anchor_mismatches")
        batch_op.drop_column("lure_categories")
        batch_op.drop_column("mime_parts")
