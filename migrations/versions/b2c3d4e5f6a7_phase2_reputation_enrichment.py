"""Phase 2 – Reputation enrichment: Shodan, VT hash, extended URL/attachment fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # email_analyses: Shodan enrichment columns
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("shodan_enrichment_status", sa.String(16), nullable=True)
        )
        batch_op.add_column(
            sa.Column("shodan_enrichment_error", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("shodan_data", sa.JSON(), nullable=True)
        )

    # url_indicators: Phase 2 URL intelligence columns
    with op.batch_alter_table("url_indicators", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("expanded_url", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("page_title", sa.String(512), nullable=True)
        )
        batch_op.add_column(
            sa.Column("redirect_count", sa.Integer(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("final_status_code", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("is_redirect_suspicious", sa.Boolean(), nullable=True, server_default="0")
        )

    # attachment_indicators: Phase 2 VT hash + Phase 3 static analysis columns
    with op.batch_alter_table("attachment_indicators", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("vt_hash_malicious", sa.Integer(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("vt_hash_suspicious", sa.Integer(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("vt_hash_status", sa.String(16), nullable=True)
        )
        batch_op.add_column(
            sa.Column("is_macro_enabled", sa.Boolean(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("has_embedded_executable", sa.Boolean(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("is_archive", sa.Boolean(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("mime_magic_mismatch", sa.Boolean(), nullable=True, server_default="0")
        )
        batch_op.add_column(
            sa.Column("file_metadata", sa.JSON(), nullable=True)
        )

    # app_settings: Shodan API key
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("shodan_key", sa.String(255), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings", schema=None) as batch_op:
        batch_op.drop_column("shodan_key")

    with op.batch_alter_table("attachment_indicators", schema=None) as batch_op:
        batch_op.drop_column("file_metadata")
        batch_op.drop_column("mime_magic_mismatch")
        batch_op.drop_column("is_archive")
        batch_op.drop_column("has_embedded_executable")
        batch_op.drop_column("is_macro_enabled")
        batch_op.drop_column("vt_hash_status")
        batch_op.drop_column("vt_hash_suspicious")
        batch_op.drop_column("vt_hash_malicious")

    with op.batch_alter_table("url_indicators", schema=None) as batch_op:
        batch_op.drop_column("is_redirect_suspicious")
        batch_op.drop_column("final_status_code")
        batch_op.drop_column("redirect_count")
        batch_op.drop_column("page_title")
        batch_op.drop_column("expanded_url")

    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("shodan_data")
        batch_op.drop_column("shodan_enrichment_error")
        batch_op.drop_column("shodan_enrichment_status")
