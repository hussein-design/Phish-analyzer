"""Phase B — pipeline_stages column for per-stage progress tracking.

Revision ID: h5c6d7e8f9a0
Revises: g4b5c6d7e8f9
Create Date: 2026-10-08

Schema additions
----------------
email_analyses.pipeline_stages  (JSON, nullable)

Stores a dict of stage_key → status for the five pipeline stages:

    {
        "static":     "done",
        "enrichment": "running",
        "urlscan":    "pending",
        "sandbox":    "skipped",
        "behavioral": "pending"
    }

Status values: "pending" | "running" | "done" | "failed" | "timeout" | "skipped"

NULL means the analysis predates Phase B.  The frontend must render NULL as
"no stage data", never as perpetual "pending".  Any non-NULL value is a live
status dict that the frontend can render as individual stage indicators.

Downgrade: drop the column.  No data migration is needed — the column is
nullable and the old code paths are unaffected by its absence.
"""

from alembic import op
import sqlalchemy as sa

revision = "h5c6d7e8f9a0"
down_revision = "g4b5c6d7e8f9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "pipeline_stages",
                sa.JSON(),
                nullable=True,
                # NULL is the correct initial value for pre-Phase-B rows.
                # Do not add a server_default here — that would coerce old
                # rows to an empty dict, breaking the NULL sentinel contract.
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("pipeline_stages")
