"""Phase C — reason_evidence column for per-signal evidence data.

Revision ID: i1j2k3l4m5n6
Revises: h5c6d7e8f9a0
Create Date: 2026-10-17

Schema additions
----------------
email_analyses.reason_evidence  (JSON, nullable)

Stores a list of evidence dicts, one per fired signal:

    [
        {
            "reason":   "<exact reason string shown to the user>",
            "category": "static" | "dynamic" | "behavioral" | "bec",
            "signal":   "<signal_id>",
            "evidence": { ... signal-specific key/value pairs ... }
        },
        ...
    ]

NULL for analyses predating Phase C.  The column has no server default so
old rows remain NULL — never coerced to an empty list.
"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "i1j2k3l4m5n6"
down_revision = "h5c6d7e8f9a0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "reason_evidence",
                sa.JSON(),
                nullable=True,
                # No server_default — old rows stay NULL (the NULL sentinel
                # contract: NULL means pre-Phase-C, not "no evidence found").
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("reason_evidence")
