"""Phase 2 behavioral analysis — sender_history, thread_history tables and
behavioral_score columns on email_analyses.

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-10-01

Design decisions
----------------
* sender_history and thread_history are new first-class tables, not ad-hoc
  JSON blobs.  They are application data the user will want preserved across
  updates, unlike the enrichment_cache which is a disposable speed optimisation.

* domain_age lookup results go through the EXISTING enrichment_cache table
  (namespace="domain_age", TTL=2592000).  A separate table for domain ages
  would duplicate the L1/L2 cache design already in cache.py.

* behavioral_score/behavioral_reasons mirror the static_score/dynamic_score
  split already on email_analyses so the API can surface them independently.

* Five boolean signal flag columns (sig_*) make per-signal querying trivial
  without requiring callers to parse the JSON reasons array.
"""

from alembic import op
import sqlalchemy as sa

revision = "e2f3a4b5c6d7"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── sender_history ────────────────────────────────────────────────────────
    op.create_table(
        "sender_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("recipient", sa.String(512), nullable=False),
        sa.Column("sender", sa.String(512), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("message_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("send_hours", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_index(
        "ix_sender_history_recipient_sender",
        "sender_history",
        ["recipient", "sender"],
        unique=True,
    )

    # ── thread_history ────────────────────────────────────────────────────────
    op.create_table(
        "thread_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("recipient", sa.String(512), nullable=False),
        sa.Column("thread_key", sa.String(512), nullable=False),
        sa.Column("sender", sa.String(512), nullable=False),
        sa.Column("message_id", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_thread_history_recipient_key",
        "thread_history",
        ["recipient", "thread_key"],
    )

    # ── email_analyses: behavioral scoring columns ────────────────────────────
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("behavioral_score", sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "behavioral_reasons",
                sa.JSON(),
                nullable=True,
                server_default="[]",
            )
        )
        batch_op.add_column(
            sa.Column("sig_first_time_sender", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_domain_age_anomaly", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_display_name_mismatch", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_reply_chain_break", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("sig_send_time_anomaly", sa.Boolean(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("email_analyses", schema=None) as batch_op:
        batch_op.drop_column("sig_send_time_anomaly")
        batch_op.drop_column("sig_reply_chain_break")
        batch_op.drop_column("sig_display_name_mismatch")
        batch_op.drop_column("sig_domain_age_anomaly")
        batch_op.drop_column("sig_first_time_sender")
        batch_op.drop_column("behavioral_reasons")
        batch_op.drop_column("behavioral_score")

    op.drop_index("ix_thread_history_recipient_key", table_name="thread_history")
    op.drop_table("thread_history")

    op.drop_index("ix_sender_history_recipient_sender", table_name="sender_history")
    op.drop_table("sender_history")
