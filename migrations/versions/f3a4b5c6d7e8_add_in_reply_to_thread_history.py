"""Phase 2 patch — add in_reply_to column to thread_history.

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7
Create Date: 2026-10-01

Rationale
---------
The reply_chain_break signal used subject-string matching alone to determine
thread membership. When two unrelated emails share a generic subject
("Re: Invoice", "Re: Hi") they share a thread_key and a legitimate second
thread is flagged as a chain break — a false positive.

Adding in_reply_to (the Message-ID the email explicitly claims to be
replying to) lets _check_reply_chain_break suppress the signal when the
In-Reply-To header matches a known message_id already in thread_history,
even if the sender is new to the thread. This is the correct interpretation:
In-Reply-To is a deliberate client-generated reference, not a heuristic.

The column is nullable because:
  - Many legitimate emails omit In-Reply-To (MUA bugs, list servers, etc.)
  - Existing thread_history rows have no value to backfill
  - The signal degrades gracefully to sender-only matching when absent
"""

from alembic import op
import sqlalchemy as sa

revision = "f3a4b5c6d7e8"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("thread_history", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("in_reply_to", sa.Text(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("thread_history", schema=None) as batch_op:
        batch_op.drop_column("in_reply_to")
