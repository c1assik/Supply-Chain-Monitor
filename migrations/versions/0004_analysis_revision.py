"""analysis revision

A release is analyzed again when a file is added to it after its verdict: a wheel for another
platform, or one uploaded into an old version. Each analysis gets a revision, and runs and
automatic verdicts of earlier revisions stay as history.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("releases", "analysis_runs", "verdicts")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table, sa.Column("revision", sa.Integer(), server_default="0", nullable=False)
        )


def downgrade() -> None:
    # Only the latest revision stays meaningful without the column.
    op.execute(
        "DELETE FROM analysis_runs r USING releases rel "
        "WHERE r.release_id = rel.id AND r.revision <> rel.revision"
    )
    op.execute(
        "DELETE FROM verdicts v USING releases rel "
        "WHERE v.release_id = rel.id AND v.decided_by = 'auto' AND v.revision <> rel.revision"
    )
    for table in reversed(_TABLES):
        op.drop_column(table, "revision")
