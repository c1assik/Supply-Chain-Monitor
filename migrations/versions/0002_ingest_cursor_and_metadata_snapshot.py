"""ingest cursor and metadata snapshot

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingest_cursors",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("serial", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_ingest_cursors")),
    )
    op.add_column(
        "releases",
        sa.Column(
            "pypi_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("releases", "pypi_metadata")
    op.drop_table("ingest_cursors")
