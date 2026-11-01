"""baseline release status

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = "'queued', 'downloaded', 'analyzed', 'alerted', 'clean', 'failed'"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_releases_status"), "releases", type_="check")
    op.create_check_constraint(
        op.f("ck_releases_status"), "releases", f"status IN ({_STATUSES}, 'baseline')"
    )


def downgrade() -> None:
    # Baselines were never analyzed and hold no results: only their artifacts' rows go with them.
    op.execute("DELETE FROM releases WHERE status = 'baseline'")
    op.drop_constraint(op.f("ck_releases_status"), "releases", type_="check")
    op.create_check_constraint(op.f("ck_releases_status"), "releases", f"status IN ({_STATUSES})")
