"""initial schema

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "packages",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("downloads_rank", sa.Integer(), nullable=True),
        sa.Column("is_popular", sa.Boolean(), server_default="false", nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_packages")),
        sa.UniqueConstraint("normalized_name", name=op.f("uq_packages_normalized_name")),
    )
    op.create_table(
        "releases",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("package_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("serial", sa.BigInteger(), nullable=True),
        sa.Column(
            "maintainers",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("prev_release_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "downloaded",
                "analyzed",
                "alerted",
                "clean",
                "failed",
                name="status",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="queued",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["package_id"],
            ["packages.id"],
            name=op.f("fk_releases_package_id_packages"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["prev_release_id"],
            ["releases.id"],
            name=op.f("fk_releases_prev_release_id_releases"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_releases")),
        sa.UniqueConstraint("package_id", "version", name=op.f("uq_releases_package_id_version")),
    )
    op.create_index(op.f("ix_releases_serial"), "releases", ["serial"], unique=False)
    op.create_index(op.f("ix_releases_status"), "releases", ["status"], unique=False)
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("release_id", sa.BigInteger(), nullable=False),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("analyzer_version", sa.String(length=64), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["releases.id"],
            name=op.f("fk_analysis_runs_release_id_releases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_runs")),
    )
    op.create_index(
        op.f("ix_analysis_runs_release_id"), "analysis_runs", ["release_id"], unique=False
    )
    op.create_table(
        "artifacts",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("release_id", sa.BigInteger(), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "sdist", "wheel", name="type", native_enum=False, create_constraint=True, length=16
            ),
            nullable=False,
        ),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["releases.id"],
            name=op.f("fk_artifacts_release_id_releases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
        sa.UniqueConstraint(
            "release_id", "filename", name=op.f("uq_artifacts_release_id_filename")
        ),
    )
    op.create_table(
        "verdicts",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("release_id", sa.BigInteger(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column(
            "level",
            sa.Enum(
                "low",
                "medium",
                "high",
                "critical",
                name="level",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column(
            "decided_by",
            sa.Enum(
                "auto",
                "human",
                name="decided_by",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column(
            "label",
            sa.Enum(
                "malicious",
                "benign",
                name="label",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=True,
        ),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name=op.f("ck_verdicts_score_range")),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["releases.id"],
            name=op.f("fk_verdicts_release_id_releases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verdicts")),
    )
    op.create_index(op.f("ix_verdicts_release_id"), "verdicts", ["release_id"], unique=False)
    op.create_table(
        "signals",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name=op.f("ck_signals_confidence_range")),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["analysis_runs.id"],
            name=op.f("fk_signals_run_id_analysis_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_signals")),
    )
    op.create_index(op.f("ix_signals_rule_id"), "signals", ["rule_id"], unique=False)
    op.create_index(op.f("ix_signals_run_id"), "signals", ["run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_signals_run_id"), table_name="signals")
    op.drop_index(op.f("ix_signals_rule_id"), table_name="signals")
    op.drop_table("signals")
    op.drop_index(op.f("ix_verdicts_release_id"), table_name="verdicts")
    op.drop_table("verdicts")
    op.drop_table("artifacts")
    op.drop_index(op.f("ix_analysis_runs_release_id"), table_name="analysis_runs")
    op.drop_table("analysis_runs")
    op.drop_index(op.f("ix_releases_status"), table_name="releases")
    op.drop_index(op.f("ix_releases_serial"), table_name="releases")
    op.drop_table("releases")
    op.drop_table("packages")
