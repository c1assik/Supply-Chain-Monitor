"""SQLAlchemy models. Schema changes go through Alembic migrations."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pypi_monitor.domain import ArtifactType, DecidedBy, Label, ReleaseStatus, Severity

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """Store enum values in a VARCHAR with a CHECK, so adding a value is a plain migration."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=16,
        values_callable=lambda cls: [member.value for member in cls],
    )


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    normalized_name: Mapped[str] = mapped_column(String(255), unique=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    downloads_rank: Mapped[int | None] = mapped_column(Integer)
    is_popular: Mapped[bool] = mapped_column(server_default="false")


class Release(Base):
    __tablename__ = "releases"
    __table_args__ = (
        UniqueConstraint("package_id", "version"),
        Index(None, "status"),
        Index(None, "serial"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id", ondelete="CASCADE"))
    version: Mapped[str] = mapped_column(String(255))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    serial: Mapped[int | None] = mapped_column(BigInteger)
    maintainers: Mapped[list[Any]] = mapped_column(JSONB, server_default="[]")
    prev_release_id: Mapped[int | None] = mapped_column(
        ForeignKey("releases.id", ondelete="SET NULL")
    )
    # Snapshot of the PyPI metadata: packages get deleted, and it is evidence.
    pypi_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
    status: Mapped[ReleaseStatus] = mapped_column(
        _enum(ReleaseStatus, "status"), server_default=ReleaseStatus.QUEUED.value
    )
    # Grows when a file added after the analysis makes the release go through the stages again.
    revision: Mapped[int] = mapped_column(Integer, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IngestCursor(Base):
    """Last processed PyPI serial of a named event source."""

    __tablename__ = "ingest_cursors"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    serial: Mapped[int] = mapped_column(BigInteger)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("release_id", "filename"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    release_id: Mapped[int] = mapped_column(ForeignKey("releases.id", ondelete="CASCADE"))
    filename: Mapped[str] = mapped_column(String(512))
    type: Mapped[ArtifactType] = mapped_column(_enum(ArtifactType, "type"))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    storage_key: Mapped[str] = mapped_column(String(1024))


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (Index(None, "release_id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    release_id: Mapped[int] = mapped_column(ForeignKey("releases.id", ondelete="CASCADE"))
    analyzer: Mapped[str] = mapped_column(String(64))
    analyzer_version: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # The revision of the release this run analyzed: only runs of the current one are scored.
    revision: Mapped[int] = mapped_column(Integer, server_default="0")


class Signal(Base):
    __tablename__ = "signals"
    __table_args__ = (
        Index(None, "run_id"),
        Index(None, "rule_id"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    confidence: Mapped[float] = mapped_column(Float)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text)


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = (
        Index(None, "release_id"),
        CheckConstraint("score BETWEEN 0 AND 100", name="score_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    release_id: Mapped[int] = mapped_column(ForeignKey("releases.id", ondelete="CASCADE"))
    score: Mapped[int] = mapped_column(SmallInteger)
    level: Mapped[Severity] = mapped_column(_enum(Severity, "level"))
    decided_by: Mapped[DecidedBy] = mapped_column(_enum(DecidedBy, "decided_by"))
    label: Mapped[Label | None] = mapped_column(_enum(Label, "label"))
    comment: Mapped[str | None] = mapped_column(Text)
    # An automatic verdict belongs to one revision of the analysis; a human label to the release.
    revision: Mapped[int] = mapped_column(Integer, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
