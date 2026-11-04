"""What the dashboard reads from the database and the one thing it writes: manual labels."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sqlalchemy import func, select

from pypi_monitor.db.models import AnalysisRun, Artifact, Package, Release, Signal, Verdict
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import DecidedBy, Label, ReleaseStatus, Severity
from pypi_monitor.pipeline.stages import primary_artifacts
from pypi_monitor.web.diff import StoredArtifact

PAGE_SIZE = 50
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


class LevelFilter(StrEnum):
    ALERTS = "alerts"
    MEDIUM = "medium"


class LabelFilter(StrEnum):
    ANY = "any"
    NONE = "none"
    MALICIOUS = "malicious"
    BENIGN = "benign"


_LEVELS = {
    LevelFilter.ALERTS: (Severity.HIGH, Severity.CRITICAL),
    # Low stays out of the feed: it is stored, not shown.
    LevelFilter.MEDIUM: (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL),
}


@dataclass(frozen=True)
class FeedRow:
    release_id: int
    name: str
    version: str
    status: ReleaseStatus
    score: int
    level: Severity
    label: Label | None
    popular: bool
    decided_at: datetime


@dataclass(frozen=True)
class FeedPage:
    rows: list[FeedRow]
    has_more: bool


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def feed(
    sessions: Sessions, level: LevelFilter, label: LabelFilter, search: str, page: int
) -> FeedPage:
    latest = (
        select(Verdict.label)
        .where(Verdict.release_id == Release.id, Verdict.decided_by == DecidedBy.HUMAN)
        .order_by(Verdict.id.desc())
        .limit(1)
        .correlate(Release)
        .scalar_subquery()
    )
    # A release analyzed again has an automatic verdict per revision: the last one stands.
    last_auto = (
        select(func.max(Verdict.id))
        .where(Verdict.release_id == Release.id, Verdict.decided_by == DecidedBy.AUTO)
        .correlate(Release)
        .scalar_subquery()
    )
    query = (
        select(
            Release.id,
            Package.name,
            Release.version,
            Release.status,
            Verdict.score,
            Verdict.level,
            latest.label("label"),
            Package.is_popular,
            Verdict.created_at,
        )
        .join(Package, Package.id == Release.package_id)
        .join(Verdict, Verdict.release_id == Release.id)
        .where(Verdict.id == last_auto, Verdict.level.in_(_LEVELS[level]))
    )
    if search:
        pattern = f"%{_escape_like(search)}%"
        query = query.where(Package.name.ilike(pattern, escape="\\"))
    if label is LabelFilter.NONE:
        query = query.where(latest.is_(None))
    elif label is not LabelFilter.ANY:
        query = query.where(latest == Label(label.value))
    query = query.order_by(Verdict.id.desc()).limit(PAGE_SIZE + 1).offset((page - 1) * PAGE_SIZE)
    async with sessions() as session:
        rows = [FeedRow(*row) for row in await session.execute(query)]
    return FeedPage(rows[:PAGE_SIZE], len(rows) > PAGE_SIZE)


@dataclass(frozen=True)
class SignalView:
    analyzer: str
    rule_id: str
    severity: Severity
    confidence: float
    location: str | None
    evidence: str


@dataclass(frozen=True)
class ReleaseCard:
    release: Release
    package: Package
    previous_version: str | None
    verdict: Verdict | None
    labels: list[Verdict]
    signals: list[SignalView]
    failed_runs: list[AnalysisRun]
    artifacts: list[Artifact]

    @property
    def label(self) -> Label | None:
        return self.labels[0].label if self.labels else None


def _location(signal: Signal) -> str | None:
    if signal.file_path and signal.line:
        return f"{signal.file_path}:{signal.line}"
    return signal.file_path


async def release_card(sessions: Sessions, release_id: int) -> ReleaseCard | None:
    async with sessions() as session:
        found = (
            await session.execute(
                select(Release, Package)
                .join(Package, Package.id == Release.package_id)
                .where(Release.id == release_id)
            )
        ).one_or_none()
        if found is None:
            return None
        release, package = found[0], found[1]
        previous = (
            None
            if release.prev_release_id is None
            else await session.get(Release, release.prev_release_id)
        )
        verdicts = list(
            await session.scalars(
                select(Verdict).where(Verdict.release_id == release_id).order_by(Verdict.id.desc())
            )
        )
        # The current revision: a file added later may have made the earlier one obsolete.
        current = (AnalysisRun.release_id == release_id) & (
            AnalysisRun.revision == release.revision
        )
        runs = list(await session.scalars(select(AnalysisRun).where(current)))
        signals = list(
            await session.execute(
                select(AnalysisRun.analyzer, Signal)
                .join(Signal, Signal.run_id == AnalysisRun.id)
                .where(current)
            )
        )
        artifacts = list(
            await session.scalars(
                select(Artifact).where(Artifact.release_id == release_id).order_by(Artifact.id)
            )
        )
    views = [
        SignalView(
            analyzer,
            signal.rule_id,
            signal.severity,
            signal.confidence,
            _location(signal),
            signal.evidence,
        )
        for analyzer, signal in signals
    ]
    views.sort(key=lambda v: (-_SEVERITY_RANK[v.severity], -v.confidence, v.rule_id))
    return ReleaseCard(
        release=release,
        package=package,
        previous_version=previous.version if previous else None,
        verdict=next((v for v in verdicts if v.decided_by is DecidedBy.AUTO), None),
        labels=[v for v in verdicts if v.decided_by is DecidedBy.HUMAN],
        signals=views,
        failed_runs=[run for run in runs if run.error],
        artifacts=artifacts,
    )


async def add_label(
    sessions: Sessions, verdict: Verdict, label: Label, comment: str | None
) -> None:
    """A label is a new verdict, so the history of decisions is kept next to the automatic one."""
    async with sessions.begin() as session:
        session.add(
            Verdict(
                release_id=verdict.release_id,
                score=verdict.score,
                level=verdict.level,
                decided_by=DecidedBy.HUMAN,
                label=label,
                comment=comment,
            )
        )


async def stored_artifacts(sessions: Sessions, release_id: int | None) -> list[StoredArtifact]:
    if release_id is None:
        return []
    async with sessions() as session:
        artifacts = list(
            await session.scalars(select(Artifact).where(Artifact.release_id == release_id))
        )
    # The diff page shows what the diff compared: the other wheels are in the signals of the card.
    primary, _ = primary_artifacts(artifacts)
    return [StoredArtifact(artifact.filename, artifact.storage_key) for artifact in primary]
