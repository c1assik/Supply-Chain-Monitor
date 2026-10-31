"""Pipeline stages: queued → downloaded → analyzed → alerted / clean / failed.

A stage acts only on a release in its own status and commits the next status together with its
results, so running a stage twice is harmless and a release can always be picked up again.
"""

import asyncio
import logging
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import Executor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

from pypi_monitor.alerts.telegram import Alert, Notifier
from pypi_monitor.analyzers.base import Analyzer, ReleaseContext
from pypi_monitor.analyzers.base import Signal as FoundSignal
from pypi_monitor.db.models import AnalysisRun, Artifact, Package, Release, Verdict
from pypi_monitor.db.models import Signal as SignalRow
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import ArtifactType, DecidedBy, ReleaseStatus, Severity
from pypi_monitor.metrics import (
    ALERTS,
    ANALYZER_ERRORS,
    ARTIFACTS_SKIPPED,
    VERDICT_LATENCY,
    VERDICTS,
)
from pypi_monitor.pipeline.queue import ReleaseQueue, Stage
from pypi_monitor.pipeline.unpack import (
    UnpackLimits,
    UnsafeArchiveError,
    UnsupportedArchiveError,
    unpack,
)
from pypi_monitor.pypi import NotReadyError, PyPIClient
from pypi_monitor.scoring import ScoringConfig, score_release
from pypi_monitor.storage import ArtifactStorage

log = logging.getLogger(__name__)

MAX_EVIDENCE_LENGTH = 4000
MAX_PATH_LENGTH = 1024
UNPACK_ANALYZER = "unpack"
UNPACK_ANALYZER_VERSION = "1"
ALERT_LEVELS = frozenset({Severity.HIGH, Severity.CRITICAL})
UNSAFE_ARCHIVE_SEVERITY = {
    "path_traversal": Severity.HIGH,
    "too_large": Severity.MEDIUM,
    "too_many_files": Severity.MEDIUM,
    "corrupt": Severity.LOW,
}
RESUMABLE = {
    ReleaseStatus.QUEUED: Stage.DOWNLOAD,
    ReleaseStatus.DOWNLOADED: Stage.ANALYZE,
    ReleaseStatus.ANALYZED: Stage.SCORE,
}


@dataclass(frozen=True)
class _Run:
    analyzer: str
    version: str
    signals: list[FoundSignal]
    duration_ms: int
    error: str | None = None


class Pipeline:
    def __init__(
        self,
        *,
        sessions: Sessions,
        client: PyPIClient,
        storage: ArtifactStorage,
        queue: ReleaseQueue,
        notifier: Notifier,
        scoring: ScoringConfig,
        analyzers: Sequence[Analyzer],
        limits: UnpackLimits,
        max_artifact_bytes: int,
        analyzer_timeout_s: float,
        executor: Executor | None = None,
    ) -> None:
        self._sessions = sessions
        self._client = client
        self._storage = storage
        self._queue = queue
        self._notifier = notifier
        self._scoring = scoring
        self.analyzers = analyzers
        self._limits = limits
        self._max_artifact_bytes = max_artifact_bytes
        self._analyzer_timeout_s = analyzer_timeout_s
        # CPU-bound work: run in threads it would fight for the GIL with the event loop.
        self._executor = executor

    async def download(self, release_id: int) -> None:
        loaded = await self._load(release_id, ReleaseStatus.QUEUED)
        if loaded is None:
            return
        release, package = loaded
        data = await self._client.release(package.name, release.version)
        # A release is announced before its first file is uploaded.
        if not data.get("urls"):
            raise NotReadyError(f"{package.name} {release.version} has no files")
        snapshot = await self._snapshot(package.name, data)
        artifacts = await self._fetch_artifacts(package, release, data["urls"])
        uploads = [_upload_time(file) for file in data["urls"]]

        async with self._sessions.begin() as session:
            if artifacts:
                await session.execute(insert(Artifact).values(artifacts).on_conflict_do_nothing())
            await session.execute(
                update(Release)
                .where(Release.id == release_id)
                .values(
                    status=ReleaseStatus.DOWNLOADED,
                    maintainers=[role["user"] for role in _roles(data)],
                    pypi_metadata=snapshot,
                    serial=data.get("last_serial"),
                    published_at=min(uploads),
                )
            )
        await self._queue.enqueue(Stage.ANALYZE, release_id)

    async def _snapshot(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        project = await self._client.project(name)
        uploads = [
            _upload_time(file) for files in project.get("releases", {}).values() for file in files
        ]
        snapshot: dict[str, Any] = {
            "info": data["info"],
            "urls": data["urls"],
            "ownership": data.get("ownership", {}),
            "version_count": len(project.get("releases", {})),
            "first_upload": min(uploads).isoformat() if uploads else None,
        }
        if snapshot["version_count"] <= 1:
            snapshot["owner_package_counts"] = await self._owner_package_counts(data)
        stripped: dict[str, Any] = _strip_nul(snapshot)
        return stripped

    async def _owner_package_counts(self, data: dict[str, Any]) -> dict[str, int]:
        counts = {}
        for user in {role["user"] for role in _roles(data)}:
            try:
                packages = await self._client.user_packages(user)
            except Exception as e:
                # A nice-to-have signal must not hold the release back.
                log.warning("cannot list packages of %s: %r", user, e)
                return {}
            # All owners or nothing: a partial answer could wrongly look like a new account.
            if packages is None:
                return {}
            counts[user] = len(packages)
        return counts

    async def _fetch_artifacts(
        self, package: Package, release: Release, files: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        artifacts = []
        with tempfile.TemporaryDirectory(prefix="scm-download-") as directory:
            for file in choose_files(files, self._max_artifact_bytes):
                filename = _safe_filename(file["filename"])
                path = Path(directory) / filename
                sha256 = await self._client.download(file["url"], path, self._max_artifact_bytes)
                if sha256 != file["digests"]["sha256"]:
                    raise ValueError(f"sha256 mismatch for {filename}")
                key = f"{package.normalized_name}/{release.version}/{filename}"
                await asyncio.to_thread(self._storage.put, path, key)
                artifacts.append(
                    {
                        "release_id": release.id,
                        "filename": filename,
                        "type": _artifact_type(file),
                        "sha256": sha256,
                        "size": path.stat().st_size,
                        "storage_key": key,
                    }
                )
        return artifacts

    async def analyze(self, release_id: int) -> None:
        loaded = await self._load(release_id, ReleaseStatus.DOWNLOADED)
        if loaded is None:
            return
        release, package = loaded
        async with self._sessions() as session:
            artifacts = list(
                await session.scalars(select(Artifact).where(Artifact.release_id == release_id))
            )

        with tempfile.TemporaryDirectory(prefix="scm-analyze-") as directory:
            root = Path(directory)
            archives, unpacked = root / "archives", root / "unpacked"
            archives.mkdir()
            unpacked.mkdir()
            started = time.monotonic()
            unpack_signals = [
                signal
                for artifact in artifacts
                for signal in await self._unpack(artifact, archives, unpacked)
            ]
            runs = [
                _Run(
                    UNPACK_ANALYZER,
                    UNPACK_ANALYZER_VERSION,
                    unpack_signals,
                    _elapsed_ms(started),
                )
            ]
            context = ReleaseContext(
                name=package.name,
                version=release.version,
                metadata=release.pypi_metadata,
                artifact_dir=unpacked if artifacts else None,
            )
            runs += await asyncio.gather(*(self._run(a, context) for a in self.analyzers))

        async with self._sessions.begin() as session:
            for run in runs:
                row = AnalysisRun(
                    release_id=release_id,
                    analyzer=run.analyzer,
                    analyzer_version=run.version,
                    duration_ms=run.duration_ms,
                    error=run.error,
                )
                session.add(row)
                await session.flush()
                session.add_all(_signal_row(row.id, signal) for signal in run.signals)
            await session.execute(
                update(Release)
                .where(Release.id == release_id)
                .values(status=ReleaseStatus.ANALYZED)
            )
        await self._queue.enqueue(Stage.SCORE, release_id)

    async def _unpack(
        self, artifact: Artifact, archives: Path, unpacked: Path
    ) -> list[FoundSignal]:
        archive = archives / artifact.filename
        await asyncio.to_thread(self._storage.get, artifact.storage_key, archive)
        target = unpacked / artifact.filename
        target.mkdir()
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(self._executor, unpack, archive, target, self._limits)
        except UnsupportedArchiveError:
            ARTIFACTS_SKIPPED.labels("unsupported_archive").inc()
            log.warning("unsupported archive: %s", artifact.filename)
        except UnsafeArchiveError as e:
            # What was unpacked before the violation is still scanned.
            return [
                FoundSignal(
                    rule_id=f"archive.{e.reason}",
                    severity=UNSAFE_ARCHIVE_SEVERITY[e.reason],
                    confidence=0.9,
                    evidence=e.detail,
                    file_path=artifact.filename,
                )
            ]
        return []

    async def _run(self, analyzer: Analyzer, context: ReleaseContext) -> _Run:
        started = time.monotonic()
        try:
            loop = asyncio.get_running_loop()
            signals = await asyncio.wait_for(
                loop.run_in_executor(self._executor, analyzer.analyze, context),
                self._analyzer_timeout_s,
            )
        except Exception as e:
            ANALYZER_ERRORS.labels(analyzer.name).inc()
            log.warning("%s failed on %s", analyzer.name, context.name, exc_info=True)
            error = repr(e)
            return _Run(analyzer.name, analyzer.version, [], _elapsed_ms(started), error)
        return _Run(analyzer.name, analyzer.version, signals, _elapsed_ms(started))

    async def score(self, release_id: int) -> None:
        loaded = await self._load(release_id, ReleaseStatus.ANALYZED)
        if loaded is None:
            return
        release, package = loaded
        async with self._sessions.begin() as session:
            verdict = await self._auto_verdict(session, release_id)
            if verdict is None:
                signals = await self._signals(session, release_id)
                result = score_release(
                    signals, self._scoring, package.normalized_name, package.is_popular
                )
                verdict = Verdict(
                    release_id=release_id,
                    score=result.score,
                    level=result.level,
                    decided_by=DecidedBy.AUTO,
                )
                session.add(verdict)
                VERDICTS.labels(result.level.value).inc()
                if release.published_at is not None:
                    latency = datetime.now(UTC) - release.published_at
                    VERDICT_LATENCY.observe(latency.total_seconds())
            if verdict.level not in ALERT_LEVELS:
                await session.execute(
                    update(Release)
                    .where(Release.id == release_id)
                    .values(status=ReleaseStatus.CLEAN)
                )
        if verdict.level in ALERT_LEVELS:
            await self._queue.enqueue(Stage.ALERT, release_id)

    async def alert(self, release_id: int) -> None:
        loaded = await self._load(release_id, ReleaseStatus.ANALYZED)
        if loaded is None:
            return
        release, package = loaded
        async with self._sessions() as session:
            verdict = await self._auto_verdict(session, release_id)
            if verdict is None:
                raise ValueError(f"release {release_id} has no verdict to alert on")
            signals = await self._signals(session, release_id)
        top = score_release(
            signals, self._scoring, package.normalized_name, package.is_popular
        ).top_signals
        await self._notifier.send(
            Alert(package.name, release.version, verdict.score, verdict.level, top)
        )
        async with self._sessions.begin() as session:
            await session.execute(
                update(Release).where(Release.id == release_id).values(status=ReleaseStatus.ALERTED)
            )
        ALERTS.labels(verdict.level.value).inc()

    async def fail(self, release_id: int) -> None:
        async with self._sessions.begin() as session:
            await session.execute(
                update(Release).where(Release.id == release_id).values(status=ReleaseStatus.FAILED)
            )

    async def sweep(self, stale_after_s: float, limit: int = 1000) -> int:
        """Requeue releases left behind by a crash; the job id prevents double queueing."""
        threshold = datetime.now(UTC) - timedelta(seconds=stale_after_s)
        async with self._sessions() as session:
            rows = list(
                await session.execute(
                    select(Release.id, Release.status)
                    .where(Release.status.in_(RESUMABLE), Release.created_at < threshold)
                    .order_by(Release.id)
                    .limit(limit)
                )
            )
        for release_id, status in rows:
            await self._queue.enqueue(RESUMABLE[status], release_id)
        return len(rows)

    async def _load(self, release_id: int, status: ReleaseStatus) -> tuple[Release, Package] | None:
        async with self._sessions() as session:
            row = await session.execute(
                select(Release, Package)
                .join(Package, Package.id == Release.package_id)
                .where(Release.id == release_id, Release.status == status)
            )
            found = row.one_or_none()
            return None if found is None else (found[0], found[1])

    async def _auto_verdict(self, session: Any, release_id: int) -> Verdict | None:
        verdict: Verdict | None = await session.scalar(
            select(Verdict).where(
                Verdict.release_id == release_id, Verdict.decided_by == DecidedBy.AUTO
            )
        )
        return verdict

    async def _signals(self, session: Any, release_id: int) -> list[FoundSignal]:
        rows = await session.scalars(
            select(SignalRow)
            .join(AnalysisRun, AnalysisRun.id == SignalRow.run_id)
            .where(AnalysisRun.release_id == release_id)
        )
        return [
            FoundSignal(
                rule_id=row.rule_id,
                severity=row.severity,
                confidence=row.confidence,
                evidence=row.evidence,
                file_path=row.file_path,
                line=row.line,
            )
            for row in rows
        ]


def choose_files(files: list[dict[str, Any]], max_bytes: int) -> list[dict[str, Any]]:
    """Pick the sdist and one wheel: a release can have dozens of nearly identical wheels."""
    fitting = []
    for file in files:
        if file["size"] > max_bytes:
            ARTIFACTS_SKIPPED.labels("too_large").inc()
        else:
            fitting.append(file)
    sdists = [file for file in fitting if file["packagetype"] == "sdist"]
    wheels = [file for file in fitting if file["packagetype"] == "bdist_wheel"]
    wheels.sort(key=lambda file: (not file["filename"].endswith("-none-any.whl"), file["size"]))
    return sdists[:1] + wheels[:1]


def _artifact_type(file: dict[str, Any]) -> ArtifactType:
    return ArtifactType.SDIST if file["packagetype"] == "sdist" else ArtifactType.WHEEL


def _safe_filename(filename: str) -> str:
    if PurePosixPath(filename).name != filename or filename in ("", ".", ".."):
        raise ValueError(f"unsafe artifact filename: {filename!r}")
    return filename


def _roles(data: dict[str, Any]) -> list[dict[str, str]]:
    roles: list[dict[str, str]] = (data.get("ownership") or {}).get("roles", [])
    return roles


def _upload_time(file: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(file["upload_time_iso_8601"])


def _elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _strip_nul(value: Any) -> Any:
    """PostgreSQL rejects NUL in text and jsonb, and package data can contain anything."""
    if isinstance(value, str):
        return value.replace("\0", "")
    if isinstance(value, list):
        return [_strip_nul(item) for item in value]
    if isinstance(value, dict):
        return {_strip_nul(key): _strip_nul(item) for key, item in value.items()}
    return value


def _clean_text(value: str, limit: int) -> str:
    return value.encode("utf-8", "replace").decode("utf-8").replace("\0", "")[:limit]


def _signal_row(run_id: int, signal: FoundSignal) -> SignalRow:
    return SignalRow(
        run_id=run_id,
        rule_id=signal.rule_id,
        severity=signal.severity,
        confidence=signal.confidence,
        file_path=_clean_text(signal.file_path, MAX_PATH_LENGTH) if signal.file_path else None,
        line=signal.line,
        evidence=_clean_text(signal.evidence, MAX_EVIDENCE_LENGTH),
    )
