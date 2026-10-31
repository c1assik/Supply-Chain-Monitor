"""The whole path of a release, from the queue to the alert, against a real PostgreSQL."""

import hashlib
import io
import json
import multiprocessing
import tarfile
from collections.abc import AsyncIterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from pypi_monitor.alerts.telegram import Alert
from pypi_monitor.analyzers import Analyzer, ReleaseContext, Signal
from pypi_monitor.analyzers.guarddog import GuardDogAnalyzer
from pypi_monitor.analyzers.metadata import MetadataAnalyzer
from pypi_monitor.db.models import AnalysisRun, Artifact, Package, Release, Verdict
from pypi_monitor.db.models import Signal as SignalRow
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import ReleaseStatus, Severity
from pypi_monitor.ingest.store import record_release
from pypi_monitor.pipeline.queue import Stage
from pypi_monitor.pipeline.stages import Pipeline, choose_files
from pypi_monitor.pipeline.unpack import UnpackLimits
from pypi_monitor.pypi import NotReadyError, PyPIClient
from pypi_monitor.pypi.client import FILES_HOST
from pypi_monitor.scoring import load_scoring_config
from tests.conftest import FakeQueue, FakeStorage
from tests.test_guarddog_analyzer import MALICIOUS_SETUP

LIMITS = UnpackLimits(max_bytes=10_000_000, max_files=1000, max_ratio=1000)


def sdist(name: str, files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode()
            member = tarfile.TarInfo(f"{name}/{path}")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


@dataclass
class FakeIndex:
    """Serves a single release the way pypi.org does."""

    name: str
    version: str
    archive: bytes
    sha256: str = ""
    ready: bool = True
    files: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        filename = f"{self.name}-{self.version}.tar.gz"
        self.files = [
            {
                "filename": filename,
                "packagetype": "sdist",
                "size": len(self.archive),
                "url": f"https://{FILES_HOST}/packages/{filename}",
                "digests": {"sha256": self.sha256 or hashlib.sha256(self.archive).hexdigest()},
                "upload_time_iso_8601": (datetime.now(UTC) - timedelta(minutes=2)).isoformat(),
            }
        ]

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == FILES_HOST:
            return httpx.Response(200, content=self.archive)
        if request.url.path == "/pypi":
            body = (
                '<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
                "</data></array></value></param></params></methodResponse>"
            )
            return httpx.Response(200, text=body)
        if not self.ready:
            return httpx.Response(404)
        data = {
            "info": {"name": self.name, "version": self.version, "description": ""},
            "urls": self.files,
            "ownership": {"roles": [{"role": "Owner", "user": "mallory"}]},
            "last_serial": 555,
        }
        if request.url.path == f"/pypi/{self.name}/json":
            data["releases"] = {self.version: self.files}
        return httpx.Response(200, content=json.dumps(data))


class RecordingNotifier:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []
        self.failures = 0

    async def send(self, alert: Alert) -> None:
        if self.failures:
            self.failures -= 1
            raise httpx.ConnectError("telegram is down")
        self.alerts.append(alert)


class BrokenAnalyzer(Analyzer):
    name = "broken"
    version = "1"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        raise RuntimeError("boom")


@dataclass
class Harness:
    pipeline: Pipeline
    sessions: Sessions
    queue: FakeQueue
    notifier: RecordingNotifier
    storage: FakeStorage

    async def add(self, name: str, version: str) -> int:
        async with self.sessions.begin() as session:
            release_id = await record_release(session, name, version)
        assert release_id is not None
        return release_id

    async def run_queue(self) -> None:
        """Run jobs until the queue is empty, the way the worker would."""
        while self.queue.jobs:
            stage, release_id = self.queue.jobs.pop(0)
            await getattr(self.pipeline, stage.value)(release_id)

    async def status(self, release_id: int) -> ReleaseStatus:
        async with self.sessions() as session:
            release = await session.get(Release, release_id)
            assert release is not None
            return release.status

    async def verdict(self, release_id: int) -> Verdict:
        async with self.sessions() as session:
            verdict = await session.scalar(select(Verdict).where(Verdict.release_id == release_id))
            assert verdict is not None
            return verdict


def make_pipeline(
    index: FakeIndex,
    sessions: Sessions,
    queue: FakeQueue,
    storage: FakeStorage,
    analyzers: list[Analyzer] | None = None,
) -> tuple[Pipeline, PyPIClient, RecordingNotifier]:
    client = PyPIClient(httpx.MockTransport(index.handle))
    notifier = RecordingNotifier()
    pipeline = Pipeline(
        sessions=sessions,
        client=client,
        storage=storage,  # type: ignore[arg-type]
        queue=queue,
        notifier=notifier,
        scoring=load_scoring_config(Path("config/scoring.yaml")),
        analyzers=analyzers
        if analyzers is not None
        else [MetadataAnalyzer({"requests": 1}), GuardDogAnalyzer()],
        limits=LIMITS,
        max_artifact_bytes=5_000_000,
        analyzer_timeout_s=60,
    )
    return pipeline, client, notifier


@pytest.fixture
async def malicious(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> AsyncIterator[tuple[Harness, FakeIndex]]:
    index = FakeIndex("reqeusts", "1.0", sdist("reqeusts-1.0", {"setup.py": MALICIOUS_SETUP}))
    pipeline, client, notifier = make_pipeline(index, sessions, queue, storage)
    yield Harness(pipeline, sessions, queue, notifier, storage), index
    await client.aclose()


async def test_malicious_package_leads_to_an_alert(
    malicious: tuple[Harness, FakeIndex], storage: FakeStorage
) -> None:
    harness, index = malicious
    release_id = await harness.add("reqeusts", "1.0")
    harness.queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()

    assert await harness.status(release_id) is ReleaseStatus.ALERTED
    verdict = await harness.verdict(release_id)
    assert verdict.level is Severity.CRITICAL
    assert verdict.score >= 80

    assert storage.objects["reqeusts/1.0/reqeusts-1.0.tar.gz"] == index.archive

    async with harness.sessions() as session:
        release = await session.get(Release, release_id)
        artifact = await session.scalar(select(Artifact))
        runs = list(await session.scalars(select(AnalysisRun.analyzer)))
        rules = set(await session.scalars(select(SignalRow.rule_id)))
    assert release is not None
    assert release.maintainers == ["mallory"]
    assert release.serial == 555
    assert release.pypi_metadata["info"]["name"] == "reqeusts"
    assert artifact is not None
    assert artifact.sha256 == hashlib.sha256(index.archive).hexdigest()
    assert sorted(runs) == ["guarddog", "metadata", "unpack"]
    assert {"metadata.typosquat", "metadata.new_package"} <= rules
    assert any(rule.startswith("guarddog.install.threat-") for rule in rules)

    alert = harness.notifier.alerts[0]
    assert (alert.package, alert.version, alert.level) == ("reqeusts", "1.0", Severity.CRITICAL)
    assert len(alert.signals) == 3


async def test_clean_package_gets_a_verdict_and_no_alert(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> None:
    files = {"setup.py": "from setuptools import setup\nsetup(name='fine')", "fine.py": "x = 1"}
    index = FakeIndex("fine", "1.0", sdist("fine-1.0", files))
    pipeline, client, notifier = make_pipeline(index, sessions, queue, storage)
    harness = Harness(pipeline, sessions, queue, notifier, storage)
    release_id = await harness.add("fine", "1.0")
    queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()
    await client.aclose()

    assert await harness.status(release_id) is ReleaseStatus.CLEAN
    assert (await harness.verdict(release_id)).level in (Severity.LOW, Severity.MEDIUM)
    assert notifier.alerts == []


async def test_release_not_on_pypi_yet_stays_queued_for_a_retry(
    malicious: tuple[Harness, FakeIndex],
) -> None:
    harness, index = malicious
    index.ready = False
    release_id = await harness.add("reqeusts", "1.0")

    with pytest.raises(NotReadyError):
        await harness.pipeline.download(release_id)
    assert await harness.status(release_id) is ReleaseStatus.QUEUED

    index.ready = True
    await harness.pipeline.download(release_id)
    assert await harness.status(release_id) is ReleaseStatus.DOWNLOADED


async def test_hash_mismatch_never_reaches_the_storage(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> None:
    index = FakeIndex("evil", "1.0", b"tampered", sha256="0" * 64)
    pipeline, client, _ = make_pipeline(index, sessions, queue, storage)
    harness = Harness(pipeline, sessions, queue, RecordingNotifier(), storage)
    release_id = await harness.add("evil", "1.0")

    with pytest.raises(ValueError, match="sha256 mismatch"):
        await pipeline.download(release_id)
    await client.aclose()

    assert storage.objects == {}
    assert await harness.status(release_id) is ReleaseStatus.QUEUED


async def test_unsafe_archive_is_a_signal_and_the_rest_is_scanned(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> None:
    files = {"setup.py": MALICIOUS_SETUP, "../../escape.py": "x"}
    index = FakeIndex("trav", "1.0", sdist("trav", files))
    pipeline, client, notifier = make_pipeline(index, sessions, queue, storage)
    harness = Harness(pipeline, sessions, queue, notifier, storage)
    release_id = await harness.add("trav", "1.0")
    queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()
    await client.aclose()

    async with sessions() as session:
        rules = set(await session.scalars(select(SignalRow.rule_id)))
    assert "archive.path_traversal" in rules
    assert any(rule.startswith("guarddog.install.threat-") for rule in rules)


async def test_crashing_analyzer_is_recorded_and_does_not_stop_the_release(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> None:
    index = FakeIndex("fine", "1.0", sdist("fine-1.0", {"a.py": "x = 1"}))
    pipeline, client, notifier = make_pipeline(index, sessions, queue, storage, [BrokenAnalyzer()])
    harness = Harness(pipeline, sessions, queue, notifier, storage)
    release_id = await harness.add("fine", "1.0")
    queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()
    await client.aclose()

    assert await harness.status(release_id) is ReleaseStatus.CLEAN
    async with sessions() as session:
        run = await session.scalar(select(AnalysisRun).where(AnalysisRun.analyzer == "broken"))
    assert run is not None
    assert run.error is not None
    assert "boom" in run.error


async def test_evidence_with_nul_bytes_is_stored(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage
) -> None:
    class NulAnalyzer(Analyzer):
        name = "nul"
        version = "1"

        def analyze(self, release: ReleaseContext) -> list[Signal]:
            return [
                Signal(
                    rule_id="nul.rule",
                    severity=Severity.LOW,
                    confidence=1,
                    evidence="a\0b",
                    file_path="c\0d\udcff",
                )
            ]

    index = FakeIndex("fine", "1.0", sdist("fine-1.0", {"a.py": "x = 1"}))
    index.files[0]["comment_text"] = "with\0nul"
    pipeline, client, _ = make_pipeline(index, sessions, queue, storage, [NulAnalyzer()])
    harness = Harness(pipeline, sessions, queue, RecordingNotifier(), storage)
    release_id = await harness.add("fine", "1.0")
    queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()
    await client.aclose()

    assert await harness.status(release_id) is ReleaseStatus.CLEAN
    async with sessions() as session:
        assert await session.scalar(select(SignalRow.evidence)) == "ab"


async def test_failed_delivery_can_be_retried_without_a_second_verdict(
    malicious: tuple[Harness, FakeIndex],
) -> None:
    harness, _ = malicious
    harness.notifier.failures = 1
    release_id = await harness.add("reqeusts", "1.0")
    harness.queue.jobs.append((Stage.DOWNLOAD, release_id))

    with pytest.raises(httpx.ConnectError):
        await harness.run_queue()
    assert await harness.status(release_id) is ReleaseStatus.ANALYZED

    # The sweeper resumes the release from its status.
    await harness.pipeline.sweep(stale_after_s=-60)
    await harness.run_queue()

    assert await harness.status(release_id) is ReleaseStatus.ALERTED
    assert len(harness.notifier.alerts) == 1
    async with harness.sessions() as session:
        verdicts = list(await session.scalars(select(Verdict)))
    assert len(verdicts) == 1


async def test_stages_ignore_a_release_in_another_status(
    malicious: tuple[Harness, FakeIndex],
) -> None:
    harness, _ = malicious
    release_id = await harness.add("reqeusts", "1.0")
    harness.queue.jobs.append((Stage.DOWNLOAD, release_id))
    await harness.run_queue()

    await harness.pipeline.download(release_id)
    await harness.pipeline.analyze(release_id)
    await harness.pipeline.score(release_id)
    await harness.pipeline.alert(release_id)

    assert harness.queue.jobs == []
    assert len(harness.notifier.alerts) == 1


async def test_sweep_requeues_only_stale_unfinished_releases(
    malicious: tuple[Harness, FakeIndex],
) -> None:
    harness, _ = malicious
    fresh = await harness.add("fresh", "1.0")
    stale_queued = await harness.add("stale", "1.0")
    stale_downloaded = await harness.add("stale", "2.0")
    finished = await harness.add("stale", "3.0")
    old = datetime.now(UTC) - timedelta(hours=1)
    async with harness.sessions.begin() as session:
        await session.execute(update(Release).where(Release.id != fresh).values(created_at=old))
        for release_id, status in [
            (stale_downloaded, ReleaseStatus.DOWNLOADED),
            (finished, ReleaseStatus.CLEAN),
        ]:
            await session.execute(
                update(Release).where(Release.id == release_id).values(status=status)
            )

    assert await harness.pipeline.sweep(stale_after_s=900) == 2

    assert harness.queue.jobs == [
        (Stage.DOWNLOAD, stale_queued),
        (Stage.ANALYZE, stale_downloaded),
    ]


async def test_popular_package_gets_the_multiplier(malicious: tuple[Harness, FakeIndex]) -> None:
    harness, _ = malicious
    release_id = await harness.add("reqeusts", "1.0")
    async with harness.sessions.begin() as session:
        await session.execute(update(Package).values(is_popular=True))
    harness.queue.jobs.append((Stage.DOWNLOAD, release_id))

    await harness.run_queue()

    assert (await harness.verdict(release_id)).score == 100


async def test_real_analyzers_and_unsafe_archives_work_in_a_process_pool(
    sessions: Sessions, queue: FakeQueue, storage: FakeStorage, tmp_path: Path
) -> None:
    files = {"setup.py": MALICIOUS_SETUP, "../../escape.py": "x"}
    index = FakeIndex("reqeusts", "1.0", sdist("trav", files))
    pipeline, client, notifier = make_pipeline(index, sessions, queue, storage)
    harness = Harness(pipeline, sessions, queue, notifier, storage)
    release_id = await harness.add("reqeusts", "1.0")
    queue.jobs.append((Stage.DOWNLOAD, release_id))

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(1, mp_context=context) as executor:
        pipeline._executor = executor
        await harness.run_queue()
    await client.aclose()

    async with sessions() as session:
        rules = set(await session.scalars(select(SignalRow.rule_id)))
        errors = list(await session.scalars(select(AnalysisRun.error)))
    assert {"archive.path_traversal", "metadata.typosquat"} <= rules
    assert any(rule.startswith("guarddog.install.threat-") for rule in rules)
    assert errors == [None, None, None]


async def test_owner_lookups_stay_within_the_budget(
    malicious: tuple[Harness, FakeIndex],
) -> None:
    _, index = malicious
    client = PyPIClient(httpx.MockTransport(index.handle))

    assert await client.user_packages("alice") == []
    assert await client.user_packages("bob") is None
    await client.aclose()


def test_files_choice_prefers_sdist_and_a_pure_wheel() -> None:
    def file(name: str, packagetype: str, size: int = 10) -> dict[str, Any]:
        return {"filename": name, "packagetype": packagetype, "size": size}

    files = [
        file("a-1-cp312-cp312-linux_x86_64.whl", "bdist_wheel", 5),
        file("a-1-py3-none-any.whl", "bdist_wheel", 50),
        file("a-1.tar.gz", "sdist"),
        file("a-1.egg", "bdist_egg"),
    ]

    chosen = [f["filename"] for f in choose_files(files, 100)]
    assert chosen == ["a-1.tar.gz", "a-1-py3-none-any.whl"]

    assert choose_files([file("big.tar.gz", "sdist", 101)], 100) == []
