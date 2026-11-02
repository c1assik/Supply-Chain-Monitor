"""The dashboard shows what attackers wrote, so most of this is about staying a page of text."""

import io
import tarfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from pypi_monitor.db.models import AnalysisRun, Artifact, Package, Release, Signal, Verdict
from pypi_monitor.db.session import Sessions
from pypi_monitor.domain import (
    ArtifactType,
    DecidedBy,
    Label,
    ReleaseStatus,
    Severity,
)
from pypi_monitor.pipeline.unpack import UnpackLimits
from pypi_monitor.web.app import create_app
from pypi_monitor.web.diff import (
    MAX_FILE_BYTES,
    FileStatus,
    diff_directories,
)
from tests.conftest import FakeStorage

LIMITS = UnpackLimits(10_000_000, 1000, 1000)
XSS = "<script>alert(1)</script>"
BASE_URL = "http://localhost"
HTMX = {"HX-Request": "true"}


def write_sdist(root: Path, stem: str, files: dict[str, str]) -> None:
    for path, content in files.items():
        target = root / f"{stem}.tar.gz" / stem / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def test_diff_shows_changes_and_puts_autorun_files_first(tmp_path: Path) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    write_sdist(old, "p-1", {"p/util.py": "a = 1\n", "p/__init__.py": "X = 1\n", "same.py": "s\n"})
    write_sdist(
        new,
        "p-2",
        {
            "p/util.py": "a = 2\n",
            "p/__init__.py": "exec(x)\nX = 1\n",
            "same.py": "s\n",
            "n.py": "n\n",
        },
    )

    files = diff_directories(old, new).files

    assert files[0].path == "p/__init__.py"
    assert files[0].autorun
    assert "+exec(x)" in files[0].lines
    assert {f.path: f.status for f in files} == {
        "p/__init__.py": FileStatus.CHANGED,
        "p/util.py": FileStatus.CHANGED,
        "n.py": FileStatus.ADDED,
    }


def test_new_package_shows_all_its_files(tmp_path: Path) -> None:
    (tmp_path / "old").mkdir()
    write_sdist(tmp_path / "new", "p-1", {"setup.py": "evil()\n"})

    found = diff_directories(tmp_path / "old", tmp_path / "new")

    assert [f.status for f in found.files] == [FileStatus.ADDED]
    assert "+evil()" in found.files[0].lines


@pytest.mark.parametrize(
    ("content", "note"),
    [
        (b"\0\1\2", "бинарный"),
        (b"x" * (MAX_FILE_BYTES + 1), "большой"),
        (b"x" * 5000, "длинные"),
    ],
)
def test_unreadable_files_are_listed_without_content(
    tmp_path: Path, content: bytes, note: str
) -> None:
    (tmp_path / "old").mkdir()
    target = tmp_path / "new/p-1.tar.gz/p-1/blob.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)

    found = diff_directories(tmp_path / "old", tmp_path / "new").files[0]

    assert found.lines == []
    assert note in (found.note or "")


def sdist_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.fixture
async def client(sessions: Sessions, storage: FakeStorage) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(sessions, storage, LIMITS, ["localhost"])  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as http:
        yield http


async def add_release(
    sessions: Sessions,
    storage: FakeStorage,
    name: str = "evil",
    level: Severity = Severity.CRITICAL,
) -> int:
    async with sessions.begin() as session:
        package = Package(name=name, normalized_name=name)
        session.add(package)
        await session.flush()
        old = Release(package_id=package.id, version="1.0", status=ReleaseStatus.BASELINE)
        session.add(old)
        await session.flush()
        new = Release(
            package_id=package.id,
            version="1.1",
            status=ReleaseStatus.ALERTED,
            prev_release_id=old.id,
            maintainers=["mallory"],
        )
        session.add(new)
        await session.flush()
        run = AnalysisRun(release_id=new.id, analyzer="diff", analyzer_version="1", error=None)
        session.add(run)
        await session.flush()
        session.add(
            Signal(
                run_id=run.id,
                rule_id="diff.install.new_dangerous_call",
                severity=Severity.HIGH,
                confidence=0.8,
                file_path=f"evil/{XSS}.py",
                line=3,
                evidence=XSS,
            )
        )
        session.add(Verdict(release_id=new.id, score=90, level=level, decided_by=DecidedBy.AUTO))
        for release, version, files in (
            (old, "1.0", {"evil-1.0/evil/__init__.py": "X = 1\n"}),
            (new, "1.1", {"evil-1.1/evil/__init__.py": f"exec('{XSS}')\nX = 1\n"}),
        ):
            key = f"{name}/{version}/{name}-{version}.tar.gz"
            storage.objects[key] = sdist_bytes(files)
            session.add(
                Artifact(
                    release_id=release.id,
                    filename=f"{name}-{version}.tar.gz",
                    type=ArtifactType.SDIST,
                    sha256="a" * 64,
                    size=1,
                    storage_key=key,
                )
            )
        release_id: int = new.id
    return release_id


async def labels(sessions: Sessions) -> list[Any]:
    async with sessions() as session:
        return list(
            await session.scalars(select(Verdict).where(Verdict.decided_by == DecidedBy.HUMAN))
        )


async def test_feed_shows_alerts_and_hides_medium_by_default(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    await add_release(sessions, storage, "alerted")
    await add_release(sessions, storage, "quiet", Severity.MEDIUM)

    page = (await client.get("/")).text
    wider = (await client.get("/", params={"level": "medium"})).text

    assert "alerted" in page
    assert "quiet" not in page
    assert "quiet" in wider


async def test_low_level_is_never_in_the_feed(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    await add_release(sessions, storage, "silent", Severity.LOW)
    assert "silent" not in (await client.get("/", params={"level": "medium"})).text


async def test_search_treats_wildcards_as_text(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    await add_release(sessions, storage, "some-evil")

    assert "some-evil" in (await client.get("/", params={"q": "EVIL"})).text
    assert "some-evil" not in (await client.get("/", params={"q": "%"})).text


async def test_htmx_gets_a_fragment(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    await add_release(sessions, storage)

    response = await client.get("/", headers=HTMX)

    assert "<html" not in response.text
    assert "<table" in response.text
    assert "HX-Request" in response.headers["Vary"]


@pytest.mark.parametrize("path", ["/releases/{id}", "/releases/{id}/diff", "/releases/{id}/report"])
async def test_package_content_is_escaped(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage, path: str
) -> None:
    release_id = await add_release(sessions, storage)

    response = await client.get(path.format(id=release_id))

    assert response.status_code == 200
    assert XSS not in response.text
    assert "&lt;script&gt;" in response.text


async def test_diff_page_shows_the_injected_line(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)

    page = (await client.get(f"/releases/{release_id}/diff")).text

    assert "1.0" in page
    assert "+exec(&#39;&lt;script&gt;" in page


async def test_label_is_kept_next_to_the_automatic_verdict(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)

    response = await client.post(
        f"/releases/{release_id}/label",
        data={"label": "malicious", "comment": "steals tokens"},
        headers=HTMX,
    )

    assert response.status_code == 200
    assert "steals tokens" in response.text
    stored = await labels(sessions)
    assert [(v.label, v.score, v.comment) for v in stored] == [
        (Label.MALICIOUS, 90, "steals tokens")
    ]


async def test_latest_label_wins_in_the_feed(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)
    url = f"/releases/{release_id}/label"
    await client.post(url, data={"label": "malicious"}, headers=HTMX)
    await client.post(url, data={"label": "benign"}, headers=HTMX)

    assert "evil" not in (await client.get("/", params={"label": "malicious"})).text
    assert "evil" in (await client.get("/", params={"label": "benign"})).text
    assert "evil" not in (await client.get("/")).text


async def test_cross_site_form_cannot_label(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)

    response = await client.post(f"/releases/{release_id}/label", data={"label": "benign"})

    assert response.status_code == 403
    assert await labels(sessions) == []


async def test_unknown_label_is_rejected(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)

    response = await client.post(
        f"/releases/{release_id}/label", data={"label": "whatever"}, headers=HTMX
    )

    assert response.status_code == 422
    assert await labels(sessions) == []


async def test_foreign_host_is_refused(client: httpx.AsyncClient) -> None:
    response = await client.get("/", headers={"Host": "attacker.example"})
    assert response.status_code == 400


async def test_policy_forbids_inline_code(client: httpx.AsyncClient) -> None:
    response = await client.get("/")
    policy = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy
    assert "<script>" not in response.text


async def test_unknown_release_is_404(client: httpx.AsyncClient) -> None:
    assert (await client.get("/releases/999")).status_code == 404


async def test_report_has_what_pypi_needs(
    client: httpx.AsyncClient, sessions: Sessions, storage: FakeStorage
) -> None:
    release_id = await add_release(sessions, storage)
    url = f"/releases/{release_id}/report"
    assert "не размечен" in (await client.get(url)).text

    await client.post(
        f"/releases/{release_id}/label",
        data={"label": "malicious", "comment": "steals tokens"},
        headers=HTMX,
    )
    page = (await client.get(url)).text

    assert "не размечен" not in page
    assert "https://pypi.org/project/evil/1.1/" in page
    assert "a" * 64 in page
    assert "steals tokens" in page
    assert "diff.install.new_dangerous_call" in page
