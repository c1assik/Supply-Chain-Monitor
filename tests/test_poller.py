from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from pypi_monitor.db.models import Package, Release
from pypi_monitor.db.session import Sessions
from pypi_monitor.ingest.poller import PACKAGES_FEED, UPDATES_FEED, Poller
from pypi_monitor.pipeline.queue import Stage
from pypi_monitor.pypi import ChangelogEvent, FeedEntry, NotReadyError, PyPIClient
from tests.conftest import FakeQueue

NOW = datetime(2026, 10, 31, tzinfo=UTC)


class FakePyPI(PyPIClient):
    def __init__(self) -> None:
        super().__init__()
        self.feeds: dict[str, list[FeedEntry]] = {UPDATES_FEED: [], PACKAGES_FEED: []}
        self.serial = 100
        self.events: list[ChangelogEvent] = []
        self.projects: dict[str, str] = {}

    async def fetch_feed(self, path: str) -> list[FeedEntry]:
        return self.feeds[path]

    async def last_serial(self) -> int:
        return self.serial

    async def changelog_since(self, serial: int) -> list[ChangelogEvent]:
        return [event for event in self.events if event.serial > serial]

    async def project(self, name: str) -> dict[str, object]:
        if name not in self.projects:
            raise NotReadyError(name)
        return {"info": {"version": self.projects[name]}}


def event(name: str, version: str, serial: int, action: str = "new release") -> ChangelogEvent:
    return ChangelogEvent(name, version, NOW, action, serial)


@pytest.fixture
def pypi() -> FakePyPI:
    return FakePyPI()


@pytest.fixture
def poller(pypi: FakePyPI, sessions: Sessions, queue: FakeQueue) -> Poller:
    return Poller(pypi, sessions, queue, settle_s=0)


async def count_releases(sessions: Sessions) -> int:
    async with sessions() as session:
        return await session.scalar(select(func.count()).select_from(Release)) or 0


async def test_repeated_polls_do_not_duplicate_releases(
    poller: Poller, pypi: FakePyPI, sessions: Sessions, queue: FakeQueue
) -> None:
    pypi.feeds[UPDATES_FEED] = [FeedEntry("Foo_Bar", "1.0", NOW), FeedEntry("foo-bar", "1.1", NOW)]

    assert await poller.poll_feeds() == 2
    assert await poller.poll_feeds() == 0

    assert await count_releases(sessions) == 2
    assert [stage for stage, _ in queue.jobs] == [Stage.DOWNLOAD, Stage.DOWNLOAD]
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(Package)) == 1


async def test_popular_packages_go_to_the_priority_queue(
    poller: Poller, pypi: FakePyPI, sessions: Sessions, queue: FakeQueue
) -> None:
    async with sessions.begin() as session:
        session.add(Package(name="top", normalized_name="top", is_popular=True))
    pypi.feeds[UPDATES_FEED] = [FeedEntry("top", "1.0", NOW), FeedEntry("rare", "1.0", NOW)]

    await poller.poll_feeds()

    assert len(queue.jobs) == 2
    assert len(queue.priority) == 1


async def test_packages_feed_resolves_the_version(
    poller: Poller, pypi: FakePyPI, sessions: Sessions
) -> None:
    pypi.feeds[PACKAGES_FEED] = [
        FeedEntry("brand-new", None, NOW),
        FeedEntry("no-files", None, NOW),
    ]
    pypi.projects["brand-new"] = "0.1"

    assert await poller.poll_feeds() == 1
    assert await count_releases(sessions) == 1


async def test_first_catch_up_only_remembers_the_position(
    poller: Poller, pypi: FakePyPI, sessions: Sessions
) -> None:
    pypi.events = [event("old", "1.0", 50)]

    assert await poller.catch_up() == 0
    assert await count_releases(sessions) == 0


async def test_catch_up_fills_a_gap_after_downtime(
    poller: Poller, pypi: FakePyPI, sessions: Sessions, queue: FakeQueue
) -> None:
    await poller.catch_up()
    pypi.feeds[UPDATES_FEED] = [FeedEntry("seen", "1.0", NOW)]
    await poller.poll_feeds()

    # Released while the service was down, and gone from RSS by now.
    pypi.events = [
        event("seen", "1.0", 101),
        event("missed", "1.0", 102),
        event("missed", "1.0", 103, "add py3 file missed-1.0-py3-none-any.whl"),
        event("other", "2.0", 104),
    ]

    assert await poller.catch_up() == 2
    assert await count_releases(sessions) == 3
    assert len(queue.jobs) == 3

    assert await poller.catch_up() == 0
