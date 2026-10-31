"""Keeps the database in step with PyPI: RSS gives low latency, the changelog gives completeness."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable

from packaging.utils import canonicalize_name
from sqlalchemy import exists, select
from sqlalchemy.dialects.postgresql import insert

from pypi_monitor.db.models import IngestCursor, Package, Release
from pypi_monitor.db.session import Sessions
from pypi_monitor.ingest.store import record_release
from pypi_monitor.metrics import FEED_ERRORS, FEED_LAST_SUCCESS, RELEASES_INGESTED
from pypi_monitor.pipeline.queue import ReleaseQueue, Stage
from pypi_monitor.pypi import NotReadyError, PyPIClient
from pypi_monitor.pypi.feeds import NEW_RELEASE_ACTION, FeedEntry

log = logging.getLogger(__name__)

UPDATES_FEED = "/rss/updates.xml"
PACKAGES_FEED = "/rss/packages.xml"
CHANGELOG_CURSOR = "changelog"


class Poller:
    def __init__(
        self, client: PyPIClient, sessions: Sessions, queue: ReleaseQueue, settle_s: float
    ) -> None:
        self._client = client
        self._sessions = sessions
        self._queue = queue
        self._settle_s = settle_s

    async def poll_feeds(self) -> int:
        """Record what the RSS feeds show right now and return the number of new releases."""
        entries = await self._client.fetch_feed(UPDATES_FEED)
        entries += await self._resolve_new_packages(await self._client.fetch_feed(PACKAGES_FEED))
        new_ids = []
        async with self._sessions.begin() as session:
            for entry in entries:
                assert entry.version is not None  # noqa: S101
                release_id = await record_release(
                    session, entry.name, entry.version, entry.published_at
                )
                if release_id is not None:
                    new_ids.append(release_id)
        await self._publish(new_ids, "rss")
        return len(new_ids)

    async def _resolve_new_packages(self, entries: list[FeedEntry]) -> list[FeedEntry]:
        """`packages.xml` has no versions; ask for them, but only for packages not seen yet."""
        names = {canonicalize_name(entry.name): entry for entry in entries}
        async with self._sessions() as session:
            known = await session.scalars(
                select(Package.normalized_name).where(
                    Package.normalized_name.in_(names),
                    exists().where(Release.package_id == Package.id),
                )
            )
            unknown = names.keys() - set(known)
        resolved = []
        for name in unknown:
            entry = names[name]
            try:
                info = (await self._client.project(entry.name))["info"]
            except NotReadyError:
                continue  # A project without files yet; it stays in the feed for a while.
            resolved.append(FeedEntry(entry.name, info["version"], entry.published_at))
        return resolved

    async def catch_up(self) -> int:
        """Record every release since the saved serial and return the number of new ones."""
        async with self._sessions.begin() as session:
            cursor = await session.get(IngestCursor, CHANGELOG_CURSOR)
            if cursor is None:
                await session.execute(
                    insert(IngestCursor)
                    .values(name=CHANGELOG_CURSOR, serial=await self._client.last_serial())
                    .on_conflict_do_nothing()
                )
                return 0
            serial = cursor.serial

        total = 0
        # Each answer is capped by PyPI, so keep asking until there is nothing left.
        while events := await self._client.changelog_since(serial):
            serial = max(event.serial for event in events)
            new_ids = []
            async with self._sessions.begin() as session:
                for event in events:
                    if event.action != NEW_RELEASE_ACTION or event.version is None:
                        continue
                    release_id = await record_release(
                        session, event.name, event.version, event.timestamp, event.serial
                    )
                    if release_id is not None:
                        new_ids.append(release_id)
                await session.merge(IngestCursor(name=CHANGELOG_CURSOR, serial=serial))
            await self._publish(new_ids, "changelog")
            total += len(new_ids)
        return total

    async def _publish(self, release_ids: list[int], source: str) -> None:
        RELEASES_INGESTED.labels(source).inc(len(release_ids))
        for release_id in release_ids:
            await self._queue.enqueue(Stage.DOWNLOAD, release_id, self._settle_s)

    async def run(self, feed_interval_s: float, catchup_interval_s: float) -> None:
        next_feed = next_catchup = 0.0
        while True:
            now = time.monotonic()
            # The changelog goes first after a restart: it closes the gap left by the downtime.
            if now >= next_catchup:
                next_catchup = now + catchup_interval_s
                await self._guarded("changelog", self.catch_up)
            if now >= next_feed:
                next_feed = now + feed_interval_s
                await self._guarded("rss", self.poll_feeds)
            await asyncio.sleep(max(0, min(next_feed, next_catchup) - time.monotonic()))

    async def _guarded(self, source: str, poll: Callable[[], Awaitable[int]]) -> None:
        try:
            new = await poll()
        except Exception:
            FEED_ERRORS.labels(source).inc()
            log.exception("polling %s failed", source)
        else:
            FEED_LAST_SUCCESS.labels(source).set_to_current_time()
            if new:
                log.info("%s: %d new releases", source, new)
