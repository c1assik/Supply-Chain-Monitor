"""Parsing of the PyPI RSS feeds and the XML-RPC changelog."""

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlparse

import defusedxml.ElementTree as ElementTree

NEW_RELEASE_ACTION = "new release"


@dataclass(frozen=True)
class FeedEntry:
    """One RSS item. `packages.xml` does not name a version, so `version` may be None."""

    name: str
    version: str | None
    published_at: datetime | None


@dataclass(frozen=True)
class ChangelogEvent:
    name: str
    version: str | None
    timestamp: datetime
    action: str
    serial: int


def parse_feed(document: bytes) -> list[FeedEntry]:
    entries = []
    for item in ElementTree.fromstring(document).iter("item"):
        # Item links look like https://pypi.org/project/<name>/[<version>/].
        parts = urlparse(item.findtext("link", "")).path.strip("/").split("/")
        if len(parts) not in (2, 3) or parts[0] != "project":
            continue
        version = unquote(parts[2]) if len(parts) == 3 else None
        entries.append(FeedEntry(unquote(parts[1]), version, _parse_date(item.findtext("pubDate"))))
    return entries


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except ValueError:
        return None


def parse_changelog(rows: list[list[object]]) -> list[ChangelogEvent]:
    events = []
    for name, version, timestamp, action, serial in rows:
        assert isinstance(timestamp, int)  # noqa: S101
        assert isinstance(serial, int)  # noqa: S101
        events.append(
            ChangelogEvent(
                name=str(name),
                version=str(version) if version else None,
                timestamp=datetime.fromtimestamp(timestamp, UTC),
                action=str(action),
                serial=serial,
            )
        )
    return events
