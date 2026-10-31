from datetime import UTC, datetime

from pypi_monitor.pypi.feeds import parse_changelog, parse_feed

UPDATES = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>PyPI recent updates</title>
<item><title>foo 1.0.3</title><link>https://pypi.org/project/foo/1.0.3/</link>
<pubDate>Sat, 31 Oct 2026 08:08:30 GMT</pubDate></item>
<item><title>bar 2.0rc1</title><link>https://pypi.org/project/bar/2.0rc1/</link></item>
</channel></rss>"""

PACKAGES = b"""<rss version="2.0"><channel>
<item><title>foo added to PyPI</title><link>https://pypi.org/project/foo/</link>
<pubDate>Sat, 31 Oct 2026 08:06:24 GMT</pubDate></item>
<item><title>odd</title><link>https://pypi.org/help/</link></item>
</channel></rss>"""


def test_updates_feed_gives_name_and_version() -> None:
    first, second = parse_feed(UPDATES)

    assert (first.name, first.version) == ("foo", "1.0.3")
    assert first.published_at == datetime(2026, 10, 31, 8, 8, 30, tzinfo=UTC)
    assert (second.name, second.version, second.published_at) == ("bar", "2.0rc1", None)


def test_packages_feed_has_no_version_and_foreign_links_are_ignored() -> None:
    entries = parse_feed(PACKAGES)

    assert [(entry.name, entry.version) for entry in entries] == [("foo", None)]


def test_changelog_rows_become_events() -> None:
    rows: list[list[object]] = [
        ["foo", "1.0", 1793426968, "new release", 7],
        ["foo", None, 1, "create", 8],
    ]

    events = parse_changelog(rows)

    assert events[0].action == "new release"
    assert events[0].serial == 7
    assert events[1].version is None
