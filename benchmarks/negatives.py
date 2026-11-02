"""Build the frozen list of negatives: random recent releases plus the most popular packages.

The list is committed, so every run scores the same releases. Rebuild it only on purpose: metrics
of different lists do not compare. Releases that PyPI has since removed drop out by themselves, and
that is the point: some of them were malware.

    python -m benchmarks.negatives
"""

import asyncio
import json
import logging
import random
import sys
from datetime import timedelta
from typing import Any

from packaging.utils import canonicalize_name

from benchmarks.corpus import DATA_DIR, NEGATIVES_FILE, TOP_PACKAGES_FILE, fetch_dataset, positives
from pypi_monitor.pipeline.stages import choose_files
from pypi_monitor.pypi import NotReadyError, PyPIClient
from pypi_monitor.pypi.feeds import NEW_RELEASE_ACTION
from pypi_monitor.settings import Settings

log = logging.getLogger(__name__)

RANDOM_COUNT = 2000
POPULAR_COUNT = 500
TOP_COUNT = 5000
PERIOD = timedelta(days=30)
# Spots of the changelog to read: a call returns about a day of events, thousands of releases.
WINDOWS = 10
RATE_PROBE_SERIALS = 300_000
SEED = 20261101
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
CONCURRENCY = 8


async def _recent_releases(client: PyPIClient) -> list[tuple[str, str]]:
    last = await client.last_serial()
    # The changelog has no lookup by date, so a month is estimated from the rate of one window.
    sample = await client.changelog_since(last - RATE_PROBE_SERIALS)
    elapsed = sample[-1].timestamp - sample[0].timestamp
    first = last - round((sample[-1].serial - sample[0].serial) * (PERIOD / elapsed))
    step = (last - first) // WINDOWS
    found: set[tuple[str, str]] = set()
    for index in range(WINDOWS):
        events = await client.changelog_since(first + index * step)
        found.update(
            (event.name, event.version)
            for event in events
            if event.version and event.action.startswith(NEW_RELEASE_ACTION)
        )
    return sorted(found)


async def _entry(
    client: PyPIClient, name: str, version: str | None, group: str, gate: asyncio.Semaphore
) -> dict[str, Any] | None:
    async with gate:
        try:
            if version is None:
                version = (await client.project(name))["info"]["version"]
            data = await client.release(name, version or "")
        except NotReadyError:
            return None
    # Malware in the dataset is mostly an sdist, so that is what ordinary releases are judged on.
    files = choose_files(data.get("urls", []), MAX_ARTIFACT_BYTES)
    if not files:
        return None
    file = files[0]
    return {
        "name": name,
        "version": version,
        "group": group,
        "filename": file["filename"],
        "url": file["url"],
        "sha256": file["digests"]["sha256"],
    }


async def build() -> None:
    known_malware = {canonicalize_name(s.name) for s in positives(DATA_DIR)}
    gate = asyncio.Semaphore(CONCURRENCY)
    client = PyPIClient()
    try:
        url = Settings.model_fields["top_packages_url"].default
        top = (await client.top_packages(url))[:TOP_COUNT]
        TOP_PACKAGES_FILE.write_text(json.dumps(top, indent=0) + "\n", encoding="utf-8")
        popular_names = [n for n in top if canonicalize_name(n) not in known_malware]
        popular = await asyncio.gather(
            *(_entry(client, n, None, "popular", gate) for n in popular_names[:POPULAR_COUNT])
        )

        top_names = {canonicalize_name(name) for name in top}
        releases = [
            release
            for release in await _recent_releases(client)
            if canonicalize_name(release[0]) not in known_malware | top_names
        ]
        log.info("%d recent releases", len(releases))
        random.Random(SEED).shuffle(releases)  # noqa: S311
        # One release per package: a package that publishes daily is not a hundred samples.
        chosen: dict[str, tuple[str, str]] = {}
        for name, version in releases:
            chosen.setdefault(canonicalize_name(name), (name, version))
        # A margin for releases that are gone or have no files.
        candidates = list(chosen.values())[: RANDOM_COUNT * 5 // 4]
        ordinary = await asyncio.gather(
            *(_entry(client, n, v, "random", gate) for n, v in candidates)
        )
    finally:
        await client.aclose()

    entries = [e for e in popular if e] + [e for e in ordinary if e][:RANDOM_COUNT]
    NEGATIVES_FILE.write_text(json.dumps(entries, indent=1) + "\n", encoding="utf-8")
    log.info("%d negatives written", len(entries))


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    fetch_dataset(DATA_DIR)
    asyncio.run(build())
    return 0


if __name__ == "__main__":
    sys.exit(main())
