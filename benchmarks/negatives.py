"""Build the frozen list of negatives: random recent releases plus the most popular packages.

The list is committed, so every run scores the same releases. Rebuild it only on purpose: metrics
of different lists do not compare. Releases that PyPI has since removed drop out by themselves, and
that is the point: some of them were malware.

    python -m benchmarks.negatives            # a new list
    python -m benchmarks.negatives --extend   # keep the list, add random releases up to the count

A false alert in the stream costs `RELEASES_PER_DAY / random negatives` alerts a day in the
estimate. With 2000 random releases in the list one release was 22 alerts a day on test, and the
threshold had to keep a wide margin from that noise; 20000 bring it down to about 2.
"""

import argparse
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

RANDOM_COUNT = 20000
POPULAR_COUNT = 500
TOP_COUNT = 5000
PERIOD = timedelta(days=30)
# Spots of the changelog to read: a call returns about a day of events, thousands of releases.
# One per day of the period: 20000 packages with one release each need most of a month.
WINDOWS = 30
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


async def build(extend: bool) -> None:
    known_malware = {canonicalize_name(s.name) for s in positives(DATA_DIR)}
    gate = asyncio.Semaphore(CONCURRENCY)
    client = PyPIClient()
    kept: list[dict[str, Any]] = []
    if extend:
        kept = json.loads(NEGATIVES_FILE.read_text(encoding="utf-8"))
    try:
        if extend:
            top = json.loads(TOP_PACKAGES_FILE.read_text(encoding="utf-8"))
            popular: list[dict[str, Any] | None] = []
        else:
            url = Settings.model_fields["top_packages_url"].default
            top = (await client.top_packages(url))[:TOP_COUNT]
            TOP_PACKAGES_FILE.write_text(json.dumps(top, indent=0) + "\n", encoding="utf-8")
            popular_names = [n for n in top if canonicalize_name(n) not in known_malware]
            popular = await asyncio.gather(
                *(_entry(client, n, None, "popular", gate) for n in popular_names[:POPULAR_COUNT])
            )

        listed = {canonicalize_name(entry["name"]) for entry in kept}
        excluded = known_malware | {canonicalize_name(name) for name in top} | listed
        releases = [
            release
            for release in await _recent_releases(client)
            if canonicalize_name(release[0]) not in excluded
        ]
        log.info("%d recent releases", len(releases))
        random.Random(SEED).shuffle(releases)  # noqa: S311
        # One release per package: a package that publishes daily is not a hundred samples.
        chosen: dict[str, tuple[str, str]] = {}
        for name, version in releases:
            chosen.setdefault(canonicalize_name(name), (name, version))
        wanted = RANDOM_COUNT - sum(entry["group"] == "random" for entry in kept)
        # A margin for releases that are gone or have no files.
        candidates = list(chosen.values())[: wanted * 5 // 4]
        if len(candidates) < wanted:
            log.warning("only %d candidates for %d releases", len(candidates), wanted)
        ordinary = await asyncio.gather(
            *(_entry(client, n, v, "random", gate) for n, v in candidates)
        )
    finally:
        await client.aclose()

    entries = kept + [e for e in popular if e] + [e for e in ordinary if e][:wanted]
    write_negatives(entries)
    log.info("%d negatives written", len(entries))


def write_negatives(entries: list[dict[str, Any]]) -> None:
    """One release a line: the list is long, and a diff of it should stay readable."""
    lines = ",\n".join(json.dumps(entry, ensure_ascii=True) for entry in entries)
    NEGATIVES_FILE.write_text(f"[\n{lines}\n]\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.negatives")
    parser.add_argument("--extend", action="store_true", help="keep the list and add to it")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    fetch_dataset(DATA_DIR)
    asyncio.run(build(arguments.extend))
    return 0


if __name__ == "__main__":
    sys.exit(main())
