"""The version diff on real releases: compromised libraries against ordinary updates.

`benchmarks.diff_pairs` injects synthetic payloads into small packages. Here the new side is a real
attack or a real update, and the old side is the previous version from PyPI, chosen by the same
rule as in production. Signals join those of `benchmarks.malware scan`, which must be done first.

The baseline is what PyPI serves today. Versions of an attack that are gone cannot be a baseline,
while on the day of the attack an infected version could be: its successor would then show no diff
at all. Such samples are counted apart as `follow-ups`.

    python -m benchmarks.real_diff scan
    python -m benchmarks.real_diff report
"""

import argparse
import asyncio
import dataclasses
import json
import logging
import multiprocessing
import sys
import tempfile
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from benchmarks.corpus import (
    DATA_DIR,
    Group,
    Sample,
    default_limit,
    negatives,
    positives,
    top_packages,
)
from benchmarks.malware import (
    MAX_ARTIFACT_BYTES,
    Result,
    Scored,
    compute_metrics,
    download_negatives,
    latest_results,
    load_results,
    prepare_sample,
    score_results,
)
from pypi_monitor.analyzers.base import ReleaseContext, Signal
from pypi_monitor.analyzers.diff import DiffAnalyzer
from pypi_monitor.pipeline.stages import choose_files
from pypi_monitor.pipeline.unpack import (
    UnpackLimits,
    UnsafeArchiveError,
    UnsupportedArchiveError,
    unpack,
)
from pypi_monitor.pypi import NotReadyError, PyPIClient
from pypi_monitor.pypi.versions import choose_previous
from pypi_monitor.scoring import load_scoring_config

log = logging.getLogger(__name__)

CONCURRENCY = 8
# Results of another diff version must not pass for these: the version is in the name.
RESULTS_FILE = f"real_diff.v{DiffAnalyzer.version}.jsonl"
# Ordinary updates per group: the negatives of the quality benchmark are ten times more, and the
# diff needs a baseline downloaded for each of them.
NEGATIVES_PER_GROUP = 2000
TOP_RULES = 10


@dataclass(frozen=True)
class Baseline:
    sample: Sample
    version: str
    # Relative to the data directory.
    paths: list[str]


async def _baseline(
    client: PyPIClient, sample: Sample, data_dir: Path, gate: asyncio.Semaphore
) -> Baseline | None:
    async with gate:
        try:
            choice = choose_previous(sample.version, await client.simple(sample.name))
        except NotReadyError:
            return None
        if choice is None:
            return None
        version, files = choice
        paths = []
        for file in choose_files(files, MAX_ARTIFACT_BYTES):
            relative = f"previous/{canonicalize_name(sample.name)}/{file['filename']}"
            target = data_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                # Versions of one package share a baseline and may fetch it at the same time.
                partial = target.with_name(f"{target.name}.{uuid.uuid4().hex}.part")
                digest = await client.download(file["url"], partial, MAX_ARTIFACT_BYTES)
                if digest != file["digests"]["sha256"]:
                    partial.unlink()
                    raise ValueError(f"sha256 mismatch for {file['filename']}")
                partial.replace(target)
            paths.append(relative)
    return Baseline(sample, version, paths)


async def _baselines(samples: Sequence[Sample], data_dir: Path) -> list[Baseline]:
    gate = asyncio.Semaphore(CONCURRENCY)
    client = PyPIClient()
    try:
        found = await asyncio.gather(
            *(_baseline(client, sample, data_dir, gate) for sample in samples),
            return_exceptions=True,
        )
    finally:
        await client.aclose()
    baselines = []
    for sample, result in zip(samples, found, strict=True):
        if isinstance(result, BaseException):
            log.warning("no baseline of %s: %r", sample.id, result)
        elif result is not None:
            baselines.append(result)
    return baselines


def diff_sample(baseline: Baseline, data_dir: Path) -> dict[str, Any]:
    """Run the real analyzer on a release and its baseline. Runs in a worker process."""
    sample = baseline.sample
    limits = UnpackLimits(
        default_limit("max_unpacked_bytes"),
        default_limit("max_unpacked_files"),
        default_limit("max_compression_ratio"),
    )
    temporary = data_dir / "tmp"
    temporary.mkdir(exist_ok=True)
    row: dict[str, Any] = {
        "id": sample.id,
        "previous": baseline.version,
        "signals": [],
        "error": None,
    }
    with tempfile.TemporaryDirectory(dir=temporary) as directory:
        root = Path(directory)
        try:
            artifact_dir, _ = prepare_sample(sample, data_dir, root)
            previous_dir = root / "previous"
            previous_dir.mkdir()
            for relative in baseline.paths:
                archive = data_dir / relative
                target = previous_dir / archive.name
                target.mkdir()
                try:
                    unpack(archive, target, limits)
                except (UnsafeArchiveError, UnsupportedArchiveError) as e:
                    log.warning("%s: %r", archive.name, e)
            signals = DiffAnalyzer().analyze(
                ReleaseContext(
                    name=sample.name,
                    version=sample.version,
                    metadata={"previous_version": baseline.version},
                    artifact_dir=artifact_dir,
                    previous_artifact_dir=previous_dir,
                )
            )
            row["signals"] = [signal.model_dump(mode="json") for signal in signals]
        except Exception as e:
            row["error"] = repr(e)
    return row


def run_scan(data_dir: Path, processes: int) -> Path:
    samples = [s for s in positives(data_dir) if s.group is Group.COMPROMISED]
    ordinary = negatives(NEGATIVES_PER_GROUP)
    asyncio.run(download_negatives(ordinary, data_dir))
    samples += [s for s in ordinary if (data_dir / s.path).exists()]
    path = data_dir / RESULTS_FILE
    done = {row["id"] for row in _rows(path)}
    left = [sample for sample in samples if sample.id not in done]
    baselines = asyncio.run(_baselines(left, data_dir))
    log.info("%d of %d samples have a baseline", len(baselines), len(left))
    context = multiprocessing.get_context("spawn")
    with (
        ProcessPoolExecutor(processes, mp_context=context) as executor,
        path.open("a", encoding="utf-8") as output,
    ):
        futures = [executor.submit(diff_sample, baseline, data_dir) for baseline in baselines]
        for count, future in enumerate(as_completed(futures), start=1):
            output.write(json.dumps(future.result()) + "\n")
            output.flush()
            if count % 100 == 0:
                log.info("%d/%d", count, len(baselines))
    return path


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def with_diff(results: Iterable[Result], rows: Iterable[dict[str, Any]]) -> list[Result]:
    """Static signals of each release joined with its diff signals."""
    signals = {
        row["id"]: [Signal.model_validate(signal) for signal in row["signals"]] for row in rows
    }
    return [
        dataclasses.replace(result, signals=[*result.signals, *signals[result.id]])
        if result.id in signals
        else result
        for result in results
    ]


def follow_ups(results: Iterable[Result], rows: Iterable[dict[str, Any]]) -> set[str]:
    """Attack releases with an earlier attack release of the package above their baseline."""
    previous = {row["id"]: row["previous"] for row in rows}
    attacks: dict[str, list[str]] = defaultdict(list)
    for result in results:
        if result.group is Group.COMPROMISED:
            attacks[result.name].append(result.id.rsplit("/", 1)[1])
    found = set()
    for result in results:
        version = result.id.rsplit("/", 1)[1]
        if result.group is Group.COMPROMISED and result.id in previous:
            base = _version(previous[result.id])
            current = _version(version)
            if any(base < _version(v) < current for v in attacks[result.name]):
                found.add(result.id)
    return found


def _version(text: str) -> Version:
    try:
        return Version(text)
    except InvalidVersion:
        return Version("0")


def _share(scored: Sequence[Scored]) -> str:
    alerted = sum(s.alerted for s in scored)
    return f"{alerted} / {len(scored)}" + (f" ({alerted / len(scored):.1%})" if scored else "")


def render(results: Sequence[Result], rows: Sequence[dict[str, Any]], path: Path) -> str:
    config = load_scoring_config(path)
    top = top_packages()
    usable = [row for row in rows if row["error"] is None]
    covered = {row["id"] for row in usable}
    before = score_results(results, config, top)
    after = score_results(with_diff(results, usable), config, top)
    second = follow_ups(results, usable)

    lines = ["# Дифф на реальных релизах", ""]
    lines += [f"Сравнено релизов: {len(usable)}, ошибок: {len(rows) - len(usable)}.", ""]
    lines += ["| Выборка | Только статика | Статика и дифф |", "| --- | --- | --- |"]

    def row(title: str, chosen: Sequence[bool]) -> None:
        lines.append(
            f"| {title} | {_share([s for s, c in zip(before, chosen, strict=True) if c])} "
            f"| {_share([s for s, c in zip(after, chosen, strict=True) if c])} |"
        )

    groups = [r.group for r in results]
    ids = [r.id for r in results]
    row("compromised, все", [g is Group.COMPROMISED for g in groups])
    row(
        "compromised, первый заражённый релиз",
        [
            g is Group.COMPROMISED and i in covered and i not in second
            for g, i in zip(groups, ids, strict=True)
        ],
    )
    row(
        "compromised, продолжение атаки",
        [g is Group.COMPROMISED and i in second for g, i in zip(groups, ids, strict=True)],
    )
    row(
        "random, обновления",
        [g is Group.RANDOM and i in covered for g, i in zip(groups, ids, strict=True)],
    )
    row(
        "popular, обновления",
        [g is Group.POPULAR and i in covered for g, i in zip(groups, ids, strict=True)],
    )

    with_layer = compute_metrics([s for s in after if not s.result.malicious])
    without = compute_metrics([s for s in before if not s.result.malicious])
    lines += [
        "",
        f"Алертов в день, все негативы: {with_layer.alerts_per_day:.0f} "
        f"(без диффа {without.alerts_per_day:.0f}).",
        "",
        "| Релиз | Предыдущая | Только статика | Статика и дифф |",
        "| --- | --- | --- | --- |",
    ]
    previous = {row_["id"]: row_["previous"] for row_ in rows}
    for old, new in zip(before, after, strict=True):
        if old.result.group is Group.COMPROMISED:
            mark = " (продолжение)" if old.result.id in second else ""
            lines.append(
                f"| {old.result.id.split('/', 1)[1]}{mark} | {previous.get(old.result.id, 'нет')} "
                f"| {old.level.value} {old.score} | {new.level.value} {new.score} |"
            )
    new_alerts = [
        new
        for old, new in zip(before, after, strict=True)
        if new.alerted and not old.alerted and not new.result.malicious
    ]
    lines += ["", f"**Новые ложные алерты: {len(new_alerts)}**", ""]
    counts: dict[str, int] = defaultdict(int)
    for scored in new_alerts:
        for rule in {s.rule_id for s in scored.result.signals if s.rule_id.startswith("diff.")}:
            counts[rule] += 1
    lines += [
        f"- `{rule}`: {count}"
        for rule, count in sorted(counts.items(), key=lambda item: -item[1])[:TOP_RULES]
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.real_diff")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_command = commands.add_parser("scan")
    scan_command.add_argument("--processes", type=int, default=multiprocessing.cpu_count())
    report_command = commands.add_parser("report")
    report_command.add_argument("--config", type=Path, default=Path("config/scoring.yaml"))
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if arguments.command == "scan":
        print(run_scan(DATA_DIR, arguments.processes))
        return 0
    results = [r for r in load_results(latest_results(DATA_DIR)) if r.error is None]
    print(render(results, _rows(DATA_DIR / RESULTS_FILE), arguments.config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
