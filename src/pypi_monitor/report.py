"""A release as text: everything the pipeline concluded about it."""

from packaging.utils import canonicalize_name
from sqlalchemy import select

from pypi_monitor.db.models import AnalysisRun, Package, Release, Signal, Verdict
from pypi_monitor.db.session import Sessions

_MAX_EVIDENCE = 200


async def release_report(sessions: Sessions, name: str, version: str) -> str:
    async with sessions() as session:
        release = await session.scalar(
            select(Release)
            .join(Package, Package.id == Release.package_id)
            .where(Package.normalized_name == canonicalize_name(name), Release.version == version)
        )
        if release is None:
            return f"{name} {version} is not known"
        previous = (
            None
            if release.prev_release_id is None
            else await session.get(Release, release.prev_release_id)
        )
        verdicts = list(
            await session.scalars(select(Verdict).where(Verdict.release_id == release.id))
        )
        runs = list(
            await session.scalars(select(AnalysisRun).where(AnalysisRun.release_id == release.id))
        )
        signals = list(
            await session.execute(
                select(AnalysisRun.analyzer, Signal)
                .join(Signal, Signal.run_id == AnalysisRun.id)
                .where(AnalysisRun.release_id == release.id)
                .order_by(AnalysisRun.analyzer, Signal.rule_id, Signal.id)
            )
        )

    lines = [
        f"{name} {version}: {release.status.value}",
        f"compared with: {previous.version if previous else 'nothing'}",
        f"owners: {', '.join(release.maintainers) or 'unknown'}",
    ]
    lines += [f"verdict: {v.level.value} {v.score}/100 ({v.decided_by.value})" for v in verdicts]
    lines += [f"failed analyzer {run.analyzer}: {run.error}" for run in runs if run.error]
    for analyzer, signal in signals:
        location = signal.file_path or ""
        if location and signal.line:
            location = f"{location}:{signal.line}"
        lines.append(
            f"[{analyzer}] {signal.severity.value} {signal.confidence:.2f} {signal.rule_id}"
            f" {location}".rstrip()
        )
        lines += [f"    {line}" for line in signal.evidence[:_MAX_EVIDENCE].splitlines()]
    return "\n".join(lines)
