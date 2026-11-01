"""Signals from the life of a project: who publishes, when, and how the version moves."""

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, ClassVar

from packaging.version import InvalidVersion, Version

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.domain import Severity

DORMANT_AFTER = timedelta(days=365)
MIN_MAJOR_JUMP = 2
# Calendar versions: going from 2023.1 to 2025.1 is not a jump.
CALENDAR_MAJOR = 1000


def owners_of(ownership: Mapping[str, Any] | None) -> set[str]:
    """Who controls a project. The organization counts: a project may have no direct roles."""
    ownership = ownership or {}
    owners = {role["user"] for role in ownership.get("roles", [])}
    organization = ownership.get("organization")
    return owners | {f"org:{organization}"} if organization else owners


class ContextAnalyzer(Analyzer):
    name: ClassVar[str] = "context"
    version: ClassVar[str] = "1"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        metadata = release.metadata
        return [
            signal
            for signal in (
                _owners_changed(metadata),
                _dormant(metadata),
                _version_jump(metadata, release.version),
            )
            if signal is not None
        ]


def _owners_changed(metadata: Mapping[str, Any]) -> Signal | None:
    # Only a snapshot we took back then tells: PyPI shows the present owners for any old version.
    known: list[str] | None = metadata.get("known_owners")
    current = owners_of(metadata.get("ownership"))
    if not known or not current:
        return None
    previous = set(known)
    added = current - previous
    if not added:
        return None
    replaced = not current & previous
    return Signal(
        rule_id="context.owners_replaced" if replaced else "context.owner_added",
        severity=Severity.HIGH if replaced else Severity.MEDIUM,
        confidence=0.8 if replaced else 0.7,
        evidence=f"owners were {sorted(previous)}, now {sorted(current)}",
    )


def _dormant(metadata: Mapping[str, Any]) -> Signal | None:
    last_upload, first_upload = metadata.get("last_upload"), metadata.get("release_upload")
    if last_upload is None or first_upload is None:
        return None
    silence = datetime.fromisoformat(first_upload) - datetime.fromisoformat(last_upload)
    if silence < DORMANT_AFTER:
        return None
    return Signal(
        rule_id="context.dormant_release",
        severity=Severity.MEDIUM,
        confidence=0.6,
        evidence=f"{silence.days} days after the upload of {last_upload}",
    )


def _version_jump(metadata: Mapping[str, Any], version: str) -> Signal | None:
    previous = metadata.get("previous_version")
    if previous is None:
        return None
    try:
        old, new = Version(previous), Version(version)
    except InvalidVersion:
        return None
    if new.major - old.major < MIN_MAJOR_JUMP or old.major >= CALENDAR_MAJOR:
        return None
    return Signal(
        rule_id="context.version_jump",
        severity=Severity.MEDIUM,
        confidence=0.6,
        evidence=f"{previous} -> {version}",
    )
