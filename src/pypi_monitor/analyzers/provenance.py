"""Signals from how a release was published: PEP 740 attestations of Trusted Publishing.

A project that publishes from CI by Trusted Publishing gets attestations on every file. A stolen
API token or password uploads from the attacker's machine, and the attestations are gone; a
hijacked CI publishes from another repository or workflow. Both are cheap to see and rare in
ordinary life, where a project moves to Trusted Publishing once and stays.
"""

from collections.abc import Mapping
from typing import Any, ClassVar

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.domain import Severity

# Where the code comes from; the rest names the job inside the same repository.
_WORKFLOW_KEYS = frozenset({"workflow", "workflow_filepath", "environment"})


class ProvenanceAnalyzer(Analyzer):
    name: ClassVar[str] = "provenance"
    version: ClassVar[str] = "2"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        snapshot: Mapping[str, Any] | None = release.metadata.get("provenance")
        if not snapshot:
            return []
        before: Mapping[str, Any] | None = snapshot.get("previous_publisher")
        attested_types = set(snapshot.get("previous_attested_types", []))
        signals: dict[str, Signal] = {}
        for file in snapshot.get("files", []):
            publisher = file.get("publisher")
            filename = file.get("filename", "")
            if publisher is None:
                # Wheels built elsewhere may never have had them: like is compared with like.
                if file.get("packagetype") in attested_types:
                    signals.setdefault(
                        "provenance.attestations_dropped",
                        Signal(
                            rule_id="provenance.attestations_dropped",
                            severity=Severity.HIGH,
                            confidence=0.7,
                            evidence=(
                                f"previous version was published by Trusted Publishing "
                                f"({_describe(before)}), {filename} has no attestations"
                            ),
                            file_path=filename,
                        ),
                    )
            elif before is not None and _source(publisher) != _source(before):
                signals.setdefault(
                    "provenance.publisher_changed",
                    Signal(
                        rule_id="provenance.publisher_changed",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        evidence=f"{_describe(before)} -> {_describe(publisher)}",
                        file_path=filename,
                    ),
                )
            elif before is not None and _job(publisher) != _job(before):
                signals.setdefault(
                    "provenance.workflow_changed",
                    Signal(
                        rule_id="provenance.workflow_changed",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        evidence=f"{_describe(before)} -> {_describe(publisher)}",
                        file_path=filename,
                    ),
                )
        return list(signals.values())


def _source(publisher: Mapping[str, Any]) -> dict[str, Any]:
    # GitHub and GitLab names do not depend on case: `Org/Repo` and `org/repo` are one repository.
    return {
        key: value.lower() if isinstance(value, str) else value
        for key, value in publisher.items()
        if key not in _WORKFLOW_KEYS
    }


def _job(publisher: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in publisher.items() if key in _WORKFLOW_KEYS}


def _describe(publisher: Mapping[str, Any] | None) -> str:
    if not publisher:
        return "publisher unknown"
    parts = [str(publisher.get("kind", "?")), str(publisher.get("repository", ""))]
    workflow = publisher.get("workflow") or publisher.get("workflow_filepath")
    if workflow:
        parts.append(str(workflow))
    if publisher.get("environment"):
        parts.append(f"env {publisher['environment']}")
    return " ".join(part for part in parts if part)
