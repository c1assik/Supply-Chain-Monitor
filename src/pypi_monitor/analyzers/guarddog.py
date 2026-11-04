"""GuardDog as a static analysis engine: its YARA rules, normalized to our signals.

Only source code rules run. GuardDog's metadata rules reach out to the network (whois, git) and
overlap with `MetadataAnalyzer`.
"""

import logging
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, ClassVar

from guarddog.analyzer.sourcecode import YaraRule, get_sourcecode_rules
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.pypi_package_scanner import PypiPackageScanner

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.analyzers.startup import StartupCode
from pypi_monitor.analyzers.tree import (
    WHEEL,
    Role,
    Tree,
    all_trees,
    artifact_trees,
    overlaid,
    role_of,
)
from pypi_monitor.domain import Severity

log = logging.getLogger(__name__)

RULE_PREFIX = "guarddog."
# Findings in code that runs by itself on install or import: this is where malware lives. The
# roles are those of the diff, see `tree.role_of` and `startup`.
INSTALL_RULE_PREFIX = "guarddog.install."
THREAT_PREFIX = "threat-"
# Elsewhere threat rules mostly describe what ordinary CLI tools and agents do.
OUTSIDE_INSTALL_CONFIDENCE_FACTOR = 0.2
# Noisy rules can match thousands of times in a big package; the first few tell the story.
MAX_SIGNALS_PER_RULE = 10
CAPABILITY_PREFIX = "capability-"
# A capability alone is what ordinary code does: only the combination of them means something.
CAPABILITY_CONFIDENCE = 0.5
SPECIFICITY_CONFIDENCE = {"low": 0.5, "medium": 0.7, "high": 0.9}
DEFAULT_CONFIDENCE = 0.7


@lru_cache
def _scanner() -> PypiPackageScanner:
    """One per process: analyzers travel to the process pool, the scanner does not pickle."""
    return PypiPackageScanner()


class GuardDogAnalyzer(Analyzer):
    name: ClassVar[str] = "guarddog"
    version: ClassVar[str] = f"{metadata.version('guarddog')}+4"

    def __init__(self) -> None:
        self._rules = {rule.id: rule for rule in get_sourcecode_rules(ECOSYSTEM.PYPI, YaraRule)}

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        if release.artifact_dir is None:
            raise ValueError("no unpacked artifact to scan")
        signals = self.normalize(scan(release.artifact_dir), release.artifact_dir)
        extra = release.extra_wheels_dir
        if extra is not None:
            # What the other wheels left after deduplication, read as if installed over the
            # first wheel: their `__init__.py` is usually the one that was dropped as a copy.
            wheel = artifact_trees(release.artifact_dir).get(WHEEL)
            signals += normalize_results(scan(extra), self._rules, extra, wheel)
        return signals

    def normalize(self, results: dict[str, Any], artifact_dir: Path) -> list[Signal]:
        return normalize_results(results, self._rules, artifact_dir)


def scan(artifact_dir: Path) -> dict[str, Any]:
    """Raw GuardDog findings by rule; the benchmark also needs them as they are."""
    report = _scanner().scan_local(str(artifact_dir))
    if report.get("errors"):
        log.warning("GuardDog rule errors on %s: %s", artifact_dir, report["errors"])
    results: dict[str, Any] = report["results"]
    return results


def normalize_results(
    results: dict[str, Any],
    rules: dict[str, Any],
    artifact_dir: Path,
    underlay: Tree | None = None,
) -> list[Signal]:
    """Signals of GuardDog findings. `underlay`: files that the trees are installed over."""
    signals = []
    places = _Places(artifact_dir, underlay)
    for rule_id, findings in results.items():
        # Rules without findings report an empty dict, not an empty list.
        if not findings:
            continue
        rule = rules.get(rule_id)
        severity = Severity(getattr(rule, "severity", None) or Severity.MEDIUM)
        confidence = SPECIFICITY_CONFIDENCE.get(
            getattr(rule, "specificity", None) or "", DEFAULT_CONFIDENCE
        )
        if rule_id.startswith(CAPABILITY_PREFIX):
            severity, confidence = Severity.LOW, CAPABILITY_CONFIDENCE
        for finding in findings[:MAX_SIGNALS_PER_RULE]:
            file_path, line = _parse_location(finding.get("location", ""), artifact_dir)
            signal_rule, signal_confidence = f"{RULE_PREFIX}{rule_id}", confidence
            if rule_id.startswith(THREAT_PREFIX):
                if places.runs_by_itself(file_path, line):
                    signal_rule = f"{INSTALL_RULE_PREFIX}{rule_id}"
                else:
                    signal_confidence *= OUTSIDE_INSTALL_CONFIDENCE_FACTOR
            signals.append(
                Signal(
                    rule_id=signal_rule,
                    severity=severity,
                    confidence=signal_confidence,
                    evidence=f"{finding.get('message', '')}\n{finding.get('code', '')}".strip(),
                    file_path=file_path,
                    line=line,
                )
            )
    return signals


class _Places:
    """Where a finding sits in its artifact, read lazily: most releases have no threat findings."""

    def __init__(self, artifact_dir: Path, underlay: Tree | None = None) -> None:
        self._artifact_dir = artifact_dir
        self._underlay = underlay
        self._index: dict[str, tuple[Tree, str]] | None = None
        self._startup: dict[int, StartupCode] = {}

    def runs_by_itself(self, file_path: str | None, line: int | None) -> bool:
        found = self._find(file_path)
        if found is None:
            return False
        tree, path = found
        role = role_of(path)
        if role is Role.AUTORUN:
            return True
        if role is not Role.NORMAL:
            return False  # Tests, vendored code and the like: a test may well call `setup()`.
        startup = self._startup.get(id(tree))
        if startup is None:
            startup = self._startup[id(tree)] = StartupCode(overlaid(tree, self._underlay))
        return startup.runs_at_import(path, line)

    def _find(self, file_path: str | None) -> tuple[Tree, str] | None:
        if file_path is None:
            return None
        if self._index is None:
            trees = all_trees(self._artifact_dir) if self._artifact_dir.is_dir() else []
            self._index = {
                tree.display(path): (tree, path) for tree in trees for path in tree.files
            }
        return self._index.get(file_path)


def _parse_location(location: str, artifact_dir: Path) -> tuple[str | None, int | None]:
    """Locations look like `<path>:<line>`; the path may be absolute."""
    if not location:
        return None, None
    path, separator, line = location.rpartition(":")
    if not separator or not line.isdecimal() or int(line) < 1:
        return location, None
    return path.removeprefix(f"{artifact_dir}/"), int(line)
