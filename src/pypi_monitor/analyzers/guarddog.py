"""GuardDog as a static analysis engine: its YARA rules, normalized to our signals.

Only source code rules run. GuardDog's metadata rules reach out to the network (whois, git) and
overlap with `MetadataAnalyzer`.
"""

import logging
from functools import lru_cache
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from guarddog.analyzer.sourcecode import YaraRule, get_sourcecode_rules
from guarddog.ecosystems import ECOSYSTEM
from guarddog.scanners.pypi_package_scanner import PypiPackageScanner

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.domain import Severity

log = logging.getLogger(__name__)

RULE_PREFIX = "guarddog."
# Findings in code that runs by itself on install or import: this is where malware lives.
INSTALL_RULE_PREFIX = "guarddog.install."
THREAT_PREFIX = "threat-"
# Elsewhere threat rules mostly describe what ordinary CLI tools and agents do.
OUTSIDE_INSTALL_CONFIDENCE_FACTOR = 0.2
# <archive>/<package>/__init__.py in a wheel, <archive>/<root>/<package>/__init__.py in an sdist.
MAX_TOP_LEVEL_INIT_DEPTH = 4
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
    version: ClassVar[str] = f"{metadata.version('guarddog')}+2"

    def __init__(self) -> None:
        self._rules = {rule.id: rule for rule in get_sourcecode_rules(ECOSYSTEM.PYPI, YaraRule)}

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        if release.artifact_dir is None:
            raise ValueError("no unpacked artifact to scan")
        report = _scanner().scan_local(str(release.artifact_dir))
        if report.get("errors"):
            log.warning("GuardDog rule errors on %s: %s", release.name, report["errors"])
        return normalize_results(report["results"], self._rules, release.artifact_dir)


def normalize_results(
    results: dict[str, Any], rules: dict[str, Any], artifact_dir: Path
) -> list[Signal]:
    signals = []
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
                if _runs_on_install_or_import(file_path):
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


def _runs_on_install_or_import(file_path: str | None) -> bool:
    if file_path is None:
        return False
    parts = PurePosixPath(file_path).parts
    name = parts[-1]
    if name == "setup.py" or name.endswith(".pth"):
        return True
    return name == "__init__.py" and len(parts) <= MAX_TOP_LEVEL_INIT_DEPTH


def _parse_location(location: str, artifact_dir: Path) -> tuple[str | None, int | None]:
    """Locations look like `<path>:<line>`; the path may be absolute."""
    if not location:
        return None, None
    path, separator, line = location.rpartition(":")
    if not separator or not line.isdecimal() or int(line) < 1:
        return location, None
    return path.removeprefix(f"{artifact_dir}/"), int(line)
