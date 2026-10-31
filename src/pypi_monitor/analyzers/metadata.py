"""Metadata signals: everything that can be said about a release without reading its code."""

import ast
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from packaging.utils import canonicalize_name

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.analyzers.typosquat import TyposquatDetector
from pypi_monitor.domain import Severity

NEW_PACKAGE_AGE = timedelta(hours=24)
MIN_README_LENGTH = 100
FORGES = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
# Imports a setup.py normally has; anything else there runs at install time for a reason.
PLAIN_SETUP_IMPORTS = frozenset(
    {
        "setuptools",
        "distutils",
        "os",
        "sys",
        "io",
        "re",
        "codecs",
        "pathlib",
        "glob",
        "pkg_resources",
    }
)
_TOP_RANK_FOR_HIGH_CONFIDENCE = 1000


class MetadataAnalyzer(Analyzer):
    name: ClassVar[str] = "metadata"
    version: ClassVar[str] = "2"

    def __init__(self, top_packages: Mapping[str, int]) -> None:
        self._top_packages = top_packages
        self._typosquat = TyposquatDetector(top_packages)

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        metadata = release.metadata
        info: Mapping[str, Any] = metadata.get("info", {})
        name = canonicalize_name(release.name)
        return [
            signal
            for signal in (
                self._typosquatting(name),
                _new_package(metadata),
                _first_account_release(metadata),
                _empty_readme(info),
                _no_repository(info),
                self._foreign_repository(name, info),
                _sdist_only_with_logic(release),
            )
            if signal is not None
        ]

    def _typosquatting(self, name: str) -> Signal | None:
        match = self._typosquat.find(name)
        if match is None:
            return None
        confidence = 0.9 if match.rank <= _TOP_RANK_FOR_HIGH_CONFIDENCE else 0.7
        if match.distance > 1:
            confidence -= 0.2
        return Signal(
            rule_id="metadata.typosquat",
            # Name collisions are common: it takes a new package or a threat to raise an alert.
            severity=Severity.MEDIUM,
            confidence=confidence,
            evidence=f"{name} resembles {match.target} (rank {match.rank}): {match.technique}",
        )

    def _foreign_repository(self, name: str, info: Mapping[str, Any]) -> Signal | None:
        if name in self._top_packages:
            return None
        for url in _urls(info):
            parsed = urlparse(url)
            parts = parsed.path.strip("/").split("/")
            if parsed.hostname not in FORGES or len(parts) < 2:
                continue
            repository = canonicalize_name(parts[1].removesuffix(".git"))
            if repository != name and repository in self._top_packages:
                return Signal(
                    rule_id="metadata.foreign_repository",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    evidence=f"links to {url}, the repository of popular {repository}",
                )
        return None


def _new_package(metadata: Mapping[str, Any]) -> Signal | None:
    first_upload = metadata.get("first_upload")
    if first_upload is None:
        return None
    age = datetime.now(UTC) - datetime.fromisoformat(first_upload)
    if age > NEW_PACKAGE_AGE:
        return None
    return Signal(
        rule_id="metadata.new_package",
        severity=Severity.LOW,
        confidence=1,
        evidence=f"first upload {first_upload}",
    )


def _first_account_release(metadata: Mapping[str, Any]) -> Signal | None:
    counts: Mapping[str, int] = metadata.get("owner_package_counts", {})
    if not counts or max(counts.values()) > 1:
        return None
    return Signal(
        rule_id="metadata.first_account_release",
        severity=Severity.LOW,
        confidence=0.8,
        evidence=f"owners have no other packages: {', '.join(sorted(counts))}",
    )


def _empty_readme(info: Mapping[str, Any]) -> Signal | None:
    description = (info.get("description") or "").strip()
    if len(description) >= MIN_README_LENGTH:
        return None
    return Signal(
        rule_id="metadata.empty_readme",
        severity=Severity.LOW,
        confidence=0.8,
        evidence=f"description has {len(description)} characters",
    )


def _urls(info: Mapping[str, Any]) -> list[str]:
    urls = list((info.get("project_urls") or {}).values())
    urls += [info.get("home_page") or ""]
    return [url for url in urls if url]


def _no_repository(info: Mapping[str, Any]) -> Signal | None:
    if any(urlparse(url).hostname in FORGES for url in _urls(info)):
        return None
    return Signal(
        rule_id="metadata.no_repository",
        severity=Severity.LOW,
        confidence=0.6,
        evidence="no link to a source repository",
    )


def _sdist_only_with_logic(release: ReleaseContext) -> Signal | None:
    files = release.metadata.get("urls", [])
    has_wheel = any(file.get("packagetype") == "bdist_wheel" for file in files)
    if has_wheel or not files or release.artifact_dir is None:
        return None
    for setup_py in _top_level_setup_files(release.artifact_dir):
        reason = _setup_logic(setup_py)
        if reason is not None:
            return Signal(
                rule_id="metadata.sdist_only_setup_logic",
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence=f"sdist without a wheel and setup.py {reason}",
                file_path=str(setup_py.relative_to(release.artifact_dir)),
            )
    return None


def _top_level_setup_files(artifact_dir: Path) -> list[Path]:
    # <artifact_dir>/<archive>/<name>-<version>/setup.py
    return sorted(artifact_dir.glob("*/*/setup.py"))


def _setup_logic(setup_py: Path) -> str | None:
    """Tell what in a setup.py goes beyond a declaration. The file is parsed, never executed."""
    source = setup_py.read_bytes()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return "does not parse"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            modules = []
        for module in modules:
            if module.partition(".")[0] not in PLAIN_SETUP_IMPORTS:
                return f"imports {module}"
    if re.search(rb"\bcmdclass\b", source):
        return "overrides install commands"
    return None
