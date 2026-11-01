"""Does released code match its source: wheel against sdist, sdist against the release tag.

A package is built from a repository, so code in an artifact that the source does not have got
there outside the reviewed history: this is how a stolen token or a compromised build looks.
Only what reaches users is compared. An sdist drags along submodules and CI scripts, and these
legitimately differ from the repository, so the wheel tells which files of the sdist matter.
"""

from collections.abc import Collection
from pathlib import PurePosixPath
from typing import ClassVar

from pypi_monitor.analyzers.base import Analyzer, ReleaseContext, Signal
from pypi_monitor.analyzers.tree import (
    SDIST,
    WHEEL,
    CodeReader,
    Role,
    Tree,
    artifact_trees,
    content_key,
    installed_paths,
    load_tree,
    read_source,
    role_of,
)
from pypi_monitor.domain import Severity

_COMPARED_SUFFIXES = (".py", ".pth")
_MAX_SIGNALS_PER_RULE = 10
# A build that compiles code also generates some: numpy/__config__.py, __init__.py from maturin.
_PLATFORM_WHEEL_CONFIDENCE_FACTOR = 0.5
WHEEL_PREFIX = "consistency.wheel"
TAG_PREFIX = "consistency.tag"


class ConsistencyAnalyzer(Analyzer):
    name: ClassVar[str] = "consistency"
    version: ClassVar[str] = "1"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        if release.artifact_dir is None:
            return []
        trees = artifact_trees(release.artifact_dir)
        sdist, wheel = trees.get(SDIST), trees.get(WHEEL)
        reader = CodeReader({release.version})
        signals = []
        if sdist is not None and wheel is not None:
            signals += _Comparison(wheel, sdist, reader, WHEEL_PREFIX).run(wheel.files.keys())
        repository = release.repository_dir
        archives = [p for p in repository.iterdir() if p.is_dir()] if repository else []
        if archives and repository is not None:
            source = load_tree(archives[0], repository)
            if sdist is not None:
                paths = installed_paths(sdist, wheel) or sdist.files.keys()
                signals += _Comparison(sdist, source, reader, TAG_PREFIX).run(paths)
            elif wheel is not None:
                signals += _Comparison(wheel, source, reader, TAG_PREFIX).run(wheel.files.keys())
        return signals


class _Comparison:
    def __init__(self, built: Tree, source: Tree, reader: CodeReader, prefix: str) -> None:
        self._built = built
        self._source = source
        self._reader = reader
        self._prefix = prefix
        self._by_name: dict[str, list[str]] = {}
        for path in source.files:
            self._by_name.setdefault(PurePosixPath(path).name, []).append(path)
        self._raw = {
            content_key(content)
            for path in source.files
            if (content := self._read(source, path)) is not None
        }

    def _read(self, tree: Tree, path: str) -> bytes | None:
        return read_source(tree.files[path]) if path.endswith(_COMPARED_SUFFIXES) else None

    def run(self, paths: Collection[str]) -> list[Signal]:
        counts = {"missing": 0, "differs": 0}
        signals = []
        for path in sorted(paths):
            role = role_of(path)
            content = self._read(self._built, path)
            # Generated files, tests and vendored code legitimately differ between the two.
            if role in (Role.IGNORED, Role.NOISY) or content is None or not content.strip():
                continue
            if content_key(content) in self._raw:
                continue
            counterpart = _counterpart(path, self._source)
            if self._matches(path, content):
                continue
            kind = "missing" if counterpart is None else "differs"
            counts[kind] += 1
            if counts[kind] <= _MAX_SIGNALS_PER_RULE:
                signals.append(self._signal(path, role, kind, counterpart))
        return signals

    def _matches(self, path: str, content: bytes) -> bool:
        """The same code under the same file name: builds move packages, but do not rename files."""
        code = self._reader.fingerprint(path, content)
        for candidate in self._by_name.get(PurePosixPath(path).name, ()):
            original = self._read(self._source, candidate)
            if original is not None and self._reader.fingerprint(candidate, original) == code:
                return True
        return False

    def _signal(self, path: str, role: Role, kind: str, counterpart: str | None) -> Signal:
        confidence = 0.8 if role is Role.AUTORUN else 0.6
        if not self._built.pure:
            confidence *= _PLATFORM_WHEEL_CONFIDENCE_FACTOR
        reference = "the sdist" if self._prefix == WHEEL_PREFIX else "the release tag"
        where = f"is not in {reference}" if counterpart is None else f"differs from {counterpart}"
        return Signal(
            rule_id=f"{self._prefix}_code_{kind}",
            severity=Severity.HIGH,
            confidence=confidence,
            evidence=f"code {where}",
            file_path=self._built.display(path),
        )


def _counterpart(path: str, source: Tree) -> str | None:
    """The file `path` comes from: layouts differ (`src/`, subdirectories of a monorepo)."""
    if path in source.files:
        return path
    suffix = f"/{path}"
    return min((p for p in source.files if p.endswith(suffix)), key=len, default=None)
