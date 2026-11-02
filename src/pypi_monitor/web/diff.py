"""Line diff of two unpacked releases, for a person to read.

Everything here is untrusted text: it is read, never executed, and sizes are bounded, because
difflib is quadratic and one minified file would otherwise hold the page.
"""

import difflib
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from pypi_monitor.analyzers.tree import SDIST, WHEEL, Role, Tree, artifact_trees, role_of
from pypi_monitor.pipeline.unpack import (
    UnpackLimits,
    UnsafeArchiveError,
    UnsupportedArchiveError,
    unpack,
)
from pypi_monitor.storage import ArtifactStorage

MAX_FILE_BYTES = 512 * 1024
MAX_LINE_LENGTH = 2000
MAX_FILE_LINES = 3000
MAX_TOTAL_LINES = 30_000
# Code that runs by itself comes first: that is where a reader should look.
_ROLE_ORDER = {Role.AUTORUN: 0, Role.NORMAL: 1}
_LAST_ROLE = 2


class FileStatus(StrEnum):
    ADDED = "added"
    CHANGED = "changed"
    REMOVED = "removed"


@dataclass(frozen=True)
class FileDiff:
    path: str
    status: FileStatus
    autorun: bool
    lines: list[str]
    # Why there are no lines to show, or why they stop early.
    note: str | None = None


@dataclass
class ReleaseDiff:
    kind: str | None = None
    files: list[FileDiff] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StoredArtifact:
    filename: str
    storage_key: str


def _read_lines(path: Path | None) -> tuple[list[str], str | None]:
    if path is None:
        return [], None
    if path.stat().st_size > MAX_FILE_BYTES:
        return [], "файл слишком большой"
    data = path.read_bytes()
    if b"\0" in data:
        return [], "бинарный файл"
    text = data.decode("utf-8", "replace")
    if any(len(line) > MAX_LINE_LENGTH for line in text.splitlines()):
        return [], "слишком длинные строки: возможно, минифицированный код"
    return text.splitlines(), None


def _file_diff(path: str, old: Path | None, new: Path | None, budget: int) -> FileDiff:
    status = (
        FileStatus.ADDED
        if old is None
        else FileStatus.REMOVED
        if new is None
        else FileStatus.CHANGED
    )
    autorun = role_of(path) is Role.AUTORUN
    old_lines, old_note = _read_lines(old)
    new_lines, new_note = _read_lines(new)
    note = new_note or old_note
    if note:
        return FileDiff(path, status, autorun, [], note)
    if budget <= 0:
        return FileDiff(path, status, autorun, [], "дифф релиза слишком большой")
    limit = min(budget, MAX_FILE_LINES)
    lines = list(difflib.unified_diff(old_lines, new_lines, lineterm="", n=3))[2:]
    if len(lines) > limit:
        return FileDiff(path, status, autorun, lines[:limit], "дифф файла обрезан")
    return FileDiff(path, status, autorun, lines)


def _same_content(old: Path, new: Path) -> bool:
    return old.stat().st_size == new.stat().st_size and old.read_bytes() == new.read_bytes()


def _sort_key(path: str) -> tuple[int, str]:
    return _ROLE_ORDER.get(role_of(path), _LAST_ROLE), path


def diff_trees(old: Tree | None, new: Tree) -> list[FileDiff]:
    old_files = old.files if old else {}
    budget = MAX_TOTAL_LINES
    diffs = []
    for path in sorted(old_files.keys() | new.files.keys(), key=_sort_key):
        before, after = old_files.get(path), new.files.get(path)
        if before and after and _same_content(before, after):
            continue
        found = _file_diff(path, before, after, budget)
        budget -= len(found.lines)
        diffs.append(found)
    return diffs


def diff_directories(old_dir: Path, new_dir: Path) -> ReleaseDiff:
    """Compare like with like, as the analyzers do; a sdist is closest to the source."""
    new_trees, old_trees = artifact_trees(new_dir), artifact_trees(old_dir)
    for kind in (SDIST, WHEEL):
        if kind in new_trees and kind in old_trees:
            return ReleaseDiff(kind, diff_trees(old_trees[kind], new_trees[kind]))
    for kind in (SDIST, WHEEL):
        if kind in new_trees:
            return ReleaseDiff(kind, diff_trees(None, new_trees[kind]))
    return ReleaseDiff()


def _fetch(
    artifacts: Sequence[StoredArtifact],
    storage: ArtifactStorage,
    root: Path,
    limits: UnpackLimits,
    warnings: list[str],
) -> Path:
    archives, unpacked = root / "archives", root / "unpacked"
    archives.mkdir(parents=True)
    unpacked.mkdir()
    for artifact in artifacts:
        archive = archives / artifact.filename
        storage.get(artifact.storage_key, archive)
        target = unpacked / artifact.filename
        target.mkdir()
        try:
            unpack(archive, target, limits)
        except UnsupportedArchiveError:
            warnings.append(f"{artifact.filename}: формат архива не поддерживается")
        except UnsafeArchiveError as e:
            warnings.append(f"{artifact.filename}: распакован не полностью ({e.reason})")
    return unpacked


def release_diff(
    new: Sequence[StoredArtifact],
    old: Sequence[StoredArtifact],
    storage: ArtifactStorage,
    limits: UnpackLimits,
) -> ReleaseDiff:
    """Fetch and compare two releases. Blocking: callers run it in a thread."""
    warnings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="scm-dashboard-") as directory:
        root = Path(directory)
        new_dir = _fetch(new, storage, root / "new", limits, warnings)
        old_dir = _fetch(old, storage, root / "old", limits, warnings)
        diff = diff_directories(old_dir, new_dir)
    diff.warnings = warnings
    return diff
