"""The wheels of a release beyond the first, cut down to what only they hold.

A project with compiled code uploads a wheel per platform and Python, and their Python files are
the same. Scanning each of them again would multiply the work for nothing, so a file is kept only
where it appears first with its content: a payload in the Windows wheel alone is what remains.
"""

import hashlib
import os
from pathlib import Path

from pypi_monitor.analyzers.tree import WHEEL, all_trees


def keep_unique_files(unpacked: Path, extra: Path) -> None:
    """Delete from the wheels under `extra` every file seen before, in a wheel under `unpacked`
    or in an earlier wheel under `extra`. A file counts as seen by its installed path and content.
    """
    seen: set[tuple[str, bytes]] = set()
    for tree in all_trees(unpacked):
        if tree.kind == WHEEL:
            seen.update((path, _digest(real)) for path, real in tree.files.items())
    for tree in all_trees(extra):
        for path, real in tree.files.items():
            key = (path, _digest(real))
            if key in seen:
                real.unlink()
            else:
                seen.add(key)
    _remove_empty_directories(extra)


def _digest(path: Path) -> bytes:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "blake2b").digest()


def _remove_empty_directories(top: Path) -> None:
    for directory, _, _ in sorted(os.walk(top), key=lambda entry: -len(entry[0])):
        path = Path(directory)
        if path != top and not any(path.iterdir()):
            path.rmdir()
