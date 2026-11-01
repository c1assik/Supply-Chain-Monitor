"""Unpacked artifacts as trees of files with comparable paths and normalized content."""

import ast
import hashlib
import os
import re
import warnings
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path, PurePosixPath

from pypi_monitor.analyzers.facts import Fact, extract_facts, may_have_facts

SDIST = "sdist"
WHEEL = "wheel"
MAX_SOURCE_BYTES = 10 * 1024 * 1024
VERSION_PLACEHOLDER = "<version>"

_BUILD_DIR = re.compile(r"^[^/]+\.(dist-info|data)/")
_MAX_AUTORUN_INIT_DEPTH = 2  # pkg/__init__.py, and the same under src/
_METADATA_SUFFIXES = (".egg-info", "dist-info")
_NOISY_DIRS = frozenset(
    {
        "vendor",
        "vendored",
        "_vendor",
        "_vendored",
        "third_party",
        "thirdparty",
        "third-party",
        "externals",
        "node_modules",
        "test",
        "tests",
        "testing",
        "doc",
        "docs",
        "example",
        "examples",
        "benchmarks",
    }
)
_GENERATED_NAMES = frozenset({"version.py", "__version__.py"})
_GENERATED_SUFFIXES = ("_pb2.py", "_pb2_grpc.py", "_pb2.pyi", "_test.py")
_VERSION_NAMES = frozenset(
    {"__version__", "version", "VERSION", "__version_info__", "version_info"}
)
_DOCSTRING_OWNERS = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


class Role(Enum):
    """How much a change to a file means."""

    IGNORED = auto()  # Written by the build tool and never executed.
    NOISY = auto()  # Vendored, generated or test code: changes in bulk, rarely runs by itself.
    NORMAL = auto()
    AUTORUN = auto()  # Runs by itself on install or import: this is where malware lives.


def role_of(path: str) -> Role:
    pure = PurePosixPath(path)
    name, parents = pure.name, pure.parts[:-1]
    if name.endswith(".pth"):
        return Role.AUTORUN
    if any(part.endswith(_METADATA_SUFFIXES) for part in parents) or name == "PKG-INFO":
        return Role.NORMAL if name == "entry_points.txt" else Role.IGNORED
    if (
        _NOISY_DIRS.intersection(parents)
        or name in _GENERATED_NAMES
        or name.startswith(("test_", "_version"))
        or name == "conftest.py"
        or name.endswith(_GENERATED_SUFFIXES)
    ):
        return Role.NOISY
    package_parts = pure.parts[1:] if pure.parts[0] == "src" else pure.parts
    if path == "setup.py" or (
        name == "__init__.py" and len(package_parts) <= _MAX_AUTORUN_INIT_DEPTH
    ):
        return Role.AUTORUN
    return Role.NORMAL


@dataclass(frozen=True)
class Tree:
    """Files of one artifact by a path that does not depend on the version."""

    kind: str
    # Platform wheels hold compiled code by design, so a new binary means nothing in them.
    pure: bool
    base: Path
    files: dict[str, Path]

    def display(self, path: str) -> str:
        """The path as signals report it: relative to the directory that holds the artifacts."""
        return self.files[path].relative_to(self.base).as_posix()


def installed_paths(sdist: Tree, wheel: Tree | None) -> set[str] | None:
    """The sdist files that reach users, or None when there is no wheel to tell.

    An sdist also carries CI scripts and whole submodules that nothing ever installs. Only the
    `setup.py` level is kept: pip runs what is there while building from the sdist.
    """
    if wheel is None:
        return None
    return {
        path
        for path in sdist.files
        if "/" not in path or any(suffix in wheel.files for suffix in _path_suffixes(path))
    }


def _path_suffixes(path: str) -> Iterator[str]:
    parts = PurePosixPath(path).parts
    return ("/".join(parts[start:]) for start in range(len(parts)))


def artifact_trees(artifact_dir: Path) -> dict[str, Tree]:
    """Trees of `<artifact_dir>/<archive>/...` by artifact kind."""
    trees: dict[str, Tree] = {}
    for archive in sorted(path for path in artifact_dir.iterdir() if path.is_dir()):
        tree = load_tree(archive, artifact_dir)
        trees.setdefault(tree.kind, tree)
    return trees


def load_tree(archive: Path, base: Path) -> Tree:
    if archive.name.endswith(".whl"):
        files = {
            _BUILD_DIR.sub(r"\1/", path): real for path, real in _walk(archive, archive).items()
        }
        return Tree(WHEEL, archive.name.endswith("-none-any.whl"), base, files)
    # An sdist and a source archive have one directory with a version in its name.
    entries = list(archive.iterdir())
    root = entries[0] if len(entries) == 1 and entries[0].is_dir() else archive
    return Tree(SDIST, True, base, _walk(root, root))


def _walk(top: Path, root: Path) -> dict[str, Path]:
    files = {}
    for directory, _, names in os.walk(top):
        for name in names:
            real = Path(directory, name)
            files[real.relative_to(root).as_posix()] = real
    return files


def read_source(path: Path) -> bytes | None:
    """The content of a file, or None when it is too big to be worth reading."""
    return None if path.stat().st_size > MAX_SOURCE_BYTES else path.read_bytes()


@dataclass(frozen=True)
class ParsedCode:
    # Hash of what the code does: formatting, comments, docstrings and version stamps do not count.
    fingerprint: str
    facts: list[Fact]


class CodeReader:
    """Reads Python sources without running them.

    One run sees the same file up to four times (sdist, wheel, tag, old version), and parsing is
    what takes the time in a big package, so results are kept by content.
    """

    def __init__(self, versions: Collection[str]) -> None:
        self._versions = versions
        self._parsed: dict[bytes, ParsedCode | None] = {}
        self._facts: dict[bytes, list[Fact] | None] = {}

    def parse(self, source: bytes) -> ParsedCode | None:
        """What the code does, or None when it cannot be read."""
        key = content_key(source)
        if key not in self._parsed:
            self._parsed[key] = self._read(source, _parse_fully)
        return self._parsed[key]

    def facts(self, source: bytes) -> list[Fact] | None:
        """Only the facts, for code that is not compared as a whole: much cheaper than `parse`."""
        if not may_have_facts(source):
            return []
        key = content_key(source)
        if key in self._parsed:
            parsed = self._parsed[key]
            return None if parsed is None else parsed.facts
        if key not in self._facts:
            self._facts[key] = self._read(source, extract_facts)
        return self._facts[key]

    def _read[T](self, source: bytes, read: Callable[[ast.Module], T]) -> T | None:
        # Deep nesting that the parser accepts still overflows the tree walkers. It has to end
        # here, as an unreadable file: code is untrusted, and a crash would switch the analyzer off.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # Old code: invalid escapes and the like.
                tree = ast.parse(source)
            _normalize(tree, self._versions)
            return read(tree)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return None

    def text_fingerprint(self, source: bytes) -> str:
        for version in self._versions:
            source = source.replace(version.encode(), VERSION_PLACEHOLDER.encode())
        return _digest(b" ".join(source.split()))

    def fingerprint(self, path: str, source: bytes) -> str:
        parsed = self.parse(source) if path.endswith(".py") else None
        return self.text_fingerprint(source) if parsed is None else parsed.fingerprint


def content_key(source: bytes) -> bytes:
    return hashlib.blake2b(source, digest_size=16).digest()


def _parse_fully(tree: ast.Module) -> ParsedCode:
    return ParsedCode(_digest(ast.dump(tree).encode("utf-8", "replace")), extract_facts(tree))


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize(tree: ast.Module, versions: Collection[str]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, _DOCSTRING_OWNERS):
            if node.body and _is_docstring(node.body[0]):
                node.body = node.body[1:]
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            is_stamp = any(isinstance(t, ast.Name) and t.id in _VERSION_NAMES for t in targets)
            if is_stamp and isinstance(node.value, ast.Constant):
                node.value.value = VERSION_PLACEHOLDER
        elif isinstance(node, ast.Constant) and node.value in versions:
            node.value = VERSION_PLACEHOLDER


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )
