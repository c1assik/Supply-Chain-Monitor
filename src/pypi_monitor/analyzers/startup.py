"""Code that runs by itself: what pip and Python start, and every module that imports at load.

`setup.py`, `.pth` files, `sitecustomize` and a top-level `__init__.py` run on install or import.
Malware rarely stops there: `__init__.py` says `from ._core import init`, and the payload sits at
the top of `_core.py`. So the graph follows module-level imports, relative ones included, from
these roots, and a reached module counts as running by itself in its import-time lines.
"""

import ast
import re
import warnings
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath

from pypi_monitor.analyzers.execution import (
    ImportNode,
    ImportTime,
    all_imports,
    dynamic_import_package,
    import_time,
    is_dynamic_import,
)
from pypi_monitor.analyzers.tree import Role, Tree, read_source, role_of

# A big framework imports hundreds of modules on start; past this the rest are not followed.
MAX_REACHED_MODULES = 3000
_PTH_IMPORT = re.compile(r"^import[ \t]+([\w. \t,]+)", re.MULTILINE)
# Projects that keep their package next to a pyproject.toml somewhere down an sdist.
_PROJECT_FILES = ("setup.py", "pyproject.toml")


@dataclass(frozen=True)
class _Module:
    name: str
    is_package: bool


@dataclass(frozen=True)
class _Reached:
    # None for a file that cannot be read: it is still on the way, but says nothing.
    import_time: ImportTime | None
    # pip runs setup.py as a whole: a function there is no less install code than the top level.
    whole: bool


class StartupCode:
    """Which files of a tree run by themselves, and which of their lines do."""

    def __init__(self, tree: Tree) -> None:
        self._tree = tree
        self._reached: dict[str, _Reached] | None = None

    def reaches(self, path: str) -> bool:
        return path in self._graph()

    def runs_at_import(self, path: str, line: int | None) -> bool:
        """A line of `path` runs on install or import. Without a line, any import-time code does."""
        reached = self._graph().get(path)
        if reached is None:
            return False
        if reached.whole or line is None:
            return True
        return reached.import_time is not None and reached.import_time.runs(line)

    def _graph(self) -> dict[str, _Reached]:
        if self._reached is None:
            self._reached = _walk(self._tree)
        return self._reached


def _walk(tree: Tree) -> dict[str, _Reached]:
    modules, paths = _modules(tree)
    roots = [path for path in tree.files if path.endswith(".py") and role_of(path) is Role.AUTORUN]
    queue = deque(roots)
    for path in tree.files:
        if path.endswith(".pth") and role_of(path) is Role.AUTORUN:
            queue += _pth_targets(tree, path, paths)
    reached: dict[str, _Reached] = {}
    while queue and len(reached) < MAX_REACHED_MODULES:
        path = queue.popleft()
        if path in reached:
            continue
        whole = PurePosixPath(path).name == "setup.py" and path in roots
        parsed = _parse(tree, path)
        if parsed is None:
            reached[path] = _Reached(None, whole)
            continue
        found = import_time(parsed)
        reached[path] = _Reached(found, whole)
        imports = all_imports(parsed) if whole else found.imports
        module = modules.get(path)
        for target in _targets(module, imports):
            queue += paths.get(target, ())
    return reached


def _parse(tree: Tree, path: str) -> ast.Module | None:
    source = read_source(tree.files[path])
    if source is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _modules(tree: Tree) -> tuple[dict[str, _Module], dict[str, list[str]]]:
    """Module of each file, and files of each module name: an sdist may hold a package twice."""
    roots = _import_roots(tree)
    by_path: dict[str, _Module] = {}
    by_name: dict[str, list[str]] = {}
    for path in tree.files:
        if not path.endswith(".py") or role_of(path) is Role.IGNORED:
            continue
        module = _module_of(path, roots)
        if module is not None:
            by_path[path] = module
            by_name.setdefault(module.name, []).append(path)
    return by_path, by_name


def _import_roots(tree: Tree) -> list[str]:
    """Directories that sys.path would point at once the code is installed, deepest first."""
    projects = {
        str(PurePosixPath(path).parent)
        for path in tree.files
        if PurePosixPath(path).name in _PROJECT_FILES
    }
    projects = {"" if project == "." else f"{project}/" for project in projects} | {""}
    roots = projects | {f"{project}src/" for project in projects}
    return sorted(roots, key=len, reverse=True)


def _module_of(path: str, roots: list[str]) -> _Module | None:
    root = next(root for root in roots if path.startswith(root))
    parts = PurePosixPath(path[len(root) :]).with_suffix("").parts
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    if parts[-1] == "__init__":
        return _Module(".".join(parts[:-1]), True) if len(parts) > 1 else None
    return _Module(".".join(parts), False)


def _pth_targets(tree: Tree, path: str, paths: dict[str, list[str]]) -> Iterator[str]:
    source = read_source(tree.files[path]) or b""
    for match in _PTH_IMPORT.finditer(source.decode("utf-8", "replace")):
        for name in match[1].split(","):
            for module in _prefixes(name.strip().split()[0] if name.strip() else ""):
                yield from paths.get(module, ())


def _targets(module: _Module | None, imports: Iterable[ImportNode]) -> Iterator[str]:
    """Modules that an import runs: `import a.b.c` runs `a`, `a.b` and `a.b.c`."""
    for node in imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield from _prefixes(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = _absolute(module, node)
            if base is None:
                continue
            yield from _prefixes(base)
            # `from pkg import name` imports the submodule when there is one.
            for alias in node.names:
                if alias.name != "*":
                    yield f"{base}.{alias.name}" if base else alias.name
        else:
            name = is_dynamic_import(node)
            if name is not None and name.startswith("."):
                name = _relative_dynamic(module, name, dynamic_import_package(node))
            if name is not None:
                yield from _prefixes(name)


def _relative_dynamic(module: _Module | None, name: str, package: str | None) -> str | None:
    """`import_module("._core", __name__)` the way importlib resolves it."""
    if package in ("__name__", "__package__"):
        if module is None:
            return None
        if package == "__package__" and not module.is_package:
            package = module.name.rpartition(".")[0]
        else:
            package = module.name
    if not package:
        return None
    rest = name.lstrip(".")
    level = len(name) - len(rest)
    bits = package.rsplit(".", level - 1)
    if len(bits) < level:
        return None
    return f"{bits[0]}.{rest}" if rest else bits[0]


def _absolute(module: _Module | None, node: ast.ImportFrom) -> str | None:
    if not node.level:
        return node.module
    if module is None:
        return None
    package = module.name.split(".") if module.is_package else module.name.split(".")[:-1]
    if node.level - 1 > len(package):
        return None
    base = package[: len(package) - (node.level - 1)]
    return ".".join([*base, *([node.module] if node.module else [])])


def _prefixes(name: str) -> Iterator[str]:
    parts = name.split(".")
    for end in range(1, len(parts) + 1):
        if all(parts[:end]):
            yield ".".join(parts[:end])
