"""Which code of a module runs when it is imported, read from its AST.

The answer is generous on purpose: a module-level statement runs, and so does a function or a
constructor that import-time code names, whether it calls it, registers it with `atexit` or starts
a thread with it. Payloads hide in exactly such helpers: `def _steal(): ...` and `_steal()` below.
What certainly does not run is a function nobody at the top level names, and the body of
`if __name__ == "__main__"` or `if TYPE_CHECKING`.
"""

import ast
import bisect
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TypeGuard

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BODY_FIELDS = frozenset({"body", "orelse", "finalbody", "handlers", "cases"})
_CONSTRUCTORS = frozenset({"__init__", "__new__", "__post_init__", "__init_subclass__"})
_DYNAMIC_IMPORTS = frozenset({"__import__", "import_module"})

ImportNode = ast.Import | ast.ImportFrom | ast.Call


@dataclass(frozen=True)
class ImportTime:
    # Function nodes of the very tree that was read: they compare by identity.
    executed: frozenset[ast.AST]
    # Sorted, disjoint line ranges that do not run on import.
    skipped: tuple[tuple[int, int], ...]
    # Imports that run on import: statements and `__import__("x")` calls with a literal name.
    imports: tuple[ImportNode, ...]
    # Bodies of `if __name__ == "__main__"` and the like, for walkers that track nodes.
    skipped_blocks: frozenset[ast.AST]

    def runs(self, line: int) -> bool:
        index = bisect.bisect_right(self.skipped, (line, float("inf"))) - 1
        return index < 0 or self.skipped[index][1] < line


def import_time(tree: ast.Module) -> ImportTime:
    return _Scan(tree).run()


def all_imports(tree: ast.Module) -> list[ImportNode]:
    """Every import of a module wherever it is: for code that pip runs as a whole, like setup.py."""
    return [node for node in ast.walk(tree) if _is_import(node)]


def is_dynamic_import(node: ast.Call) -> str | None:
    """The literal module name of `__import__("x")` or `importlib.import_module("x")`."""
    function = node.func
    name = function.id if isinstance(function, ast.Name) else None
    if isinstance(function, ast.Attribute):
        name = function.attr
    if name not in _DYNAMIC_IMPORTS or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value:
        return first.value
    return None


def _is_import(node: ast.AST) -> TypeGuard[ImportNode]:
    if isinstance(node, ast.Import | ast.ImportFrom):
        return True
    return isinstance(node, ast.Call) and is_dynamic_import(node) is not None


class _Scan:
    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self._classes: dict[str, list[ast.ClassDef]] = {}
        self._index(tree.body, in_class=False)
        self._executed: set[ast.AST] = set()
        self._skipped_blocks: list[ast.If] = []
        self._imports: list[ImportNode] = []

    def run(self) -> ImportTime:
        self._scan(self._tree.body)
        skipped = [
            node
            for node in ast.walk(self._tree)
            if isinstance(node, _FUNCTIONS) and node not in self._executed
        ]
        # A body may be empty: the reader drops docstrings before facts are read.
        ranges = [_body_range(node) for node in [*skipped, *self._skipped_blocks] if node.body]
        return ImportTime(
            frozenset(self._executed),
            tuple(_merged(ranges)),
            tuple(self._imports),
            frozenset(self._skipped_blocks),
        )

    def _index(self, body: list[ast.stmt], in_class: bool) -> None:
        """Functions by name, methods aside: `x()` at the top level never calls a method."""
        for statement in body:
            if isinstance(statement, _FUNCTIONS):
                if not in_class:
                    self._functions.setdefault(statement.name, []).append(statement)
                self._index(statement.body, in_class=False)
            elif isinstance(statement, ast.ClassDef):
                self._classes.setdefault(statement.name, []).append(statement)
                self._index(statement.body, in_class=True)
            else:
                for child in _bodies(statement):
                    self._index(child, in_class)

    def _scan(self, body: list[ast.stmt]) -> None:
        for statement in body:
            if isinstance(statement, _FUNCTIONS):
                # The definition runs: decorators and default values, not the body.
                self._names([*statement.decorator_list, statement.args])
            elif isinstance(statement, ast.ClassDef):
                self._names([*statement.decorator_list, *statement.bases, *statement.keywords])
                self._scan(statement.body)
            elif isinstance(statement, ast.If) and _never_on_import(statement.test):
                self._skipped_blocks.append(statement)
                self._scan(statement.orelse)
            elif isinstance(statement, ast.Import | ast.ImportFrom):
                self._imports.append(statement)
            else:
                bodies = list(_bodies(statement))
                self._names(_header(statement) if bodies else [statement])
                for child in bodies:
                    self._scan(child)

    def _names(self, nodes: list[ast.AST]) -> None:
        for root in nodes:
            for node in ast.walk(root):
                if isinstance(node, ast.Call) and is_dynamic_import(node) is not None:
                    self._imports.append(node)
                elif isinstance(node, ast.Name):
                    for function in self._functions.get(node.id, ()):
                        self._run(function)
                    for cls in self._classes.get(node.id, ()):
                        for member in cls.body:
                            if isinstance(member, _FUNCTIONS) and member.name in _CONSTRUCTORS:
                                self._run(member)

    def _run(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if function not in self._executed:
            self._executed.add(function)
            self._scan(function.body)


def _bodies(statement: ast.stmt) -> Iterator[list[ast.stmt]]:
    for field in ("body", "orelse", "finalbody"):
        value = getattr(statement, field, None)
        if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
            yield value
    for handler in getattr(statement, "handlers", None) or ():
        yield handler.body
    for case in getattr(statement, "cases", None) or ():
        yield case.body


def _header(statement: ast.stmt) -> list[ast.AST]:
    """What a compound statement evaluates itself: the test of an `if`, the items of a `with`."""
    nodes: list[ast.AST] = []
    for field, value in ast.iter_fields(statement):
        if field in _BODY_FIELDS:
            continue
        values = value if isinstance(value, list) else [value]
        nodes += [item for item in values if isinstance(item, ast.AST)]
    return nodes


def _never_on_import(test: ast.expr) -> bool:
    """`__name__ == "__main__"`, `TYPE_CHECKING` and `typing.TYPE_CHECKING`."""
    if isinstance(test, ast.Name | ast.Attribute):
        name = test.id if isinstance(test, ast.Name) else test.attr
        return name == "TYPE_CHECKING"
    if isinstance(test, ast.Compare) and len(test.comparators) == 1:
        sides = [test.left, test.comparators[0]]
        names = {side.id for side in sides if isinstance(side, ast.Name)}
        constants = {side.value for side in sides if isinstance(side, ast.Constant)}
        return names == {"__name__"} and constants == {"__main__"}
    return False


def _body_range(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.If) -> tuple[int, int]:
    return node.body[0].lineno, node.body[-1].end_lineno or node.body[-1].lineno


def _merged(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
