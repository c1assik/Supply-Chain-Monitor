"""Which code of a module runs when it is imported, read from its AST.

The answer is generous on purpose: a module-level statement runs, and so does a function or a
constructor that import-time code names, whether it calls it, registers it with `atexit` or starts
a thread with it. Payloads hide in exactly such helpers: `def _steal(): ...` and `_steal()` below.
A method runs once import-time code reaches it through its class: `C().run()`, `C.go()`, a
property read as `C().value`, `obj = C()` and then `obj.run()`, and `self.helper()` inside a method
that runs. Methods are looked up in the bases defined in the same module too.
What certainly does not run is a function nobody at the top level names, and the body of
`if __name__ == "__main__"` or `if TYPE_CHECKING`.
"""

import ast
import bisect
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TypeGuard

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BODY_FIELDS = frozenset({"body", "orelse", "finalbody", "handlers", "cases"})
_CONSTRUCTORS = frozenset({"__init__", "__new__", "__post_init__", "__init_subclass__"})
# What `with C():` runs besides the constructor.
_CONTEXT_METHODS = ("__enter__", "__exit__", "__aenter__", "__aexit__")
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


def dynamic_import_package(node: ast.Call) -> str | None:
    """What `package=` of `import_module(".x", package)` names, the way the module spells it.

    A literal string is returned as is; `__name__`, `__package__` and `__spec__.parent` come back
    as these names, for the caller to resolve against the module that holds the call.
    """
    argument = node.args[1] if len(node.args) > 1 else None
    for keyword in node.keywords:
        if keyword.arg == "package":
            argument = keyword.value
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value or None
    if isinstance(argument, ast.Name) and argument.id in ("__name__", "__package__"):
        return argument.id
    if (
        isinstance(argument, ast.Attribute)
        and argument.attr == "parent"
        and isinstance(argument.value, ast.Name)
        and argument.value.id == "__spec__"
    ):
        return "__package__"
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
        # `obj = C()` anywhere: `obj.run()` is then a method of C. Names are not scoped, which errs
        # towards running more.
        self._instances: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            self._note_instance(node)
        self._executed: set[ast.AST] = set()
        # The class whose method is being scanned: `self.x` and `cls.x` there are its members.
        self._owner: ast.ClassDef | None = None
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
                if isinstance(statement, ast.With | ast.AsyncWith):
                    for item in statement.items:
                        for cls in self._classes_of(item.context_expr):
                            self._run_members(cls, _CONTEXT_METHODS)
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
                        self._run_members(cls, _CONSTRUCTORS)
                elif isinstance(node, ast.Attribute):
                    for cls in self._classes_of(node.value):
                        self._run_members(cls, (node.attr,))
                if isinstance(node, ast.Call):
                    # `C()()` and `obj()` run `__call__`; `C()` alone is the constructor above.
                    for cls in self._called_instances(node.func):
                        self._run_members(cls, ("__call__",))

    def _note_instance(self, node: ast.AST) -> None:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            return
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)):
            return
        if value.func.id not in self._classes:
            return
        for target in targets:
            if isinstance(target, ast.Name):
                self._instances.setdefault(target.id, set()).add(value.func.id)

    def _classes_of(self, node: ast.AST) -> list[ast.ClassDef]:
        """Classes whose members `node.x` may name: `C`, `C(...)`, an instance, `self`."""
        if isinstance(node, ast.Call):
            node = node.func
        if not isinstance(node, ast.Name):
            return []
        found = list(self._classes.get(node.id, ()))
        for cls_name in self._instances.get(node.id, ()):
            found += self._classes.get(cls_name, ())
        if node.id in ("self", "cls") and self._owner is not None:
            found.append(self._owner)
        return found

    def _called_instances(self, function: ast.expr) -> list[ast.ClassDef]:
        if isinstance(function, ast.Call) and isinstance(function.func, ast.Name):
            return list(self._classes.get(function.func.id, ()))
        if isinstance(function, ast.Name):
            names = self._instances.get(function.id, ())
            return [cls for name in names for cls in self._classes.get(name, ())]
        return []

    def _run_members(self, cls: ast.ClassDef, names: Iterable[str]) -> None:
        wanted = set(names)
        for owner in self._lineage(cls):
            for member in owner.body:
                if isinstance(member, _FUNCTIONS) and member.name in wanted:
                    self._run(member, owner)

    def _lineage(self, cls: ast.ClassDef) -> Iterator[ast.ClassDef]:
        """The class and its bases that the module defines, each once."""
        seen: set[ast.ClassDef] = set()
        pending = [cls]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            yield current
            for base in current.bases:
                if isinstance(base, ast.Name):
                    pending += self._classes.get(base.id, ())

    def _run(
        self, function: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None = None
    ) -> None:
        if function in self._executed:
            return
        self._executed.add(function)
        outer, self._owner = self._owner, owner
        try:
            self._scan(function.body)
        finally:
            self._owner = outer


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
