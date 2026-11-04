import ast

from pypi_monitor.analyzers.execution import import_time

MODULE = """import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import socket


def unused():
    os.system("a")


def helper():
    os.system("b")


def started():
    os.system("c")


class Hook:
    def __init__(self):
        os.system("d")

    def method(self):
        os.system("e")


helper()
threading.Thread(target=started).start()
HOOK = Hook()

if __name__ == "__main__":
    os.system("f")
else:
    os.system("g")
"""


def lines_that_run() -> set[int]:
    found = import_time(ast.parse(MODULE))
    return {number for number in range(1, MODULE.count("\n") + 1) if found.runs(number)}


def test_only_code_that_import_time_code_names_runs() -> None:
    runs = lines_that_run()
    source = MODULE.splitlines()
    executed = {source[number - 1].strip() for number in runs}

    assert {'os.system("b")', 'os.system("c")', 'os.system("d")', 'os.system("g")'} <= executed
    assert not {'os.system("a")', 'os.system("e")', 'os.system("f")', "import socket"} & executed


def test_imports_that_run_include_dynamic_ones_and_skip_type_checking() -> None:
    tree = ast.parse(
        "import a\nif TYPE_CHECKING:\n    import b\ndef f():\n    import c\n__import__('d')\n"
    )

    found = import_time(tree).imports

    names = [ast.unparse(node) for node in found]
    assert names == ["import a", "__import__('d')"]


def test_a_body_emptied_by_the_reader_is_fine() -> None:
    tree = ast.parse("def f():\n    pass\n")
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef)
    function.body = []  # What is left once a docstring is dropped.

    assert import_time(tree).runs(1)


def executed_calls(source: str) -> set[str]:
    found = import_time(ast.parse(source))
    lines = source.splitlines()
    return {
        lines[number - 1].strip()
        for number in range(1, len(lines) + 1)
        if found.runs(number) and "os.system" in lines[number - 1]
    }


def test_a_method_reached_through_its_class_runs() -> None:
    source = """import os


class C:
    def run(self):
        os.system("instance")
        self._helper()

    def _helper(self):
        os.system("helper")

    def idle(self):
        os.system("idle")


class H:
    @staticmethod
    def go():
        os.system("static")


class P:
    @property
    def value(self):
        os.system("property")


class Base:
    def inherited(self):
        os.system("inherited")


class Child(Base):
    pass


class Ctx:
    def __enter__(self):
        os.system("enter")

    def __exit__(self, *args):
        pass


class Callable:
    def __call__(self):
        os.system("call")


C().run()
H.go()
P().value
obj = Child()
obj.inherited()
with Ctx():
    pass
Callable()()
"""
    executed = executed_calls(source)

    assert executed == {
        f'os.system("{name}")'
        for name in ("instance", "helper", "static", "property", "inherited", "enter", "call")
    }


def test_a_method_nobody_reaches_does_not_run() -> None:
    source = """import os


class C:
    def run(self):
        os.system("never")


def unused():
    C().run()


C()
"""
    assert executed_calls(source) == set()
