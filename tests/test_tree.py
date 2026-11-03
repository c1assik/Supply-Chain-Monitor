from pathlib import Path

import pytest

from pypi_monitor.analyzers.tree import (
    SDIST,
    WHEEL,
    CodeReader,
    Role,
    artifact_trees,
    installed_paths,
    role_of,
)


@pytest.mark.parametrize(
    ("path", "role"),
    [
        ("setup.py", Role.AUTORUN),
        ("pkg/__init__.py", Role.AUTORUN),
        ("src/pkg/__init__.py", Role.AUTORUN),
        ("evil.pth", Role.AUTORUN),
        ("pkg/sub/deep/__init__.py", Role.NORMAL),
        ("pkg/core.py", Role.NORMAL),
        ("pkg/setup.py", Role.NORMAL),
        ("tests/__init__.py", Role.NOISY),
        ("pkg/tests/test_core.py", Role.NOISY),
        ("pkg/_vendor/idna.py", Role.NOISY),
        ("pkg/_version.py", Role.NOISY),
        ("pkg/api_pb2.py", Role.NOISY),
        ("PKG-INFO", Role.IGNORED),
        ("pkg.egg-info/SOURCES.txt", Role.IGNORED),
        ("dist-info/RECORD", Role.IGNORED),
        ("dist-info/entry_points.txt", Role.NORMAL),
        ("data/purelib/pkg/__init__.py", Role.AUTORUN),
        ("data/platlib/evil.pth", Role.AUTORUN),
        ("data/purelib/pkg/core.py", Role.NORMAL),
        ("sitecustomize.py", Role.AUTORUN),
        ("src/usercustomize.py", Role.AUTORUN),
        ("pkg/sitecustomize.py", Role.NORMAL),
        ("tests/fixtures/setup.py", Role.NOISY),
    ],
)
def test_roles(path: str, role: Role) -> None:
    assert role_of(path) is role


def reader() -> CodeReader:
    return CodeReader({"1.0", "1.1"})


def code(source: str) -> str:
    parsed = reader().parse(source.encode())
    assert parsed is not None
    return parsed.fingerprint


def test_formatting_comments_and_docstrings_do_not_change_the_fingerprint() -> None:
    first = "def f(a, b):\n    return a + b\n"
    second = '# note\n"""Module."""\n\n\ndef f(a,\n      b):\n    """Doc."""\n    return (a + b)\n'
    assert code(first) == code(second)


def test_version_stamps_do_not_change_the_fingerprint() -> None:
    assert code('__version__ = "1.0"\nX = "1.0"\n') == code('__version__ = "1.1"\nX = "1.1"\n')
    assert code('__version__ = "0.0.0"\n') == code('__version__ = "1.1"\n')


def test_changed_code_changes_the_fingerprint() -> None:
    assert code("x = 1\n") != code("x = 2\n")
    assert code("f()\n") != code("f()\nexec(g())\n")


@pytest.mark.parametrize(
    "source",
    [
        b"def broken(:\n",
        b"a\0b",
        b"x = " + b"(" * 100_000,
        b"x = " + b"-" * 100_000 + b"1",
        b"x = 1" + b" + 1" * 50_000,
    ],
)
def test_hostile_code_does_not_crash_the_reader(source: bytes) -> None:
    reader().parse(source)


def test_unparseable_source_has_a_text_fingerprint() -> None:
    assert reader().fingerprint("a.py", b"print 'old'\n") == reader().fingerprint(
        "a.py", b"print   'old'\r\n"
    )


def test_trees_have_paths_without_versions(tmp_path: Path) -> None:
    for path in (
        "a-1.0.tar.gz/a-1.0/src/a/core.py",
        "a-1.0-py3-none-any.whl/a/core.py",
        "a-1.0-py3-none-any.whl/a-1.0.dist-info/entry_points.txt",
        "a-1.0-py3-none-any.whl/a-1.0.data/scripts/run",
    ):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).touch()

    trees = artifact_trees(tmp_path)

    assert set(trees[SDIST].files) == {"src/a/core.py"}
    assert set(trees[WHEEL].files) == {
        "a/core.py",
        "dist-info/entry_points.txt",
        "data/scripts/run",
    }
    assert trees[WHEEL].pure
    assert trees[SDIST].display("src/a/core.py") == "a-1.0.tar.gz/a-1.0/src/a/core.py"


def test_platform_wheel_is_not_pure(tmp_path: Path) -> None:
    (tmp_path / "a-1.0-cp313-cp313-win32.whl/a").mkdir(parents=True)

    assert not artifact_trees(tmp_path)[WHEEL].pure


def test_wheel_tells_which_sdist_files_are_installed(tmp_path: Path) -> None:
    for path in (
        "a-1.0.tar.gz/a-1.0/src/a/core.py",
        "a-1.0.tar.gz/a-1.0/setup.py",
        "a-1.0.tar.gz/a-1.0/ci/release.py",
        "a-1.0-py3-none-any.whl/a/core.py",
    ):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).touch()
    trees = artifact_trees(tmp_path)

    assert installed_paths(trees[SDIST], trees[WHEEL]) == {"src/a/core.py", "setup.py"}
    assert installed_paths(trees[SDIST], None) is None


def test_facts_alone_agree_with_a_full_parse() -> None:
    source = b"import base64\nexec(base64.b64decode(x))\n"
    parsed = reader().parse(source)

    assert parsed is not None
    assert reader().facts(source) == parsed.facts


def test_facts_of_a_source_that_cannot_be_read() -> None:
    assert reader().facts(b"import socket\ndef broken(:\n") is None


def test_wheel_install_schemes_are_compared_where_pip_puts_them(tmp_path: Path) -> None:
    archive = tmp_path / "a-1.0-py3-none-any.whl"
    for path in ("a/core.py", "a-1.0.data/purelib/a/__init__.py", "a-1.0.data/platlib/a/core.py"):
        (archive / path).parent.mkdir(parents=True, exist_ok=True)
        (archive / path).write_text("x = 1\n")

    files = artifact_trees(tmp_path)[WHEEL].files

    # A clash keeps both files: the one at the root keeps its name.
    assert set(files) == {"a/__init__.py", "a/core.py", "data/platlib/a/core.py"}
    assert files["a/core.py"] == archive / "a/core.py"


def test_a_function_of_a_docstring_alone_is_read() -> None:
    assert reader().facts(b'import os\ndef f():\n    """Doc."""\nos.system("x")\n')


@pytest.mark.parametrize(
    ("tags", "pure"),
    [("Tag: py3-none-any\n", True), ("Tag: cp313-cp313-manylinux_2_17_x86_64\n", False)],
)
def test_wheel_purity_comes_from_its_tags(tags: str, pure: bool, tmp_path: Path) -> None:
    # Copies of a wheel, as in the benchmark corpus, may carry any file name.
    archive = tmp_path / "a-1.0-py3-none-any.whl"
    (archive / "a-1.0.dist-info").mkdir(parents=True)
    (archive / "a-1.0.dist-info/WHEEL").write_text(f"Wheel-Version: 1.0\n{tags}")

    assert artifact_trees(tmp_path)[WHEEL].pure is pure
