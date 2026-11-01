from pathlib import Path

from pypi_monitor.analyzers.base import ReleaseContext, Signal
from pypi_monitor.analyzers.consistency import ConsistencyAnalyzer
from pypi_monitor.domain import Severity

Files = dict[str, str]
WHEEL = "a-1.0-py3-none-any.whl"


def write(root: Path, files: Files) -> None:
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)


def compare(
    tmp_path: Path,
    sdist: Files | None = None,
    wheel: Files | None = None,
    tag: Files | None = None,
    wheel_name: str = WHEEL,
) -> list[Signal]:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    if sdist is not None:
        write(artifacts / "a-1.0.tar.gz" / "a-1.0", sdist)
    if wheel is not None:
        write(artifacts / wheel_name, wheel)
    if tag is not None:
        write(tmp_path / "repository" / "tag.tar.gz" / "a-1.0", tag)
    return ConsistencyAnalyzer().analyze(
        ReleaseContext(
            name="a",
            version="1.0",
            artifact_dir=artifacts,
            repository_dir=tmp_path / "repository" if tag is not None else None,
        )
    )


def rules(signals: list[Signal]) -> list[str]:
    return [signal.rule_id for signal in signals]


def test_wheel_built_from_the_sdist_is_consistent(tmp_path: Path) -> None:
    sdist = {"src/a/__init__.py": "X = 1\n", "src/a/core.py": "# Comment.\nY = 2\n"}
    wheel = {"a/__init__.py": "X = 1\n", "a/core.py": "Y = 2\n", "a-1.0.dist-info/RECORD": "x"}

    assert compare(tmp_path, sdist, wheel) == []


def test_code_only_in_the_wheel(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"a/__init__.py": "X = 1\n"},
        {"a/__init__.py": "X = 1\n", "a/evil.py": "exec(x)\n"},
    )

    assert rules(signals) == ["consistency.wheel_code_missing"]
    assert signals[0].file_path == f"{WHEEL}/a/evil.py"


def test_wheel_code_differs_from_the_sdist(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"a/__init__.py": "X = 1\n"},
        {"a/__init__.py": "X = 1\nexec(x)\n"},
    )

    assert rules(signals) == ["consistency.wheel_code_differs"]
    assert signals[0].severity is Severity.HIGH
    assert signals[0].confidence == 0.8


def test_platform_wheel_is_trusted_less_because_builds_generate_code(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"a/core.py": "X = 1\n"},
        {"a/core.py": "X = 2\n"},
        wheel_name="a-1.0-cp313-cp313-win32.whl",
    )

    assert [signal.confidence for signal in signals] == [0.3]


def test_generated_and_test_files_may_differ(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"a/core.py": "X = 1\n"},
        {"a/core.py": "X = 1\n", "a/_version.py": "v = 1\n", "a/tests/test_a.py": "Y = 1\n"},
    )

    assert signals == []


def test_package_mapped_to_another_directory_is_found_by_content(tmp_path: Path) -> None:
    signals = compare(tmp_path, {"lib/core.py": "X = 1\n"}, {"a/core.py": "X = 1\n"})

    assert signals == []


def test_sdist_matching_the_tag(tmp_path: Path) -> None:
    sdist = {"setup.py": "setup()\n", "a/core.py": "X = 1\n"}

    assert compare(tmp_path, sdist, tag={"setup.py": "setup()\n", "a/core.py": "X = 1\n"}) == []


def test_sdist_differing_from_the_tag(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"setup.py": "import os\nos.system('x')\nsetup()\n", "a/core.py": "X = 1\n"},
        tag={"setup.py": "setup()\n", "a/core.py": "X = 1\n"},
    )

    assert rules(signals) == ["consistency.tag_code_differs"]
    assert signals[0].confidence == 0.8


def test_sdist_code_missing_from_the_tag(tmp_path: Path) -> None:
    signals = compare(
        tmp_path, {"a/core.py": "X = 1\n", "a/evil.py": "Y = 1\n"}, tag={"a/core.py": "X = 1\n"}
    )

    assert rules(signals) == ["consistency.tag_code_missing"]


def test_monorepo_layout(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"src/a/core.py": "X = 2\n"},
        tag={"libs/a/src/a/core.py": "X = 1\n", "libs/b/core.py": "Y = 1\n"},
    )

    assert signals[0].evidence == "code differs from libs/a/src/a/core.py"


def test_same_name_elsewhere_is_not_a_counterpart(tmp_path: Path) -> None:
    signals = compare(tmp_path, {"tests/__init__.py": "\n"}, {"a/__init__.py": "X = 1\n"})

    assert rules(signals) == ["consistency.wheel_code_missing"]


def test_sdist_files_that_are_not_installed_are_not_compared_with_the_tag(tmp_path: Path) -> None:
    signals = compare(
        tmp_path,
        {"a/core.py": "X = 1\n", "third/build/gen.py": "Y = 1\n"},
        {"a/core.py": "X = 1\n"},
        tag={"a/core.py": "X = 1\n"},
    )

    assert signals == []


def test_wheel_only_release_is_compared_with_the_tag(tmp_path: Path) -> None:
    signals = compare(tmp_path, wheel={"a/core.py": "X = 2\n"}, tag={"src/a/core.py": "X = 1\n"})

    assert rules(signals) == ["consistency.tag_code_differs"]
