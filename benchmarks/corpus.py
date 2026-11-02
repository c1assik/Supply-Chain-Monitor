"""The labelled corpus of the quality benchmark: real malware against ordinary releases.

Positives come from DataDog's malicious-software-packages-dataset, negatives from the frozen list
in `benchmarks/data/negatives.json`. Malware is live: it is unpacked with the same limits as in
production, read as data, and never installed, imported or executed.

A sample is brought to the layout of a production artifact, because analyzers look at the depth of
a path. Whatever could tell the classes apart other than the code is dropped: dataset samples carry
a `package_info-*.json` that negatives do not have, and only PKG-INFO is read on both sides.
"""

import hashlib
import json
import shutil
import subprocess  # Runs git with fixed arguments.
from dataclasses import asdict, dataclass
from email.parser import BytesHeaderParser, BytesParser
from email.policy import compat32
from enum import StrEnum
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from pypi_monitor.settings import Settings

DATASET_URL = "https://github.com/DataDog/malicious-software-packages-dataset.git"
# The corpus is fixed: new samples must not move the metrics of an unchanged rule set.
DATASET_COMMIT = "3fc8a1ff23fadb612234526e31a60e24bbc0bb3e"
SAMPLES_DIR = "samples/pypi"
ARCHIVE_PASSWORD = b"infected"
DATA_DIR = Path(".benchmark")
NEGATIVES_FILE = Path("benchmarks/data/negatives.json")
TOP_PACKAGES_FILE = Path("benchmarks/data/top_packages.json")
# Weights are tuned on the past and checked on the future, as they would be used.
FIRST_TEST_YEAR = 2025
# Negatives have no discovery date, so they are split by a hash of the name: every percent below
# this goes to training.
NEGATIVE_TRAIN_PERCENT = 70
# Bump when samples are prepared differently: old scans must not pass for new ones.
CORPUS_VERSION = 2

_PROJECT_FILES = ("setup.py", "pyproject.toml", "setup.cfg", "PKG-INFO")


class Split(StrEnum):
    TRAIN = "train"
    TEST = "test"


class Group(StrEnum):
    MALICIOUS = "malicious"
    COMPROMISED = "compromised"
    RANDOM = "random"
    POPULAR = "popular"


@dataclass(frozen=True)
class Sample:
    id: str
    name: str
    version: str
    group: Group
    split: Split
    # Relative to the data directory.
    path: str
    # Known for negatives only: dataset archives are pinned by the commit.
    sha256: str | None = None
    url: str | None = None

    @property
    def malicious(self) -> bool:
        return self.group in (Group.MALICIOUS, Group.COMPROMISED)


def fetch_dataset(data_dir: Path) -> Path:
    """Fetch the PyPI samples at the pinned commit, leaving the rest of the dataset alone."""
    target = data_dir / "dataset"
    if (target / SAMPLES_DIR).is_dir():
        return target
    target.mkdir(parents=True, exist_ok=True)
    for command in (
        ["init", "--quiet"],
        ["remote", "add", "origin", DATASET_URL],
        ["sparse-checkout", "set", "--no-cone", f"/{SAMPLES_DIR}/"],
        ["fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", DATASET_COMMIT],
        ["checkout", "--quiet", "FETCH_HEAD"],
    ):
        subprocess.run(["git", "-C", str(target), *command], check=True)  # noqa: S603, S607
    return target


def positives(data_dir: Path) -> list[Sample]:
    root = data_dir / "dataset" / SAMPLES_DIR
    return [_positive(path, data_dir) for path in sorted(root.rglob("*.zip"))]


def _positive(path: Path, data_dir: Path) -> Sample:
    """`<kind>/<name>/[<version>/]<yyyy-mm-dd>-<name>[-v<version>].zip`."""
    parts = path.relative_to(data_dir / "dataset" / SAMPLES_DIR).parts
    kind, name = parts[0], parts[1]
    version = parts[2] if len(parts) == 4 else ""
    return Sample(
        id=f"{kind}/{name}/{version or path.stem}",
        name=name,
        version=version,
        group=Group.COMPROMISED if kind == "compromised_lib" else Group.MALICIOUS,
        # The date in the name is the discovery date, close enough to tell the years apart.
        split=Split.TRAIN if int(path.name[:4]) < FIRST_TEST_YEAR else Split.TEST,
        path=str(path.relative_to(data_dir)),
    )


def negatives(limit: int | None = None) -> list[Sample]:
    """The frozen negatives; `limit` takes a stable part of each group for a quick run."""
    rows = json.loads(NEGATIVES_FILE.read_text(encoding="utf-8"))
    samples = [_negative(row) for row in rows]
    if limit is None:
        return samples
    chosen: list[Sample] = []
    for group in (Group.RANDOM, Group.POPULAR):
        members = [sample for sample in samples if sample.group is group]
        chosen += sorted(members, key=lambda sample: _hash(sample.id))[:limit]
    return chosen


def _negative(row: dict[str, Any]) -> Sample:
    name = canonicalize_name(row["name"])
    train = int(_hash(name), 16) % 100 < NEGATIVE_TRAIN_PERCENT
    return Sample(
        id=f"{row['group']}/{name}/{row['version']}",
        name=row["name"],
        version=row["version"],
        group=Group(row["group"]),
        split=Split.TRAIN if train else Split.TEST,
        path=f"negatives/{row['filename']}",
        sha256=row["sha256"],
        url=row["url"],
    )


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def top_packages() -> dict[str, int]:
    names = json.loads(TOP_PACKAGES_FILE.read_text(encoding="utf-8"))
    return {canonicalize_name(name): rank for rank, name in enumerate(names, start=1)}


def fingerprint(analyzer_versions: dict[str, str], samples: list[Sample]) -> str:
    """Name of a results file: scans can be reused while nothing that decides them has changed."""
    material = json.dumps(
        {
            "analyzers": analyzer_versions,
            "corpus": CORPUS_VERSION,
            "samples": [asdict(sample) for sample in samples],
        },
        sort_keys=True,
    )
    return _hash(material)[:16]


def default_limit(field: str) -> int:
    """A production unpack limit; settings as a whole need secrets the benchmark does not have."""
    value = Settings.model_fields[field].default
    assert isinstance(value, int)  # noqa: S101
    return value


def _depth_of(path: Path, top: Path) -> int:
    return len(path.relative_to(top).parts)


def project_roots(top: Path) -> list[tuple[Path, bool]]:
    """Find the projects of an unpacked sample: each directory, and whether it is a built wheel.

    Dataset samples sit under arbitrary prefixes such as `tmp/tmpnk51bv_5/quicly/quicly-1.1.16`,
    and some hold two artifacts, like `sources/<name>` next to an unpacked wheel. A project inside
    another one is its fixture or vendored code.
    """
    wheels = {path.parent for path in top.rglob("*.dist-info") if path.is_dir()}
    sources = {
        path.parent for path in top.rglob("*") if path.is_file() and path.name in _PROJECT_FILES
    }
    found = sorted(wheels | sources, key=lambda path: (_depth_of(path, top), str(path)))
    outermost: list[Path] = []
    for path in found:
        if not any(path.is_relative_to(root) for root in outermost):
            outermost.append(path)
    if outermost:
        return [(path, path in wheels) for path in outermost]
    root = top
    while True:
        entries = list(root.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            return [(root, False)]
        root = entries[0]


def _repair_doubled_paths(root: Path) -> None:
    """Undo a dataset quirk: wheels unpacked so that `a/b.py` became `a/b.py/a/b.py`."""
    for path in [path for path in root.rglob("*") if path.is_file()]:
        parts = path.relative_to(root).parts
        half = len(parts) // 2
        if not half or len(parts) % 2 or parts[:half] != parts[half:]:
            continue
        target = root.joinpath(*parts[:half])
        # A real `pkg/pkg` file has neighbours; a directory made of a file name has none.
        if sum(item.is_file() for item in target.rglob("*")) != 1:
            continue
        moved = root / f".repaired-{hashlib.sha256(str(path).encode()).hexdigest()}"
        path.rename(moved)
        shutil.rmtree(target)
        moved.rename(target)


def normalize_layout(unpacked: Path, artifact_dir: Path, name: str, version: str) -> None:
    """Move a sample to `<artifact_dir>/<archive>/...`, the layout of a production artifact."""
    stem = f"{canonicalize_name(name)}-{version or '0'}"
    for index, (root, wheel) in enumerate(project_roots(unpacked)):
        unique = f"{stem}-{index}" if index else stem
        if wheel:
            target = artifact_dir / f"{unique}-py3-none-any.whl"
        else:
            target = artifact_dir / f"{unique}.tar.gz" / unique
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(root, target)
        _repair_doubled_paths(target)
        for leak in target.rglob("package_info-*.json"):
            leak.unlink()


def metadata_of(artifact_dir: Path) -> dict[str, Any]:
    """PyPI-like metadata from the artifact itself.

    Upload dates, owners and the file list exist for negatives only, and giving them to one class
    would hand the label to the score. So signals built on those are out of this benchmark.
    """
    candidates = sorted(
        (
            path
            for pattern in ("PKG-INFO", "METADATA")
            for path in artifact_dir.rglob(pattern)
            if path.is_file()
        ),
        key=lambda path: _depth_of(path, artifact_dir),
    )
    if not candidates:
        return {"info": {}}
    with candidates[0].open("rb") as file:
        message = BytesParser(policy=compat32).parse(file)
    with candidates[0].open("rb") as file:
        headers = BytesHeaderParser(policy=compat32).parse(file)
    urls = {}
    for value in headers.get_all("Project-URL", []):
        label, _, url = str(value).partition(",")
        urls[label.strip()] = url.strip()
    payload = message.get_payload()
    body = payload if isinstance(payload, str) else ""
    description = body.strip() or str(headers.get("Description", ""))
    return {
        "info": {
            "description": "" if description == "UNKNOWN" else description,
            "home_page": str(headers.get("Home-page", "")),
            "project_urls": urls,
        }
    }
