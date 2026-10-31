from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from pypi_monitor.analyzers import ReleaseContext
from pypi_monitor.analyzers.metadata import MetadataAnalyzer
from pypi_monitor.analyzers.typosquat import TyposquatDetector

TOP = {
    "boto3": 1,
    "requests": 2,
    "urllib3": 3,
    "python-dateutil": 4,
    "typing-extensions": 5,
    "numpy": 6,
    "attrs": 7,
}
README = "x" * 200
REPO = {"Source": "https://github.com/someone/project"}


def rules(name: str, metadata: dict[str, Any], artifact_dir: Path | None = None) -> set[str]:
    context = ReleaseContext(name=name, version="1", metadata=metadata, artifact_dir=artifact_dir)
    return {signal.rule_id for signal in MetadataAnalyzer(TOP).analyze(context)}


def info(**overrides: Any) -> dict[str, Any]:
    return {"info": {"description": README, "project_urls": REPO} | overrides}


@pytest.mark.parametrize(
    ("name", "target", "technique"),
    [
        ("reqeusts", "requests", "edit distance"),  # transposition
        ("requets", "requests", "edit distance"),  # deletion
        ("requestss", "requests", "edit distance"),  # insertion
        ("typing-extensionz", "typing-extensions", "edit distance"),
        ("python-dateutils", "python-dateutil", "edit distance"),
        ("pythondateutil", "python-dateutil", "separators"),
        ("dateutil-python", "python-dateutil", "token order"),
        ("requests-py", "requests", "affix"),
        ("python-requests", "requests", "affix"),
        ("requests2", "requests", "affix"),
    ],
)
def test_typosquats_of_top_packages_are_found(name: str, target: str, technique: str) -> None:
    match = TyposquatDetector(TOP).find(name)

    assert match is not None
    assert (match.target, match.technique) == (target, technique)


@pytest.mark.parametrize(
    "name", ["requests", "numpy", "flask", "my-awesome-project", "attr", "boto4"]
)
def test_unrelated_names_are_not_typosquats(name: str) -> None:
    assert TyposquatDetector(TOP).find(name) is None


@pytest.mark.parametrize("name", ["django-crm", "django-cfg"])
def test_siblings_in_a_namespace_are_not_typosquats(name: str) -> None:
    assert TyposquatDetector({"django-csp": 1}).find(name) is None


def test_typosquat_gives_a_signal_with_the_target() -> None:
    context = ReleaseContext(name="reqeusts", version="1", metadata=info())

    signal = next(iter(MetadataAnalyzer(TOP).analyze(context)))

    assert signal.rule_id == "metadata.typosquat"
    assert "requests" in signal.evidence


def test_well_formed_old_package_is_silent() -> None:
    assert rules("my-project", info() | {"first_upload": "2020-01-01T00:00:00+00:00"}) == set()


def test_young_package_is_flagged() -> None:
    first_upload = (datetime.now(UTC) - timedelta(hours=2)).isoformat()

    assert rules("my-project", info() | {"first_upload": first_upload}) == {"metadata.new_package"}


def test_owner_without_other_packages_is_flagged() -> None:
    metadata = info() | {"owner_package_counts": {"mallory": 1}}

    assert rules("my-project", metadata) == {"metadata.first_account_release"}
    metadata["owner_package_counts"] = {"mallory": 1, "alice": 30}
    assert rules("my-project", metadata) == set()


def test_empty_profile_is_flagged() -> None:
    metadata = {"info": {"description": "", "project_urls": None, "home_page": None}}

    assert rules("my-project", metadata) == {"metadata.empty_readme", "metadata.no_repository"}


def test_link_to_a_popular_repository_of_someone_else_is_flagged() -> None:
    metadata = info(project_urls={"Homepage": "https://github.com/psf/requests"})

    assert rules("my-project", metadata) == {"metadata.foreign_repository"}
    assert rules("requests", metadata) == set()


def test_sdist_only_with_logic_in_setup_py_is_flagged(tmp_path: Path) -> None:
    setup_py = tmp_path / "foo-1.tar.gz/foo-1/setup.py"
    setup_py.parent.mkdir(parents=True)
    setup_py.write_text("import socket\nfrom setuptools import setup\nsetup()")
    metadata = info() | {"urls": [{"packagetype": "sdist"}]}

    assert rules("foo", metadata, tmp_path) == {"metadata.sdist_only_setup_logic"}

    setup_py.write_text("from setuptools import setup\nsetup(name='foo')")
    assert rules("foo", metadata, tmp_path) == set()

    setup_py.write_text("import socket")
    wheel = info() | {"urls": [{"packagetype": "sdist"}, {"packagetype": "bdist_wheel"}]}
    assert rules("foo", wheel, tmp_path) == set()
