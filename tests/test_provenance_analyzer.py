from typing import Any

from pypi_monitor.analyzers import ReleaseContext
from pypi_monitor.analyzers.base import Signal
from pypi_monitor.analyzers.provenance import ProvenanceAnalyzer
from pypi_monitor.domain import Severity

GITHUB = {"kind": "GitHub", "repository": "acme/lib", "workflow": "release.yml", "environment": ""}


def analyze(previous: dict[str, Any] | None, types: list[str], *files: Any) -> list[Signal]:
    snapshot = {
        "previous_publisher": previous,
        "previous_attested_types": types,
        "files": [
            {"filename": name, "packagetype": kind, "publisher": publisher}
            for name, kind, publisher in files
        ],
    }
    context = ReleaseContext(name="lib", version="1.1", metadata={"provenance": snapshot})
    return ProvenanceAnalyzer().analyze(context)


def rules(signals: list[Signal]) -> list[str]:
    return [signal.rule_id for signal in signals]


def test_same_publisher_is_quiet() -> None:
    assert analyze(GITHUB, ["sdist"], ("lib-1.1.tar.gz", "sdist", GITHUB)) == []


def test_lost_attestations_are_a_signal_once() -> None:
    signals = analyze(
        GITHUB,
        ["sdist", "bdist_wheel"],
        ("lib-1.1.tar.gz", "sdist", None),
        ("lib-1.1-py3-none-any.whl", "bdist_wheel", None),
    )

    assert rules(signals) == ["provenance.attestations_dropped"]
    assert signals[0].severity is Severity.HIGH
    assert "acme/lib" in signals[0].evidence


def test_a_kind_of_file_that_never_had_attestations_is_not_compared() -> None:
    assert analyze(GITHUB, ["sdist"], ("lib-1.1-cp313-x.whl", "bdist_wheel", None)) == []


def test_another_repository_or_another_job() -> None:
    other = {**GITHUB, "repository": "mallory/lib"}
    renamed = {**GITHUB, "workflow": "publish.yml"}

    assert rules(analyze(GITHUB, ["sdist"], ("a", "sdist", other))) == [
        "provenance.publisher_changed"
    ]
    assert rules(analyze(GITHUB, ["sdist"], ("a", "sdist", renamed))) == [
        "provenance.workflow_changed"
    ]


def test_nothing_to_compare_without_a_snapshot() -> None:
    context = ReleaseContext(name="lib", version="1.1", metadata={"provenance": None})
    assert ProvenanceAnalyzer().analyze(context) == []


def test_repository_names_do_not_depend_on_case() -> None:
    renamed = {**GITHUB, "repository": "Acme/Lib"}
    assert analyze(GITHUB, ["sdist"], ("a", "sdist", renamed)) == []
