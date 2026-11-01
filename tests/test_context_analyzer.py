from typing import Any

from pypi_monitor.analyzers.base import ReleaseContext, Signal
from pypi_monitor.analyzers.context import ContextAnalyzer, owners_of
from pypi_monitor.domain import Severity


def analyze(version: str = "1.1", **metadata: Any) -> list[Signal]:
    return ContextAnalyzer().analyze(ReleaseContext(name="a", version=version, metadata=metadata))


def ownership(*users: str, organization: str | None = None) -> dict[str, Any]:
    return {"roles": [{"role": "Owner", "user": u} for u in users], "organization": organization}


def test_a_release_with_nothing_to_compare_is_quiet() -> None:
    assert analyze() == []


def test_organization_is_an_owner() -> None:
    assert owners_of(ownership("alice", organization="acme")) == {"alice", "org:acme"}
    assert owners_of(None) == set()


def test_added_owner() -> None:
    signals = analyze(known_owners=["alice"], ownership=ownership("alice", "mallory"))

    assert [s.rule_id for s in signals] == ["context.owner_added"]
    assert signals[0].severity is Severity.MEDIUM
    assert "mallory" in signals[0].evidence


def test_replaced_owners_are_worse() -> None:
    signals = analyze(known_owners=["alice"], ownership=ownership("mallory"))

    assert [s.rule_id for s in signals] == ["context.owners_replaced"]
    assert signals[0].severity is Severity.HIGH


def test_removed_owner_alone_is_not_suspicious() -> None:
    assert analyze(known_owners=["alice", "bob"], ownership=ownership("alice")) == []


def test_owners_we_never_saw_are_not_a_change() -> None:
    assert analyze(known_owners=None, ownership=ownership("alice")) == []
    assert analyze(known_owners=[], ownership=ownership("alice")) == []


def test_dormant_project() -> None:
    signals = analyze(
        last_upload="2024-01-01T00:00:00+00:00", release_upload="2026-01-01T00:00:00+00:00"
    )

    assert [s.rule_id for s in signals] == ["context.dormant_release"]
    assert "731 days" in signals[0].evidence


def test_active_project_is_not_dormant() -> None:
    upload = {"last_upload": "2025-11-01T00:00:00+00:00"}
    assert analyze(**upload, release_upload="2026-01-01T00:00:00+00:00") == []


def test_version_jump() -> None:
    signals = analyze("9.0", previous_version="1.2.3")
    assert [s.rule_id for s in signals] == ["context.version_jump"]


def test_ordinary_version_moves() -> None:
    assert analyze("2.0", previous_version="1.9") == []
    assert analyze("1.9", previous_version="1.2") == []
    assert analyze("2026.1", previous_version="2023.5") == []
    assert analyze("not-a-version", previous_version="1.0") == []
