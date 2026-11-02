"""Joining diff signals with stored scans, and telling the first attack release from the next."""

from benchmarks.corpus import Group, Split
from benchmarks.malware import Result
from benchmarks.real_diff import follow_ups, with_diff

from pypi_monitor.domain import Severity


def result(sample_id: str, group: Group = Group.COMPROMISED) -> Result:
    name = sample_id.split("/")[1]
    return Result(sample_id, name, group, Split.TEST, [], [], 1)


def diff_row(sample_id: str, previous: str) -> dict[str, object]:
    signal = {
        "rule_id": "diff.new_ip",
        "severity": Severity.MEDIUM,
        "confidence": 1,
        "evidence": "",
    }
    return {"id": sample_id, "previous": previous, "signals": [signal], "error": None}


def test_diff_signals_join_their_release_only() -> None:
    results = [result("c/lib/2.0"), result("c/other/1.0")]
    joined = with_diff(results, [diff_row("c/lib/2.0", "1.0")])
    assert [len(r.signals) for r in joined] == [1, 0]


def test_stored_result_is_not_changed() -> None:
    original = result("c/lib/2.0")
    with_diff([original], [diff_row("c/lib/2.0", "1.0")])
    assert original.signals == []


def test_second_attack_release_over_a_removed_one_is_a_follow_up() -> None:
    results = [result("c/lib/1.1"), result("c/lib/1.2")]
    rows = [diff_row("c/lib/1.1", "1.0"), diff_row("c/lib/1.2", "1.0")]
    assert follow_ups(results, rows) == {"c/lib/1.2"}


def test_attack_above_a_clean_baseline_is_not_a_follow_up() -> None:
    results = [result("c/lib/8.41"), result("c/lib/8.45")]
    rows = [diff_row("c/lib/8.41", "8.40"), diff_row("c/lib/8.45", "8.44")]
    assert follow_ups(results, rows) == set()
