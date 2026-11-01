"""The diff benchmark as a regression test: rules must not lose recall or add false alerts."""

import ast
from pathlib import Path

import pytest
from benchmarks.diff_pairs import Report, build_pairs, run_benchmark

from pypi_monitor.scoring import load_scoring_config


@pytest.fixture(scope="module")
def report() -> Report:
    return run_benchmark(load_scoring_config(Path("config/scoring.yaml")))


def test_there_are_enough_pairs() -> None:
    assert sum(pair.infected for pair in build_pairs()) >= 50


def test_clean_pairs_are_valid_python() -> None:
    for pair in build_pairs():
        if not pair.infected:
            for path, source in pair.new.items():
                if path.endswith(".py"):
                    ast.parse(source)


def test_every_infected_pair_gives_a_signal(report: Report) -> None:
    assert report.detection_recall == 1


def test_most_infected_pairs_give_an_alert(report: Report) -> None:
    assert report.alert_recall >= 0.8


def test_clean_updates_give_no_alerts(report: Report) -> None:
    assert report.false_alert_rate == 0


def test_payload_on_the_import_path_always_alerts(report: Report) -> None:
    missed = [
        o.pair.id
        for o in report.outcomes
        if o.pair.infected and o.pair.id.split("/")[1] in ("init", "setup", "pth") and not o.alerted
    ]
    assert missed == []
