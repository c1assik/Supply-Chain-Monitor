"""Weight fitting: limits that keep the score meaningful whatever the corpus says."""

from pathlib import Path

from benchmarks.corpus import Group, Split
from benchmarks.malware import Result
from benchmarks.tune import (
    Bounds,
    Row,
    apply_weights,
    bounds_for,
    features_of,
    fit,
    precise_rules,
)

from pypi_monitor.analyzers.base import Signal
from pypi_monitor.domain import Severity
from pypi_monitor.scoring import load_scoring_config

CONFIG = load_scoring_config(Path("config/scoring.yaml"))
NO_BOUNDS = Bounds({}, {})


def result(*rules: str) -> Result:
    signals = [
        Signal(rule_id=r, severity=Severity.HIGH, confidence=0.5, evidence="") for r in rules
    ]
    return Result("id", "pkg", Group.RANDOM, Split.TRAIN, signals, [], 1)


def row(malicious: bool, **features: float) -> Row:
    return Row(features, malicious, 1.0)


def test_weight_of_a_rule_of_ordinary_code_stays_at_zero() -> None:
    rows = [row(True, evil=1)] * 20 + [row(False, big=1)] * 20
    weights = fit(rows, NO_BOUNDS)
    assert weights["evil"] > 0
    assert weights["big"] == 0


def test_bounds_hold_after_the_fit() -> None:
    rows = [row(True, evil=1, thin=1)] * 20 + [row(False)] * 20
    weights = fit(rows, Bounds({"evil": 5.0}, {"thin": 0.1}))
    assert weights["evil"] >= 5
    assert weights["thin"] <= 0.1


def test_only_guarddog_and_metadata_rules_are_fitted() -> None:
    found = features_of(result("archive.path_traversal", "diff.new_url", "guarddog.x"), CONFIG)
    assert set(found) == {"guarddog.x"}


def test_precise_rule_needs_enough_fires_and_no_ordinary_ones() -> None:
    rows = [row(True, sharp=0.9, seen=0.9, metadata_rule=0.9)] * 5 + [row(True, rare=0.9)] * 4
    rows += [row(False, seen=0.9)]
    assert precise_rules(rows) == {"sharp": 0.9, "metadata_rule": 0.9}


def test_metadata_is_never_precise_and_cannot_reach_an_alert_alone() -> None:
    rows = [row(True, **{"metadata.empty_readme": 0.8})] * 10
    bounds = bounds_for(rows, threshold=2.0)
    assert bounds.lower == {}
    assert bounds.upper["metadata.empty_readme"] * 50 / 2.0 * 4 < 100


def test_precise_rule_reaches_the_high_level_alone_after_rounding() -> None:
    rows = [row(True, **{"guarddog.install.threat-x": 0.9})] * 5
    tuned = apply_weights(CONFIG, {"guarddog.install.threat-x": 0.1}, 3.0, rows)
    assert tuned.rule_weights["guarddog.install.threat-x"] * 0.9 >= 50


def test_hand_set_weights_survive() -> None:
    tuned = apply_weights(CONFIG, {"guarddog.x": 1.0}, 3.0, [])
    assert tuned.rule_weights["diff.new_dangerous_call"] == 5
    assert tuned.levels == CONFIG.levels
