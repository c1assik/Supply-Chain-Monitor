from pathlib import Path

from pypi_monitor.analyzers import Signal
from pypi_monitor.domain import Severity
from pypi_monitor.scoring import ScoringConfig, load_scoring_config, score_release

BASE = {
    "severity_weights": {"low": 5, "medium": 15, "high": 35, "critical": 60},
    "popularity_multiplier": 1.5,
    "levels": {"critical": 80, "high": 50, "medium": 20},
}


def config(**overrides: object) -> ScoringConfig:
    return ScoringConfig.model_validate(BASE | overrides)


def signal(rule: str, severity: Severity = Severity.HIGH, confidence: float = 1) -> Signal:
    return Signal(rule_id=rule, severity=severity, confidence=confidence, evidence="e")


def test_no_signals_is_low() -> None:
    result = score_release([], config(), "pkg", False)

    assert (result.score, result.level) == (0, Severity.LOW)


def test_score_is_a_weighted_sum() -> None:
    signals = [signal("a"), signal("b", Severity.LOW, 0.5)]

    assert score_release(signals, config(), "pkg", False).score == 38


def test_rule_counts_once_with_its_strongest_signal() -> None:
    signals = [signal("a", confidence=0.5), signal("a"), signal("a", confidence=0.1)]

    assert score_release(signals, config(), "pkg", False).score == 35


def test_rule_weight_overrides_severity() -> None:
    assert score_release([signal("a")], config(rule_weights={"a": 3}), "pkg", False).score == 3


def test_combo_with_a_pattern_adds_a_bonus() -> None:
    combo = {"rules": ["a", "guarddog.threat-*"], "bonus": 30}
    signals = [signal("a", Severity.LOW), signal("guarddog.threat-x", Severity.LOW)]

    assert score_release(signals, config(combos=[combo]), "pkg", False).score == 40
    assert score_release(signals[:1], config(combos=[combo]), "pkg", False).score == 5


def test_popularity_lowers_the_bar_and_score_is_capped() -> None:
    assert score_release([signal("a")], config(), "pkg", True).level is Severity.HIGH
    assert score_release([signal("a")], config(), "pkg", False).level is Severity.MEDIUM

    many = [signal(str(i), Severity.CRITICAL) for i in range(5)]
    assert score_release(many, config(), "pkg", True).score == 100


def test_levels_follow_the_thresholds() -> None:
    weights = {"rule_weights": {"a": 19.0}}
    assert score_release([signal("a")], config(**weights), "pkg", False).level is Severity.LOW
    for weight, level in [(20, Severity.MEDIUM), (50, Severity.HIGH), (80, Severity.CRITICAL)]:
        tuned = config(rule_weights={"a": weight})
        assert score_release([signal("a")], tuned, "pkg", False).level is level


def test_allowlists_silence_packages_and_rules() -> None:
    allowed = config(allowlist={"packages": ["pkg"], "rules": ["a"]})

    assert score_release([signal("b")], allowed, "pkg", False).score == 0
    assert score_release([signal("a"), signal("b")], allowed, "other", False).score == 35


def test_top_signals_are_the_three_strongest() -> None:
    signals = [signal(rule, severity) for rule, severity in zip("abcd", Severity, strict=True)]

    top = score_release(signals, config(), "pkg", False).top_signals

    assert [s.rule_id for s in top] == ["d", "c", "b"]


def test_ordinary_tool_is_not_an_alert_with_repository_config() -> None:
    """Threat rules outside install-time code, as on real CLI tools and agents from PyPI."""
    signals = [signal(f"guarddog.threat-{i}", confidence=0.18) for i in range(4)]
    signals += [signal("metadata.new_package", Severity.LOW)]
    repository_config = load_scoring_config(Path("config/scoring.yaml"))

    assert score_release(signals, repository_config, "x", False).score < 50


def test_typosquat_with_threat_is_critical_with_repository_config() -> None:
    signals = [
        signal("metadata.typosquat", Severity.MEDIUM, 0.9),
        signal("metadata.new_package", Severity.LOW),
        signal("guarddog.install.threat-x", confidence=0.9),
    ]
    repository_config = load_scoring_config(Path("config/scoring.yaml"))

    assert score_release(signals, repository_config, "x", False).level is Severity.CRITICAL
