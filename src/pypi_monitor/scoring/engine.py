"""Risk score of a release: a weighted sum of its signals."""

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase

from packaging.utils import canonicalize_name

from pypi_monitor.analyzers.base import Signal
from pypi_monitor.domain import Severity
from pypi_monitor.scoring.config import ScoringConfig

MAX_SCORE = 100
TOP_SIGNALS = 3


@dataclass(frozen=True)
class Score:
    score: int
    level: Severity
    top_signals: list[Signal]


def score_release(
    signals: Iterable[Signal], config: ScoringConfig, package: str, is_popular: bool
) -> Score:
    if canonicalize_name(package) in config.allowlist.packages:
        return Score(0, Severity.LOW, [])

    # A rule counts once: a hundred hits of one pattern are one piece of evidence.
    strongest: dict[str, tuple[float, Signal]] = {}
    for signal in signals:
        if signal.rule_id in config.allowlist.rules:
            continue
        contribution = _contribution(signal, config)
        if signal.rule_id not in strongest or contribution > strongest[signal.rule_id][0]:
            strongest[signal.rule_id] = (contribution, signal)

    total = sum(contribution for contribution, _ in strongest.values())
    fired = strongest.keys()
    for combo in config.combos:
        if all(any(fnmatchcase(rule, pattern) for rule in fired) for pattern in combo.rules):
            total += combo.bonus
    if is_popular:
        total *= config.popularity_multiplier

    score = min(MAX_SCORE, round(total))
    ranked = sorted(strongest.values(), key=lambda item: item[0], reverse=True)
    return Score(score, _level(score, config), [signal for _, signal in ranked[:TOP_SIGNALS]])


def _contribution(signal: Signal, config: ScoringConfig) -> float:
    weight = config.rule_weights.get(signal.rule_id, config.severity_weights[signal.severity])
    return weight * signal.confidence


def _level(score: int, config: ScoringConfig) -> Severity:
    if score >= config.levels.critical:
        return Severity.CRITICAL
    if score >= config.levels.high:
        return Severity.HIGH
    if score >= config.levels.medium:
        return Severity.MEDIUM
    return Severity.LOW
