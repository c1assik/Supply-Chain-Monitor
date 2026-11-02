"""Fit scoring weights on the training part of the corpus, leaving the test part alone.

The score is a sum of `weight * confidence`, so a logistic regression on the same features gives
weights of the very same form. They are not allowed to go below zero. Ordinary code matches more
rules than malware simply because there is more of it, so a negative weight would reward size: an
attacker could pad a package with harmless code, and a compromised big library would look safe.

Two limits come from what the score is for, not from the data. A rule that fired on malware and
never on an ordinary release raises an alert alone: rules that fire together share their weight in
a regression, which would leave a lone reverse shell in `setup.py` under the alert level. And
metadata alone never does: a thin README is not a reason to wake anybody up.

Only `guarddog.*` and `metadata.*` rules seen in training are fitted. Diff, context and consistency
rules are not in this corpus and archive rules are not a matter of statistics: they keep their
weights, and `benchmarks.diff_pairs` watches over the diff.

    python -m benchmarks.tune
"""

import math
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from benchmarks.corpus import DATA_DIR, Group, Split, top_packages
from benchmarks.malware import (
    MAX_ALERTS_PER_DAY,
    RELEASES_PER_DAY,
    Result,
    compute_metrics,
    latest_results,
    load_results,
    score_results,
)
from pypi_monitor.scoring import ScoringConfig, load_scoring_config
from pypi_monitor.scoring.config import Combo

ITERATIONS = 1500
MAX_ROUNDS = 8
CONVERGED = 0.005
CALIBRATION_STEP = 1.01
FITTED_PREFIXES = ("guarddog.", "metadata.")
METADATA_PREFIX = "metadata."
# Four metadata rules at this weight and their confidence stay well under the High level.
MAX_METADATA_WEIGHT = 15
MIN_PRECISE_FIRES = 5
LEARNING_RATE = 2.0
L2 = 0.0005
HIGH_LEVEL = 50

Features = dict[str, float]


@dataclass(frozen=True)
class Row:
    features: Features
    malicious: bool
    weight: float


def features_of(result: Result, config: ScoringConfig) -> Features:
    """The strongest confidence of each rule, as the engine counts it, and fired combos."""
    features: Features = {}
    for signal in result.signals:
        if signal.rule_id.startswith(FITTED_PREFIXES):
            features[signal.rule_id] = max(features.get(signal.rule_id, 0), signal.confidence)
    fired = list(features)
    for index, combo in enumerate(config.combos):
        if all(any(fnmatchcase(rule, pattern) for rule in fired) for pattern in combo.rules):
            features[f"combo:{index}"] = 1
    return features


def build_rows(results: Sequence[Result], config: ScoringConfig) -> list[Row]:
    """Classes weigh the same whatever their sizes, or the fit would just echo the corpus mix."""
    positives = sum(result.malicious for result in results)
    negatives = len(results) - positives
    rows = []
    for result in results:
        weight = len(results) / (2 * (positives if result.malicious else negatives))
        rows.append(Row(features_of(result, config), result.malicious, weight))
    return rows


@dataclass(frozen=True)
class Bounds:
    lower: dict[str, float]
    upper: dict[str, float]

    def clip(self, name: str, value: float) -> float:
        return min(max(self.lower.get(name, 0.0), value), self.upper.get(name, math.inf))


def fit(rows: Sequence[Row], bounds: Bounds) -> dict[str, float]:
    """Projected gradient descent on the weighted log loss; the bias stays free."""
    names = sorted({name for row in rows for name in row.features})
    weights = {name: bounds.clip(name, 0.0) for name in names}
    bias = 0.0
    for _ in range(ITERATIONS):
        gradient = dict.fromkeys(names, 0.0)
        bias_gradient = 0.0
        for row in rows:
            logit = bias + sum(weights[name] * value for name, value in row.features.items())
            error = (_sigmoid(logit) - row.malicious) * row.weight
            bias_gradient += error
            for name, value in row.features.items():
                gradient[name] += error * value
        bias -= LEARNING_RATE * bias_gradient / len(rows)
        for name in names:
            step = gradient[name] / len(rows) + L2 * weights[name]
            weights[name] = bounds.clip(name, weights[name] - LEARNING_RATE * step)
    return weights


def _sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-max(min(value, 30), -30)))


def choose_threshold(
    results: Sequence[Result], weights: dict[str, float], config: ScoringConfig, alerts: float
) -> float:
    """The lowest raw score that keeps the flow of ordinary releases within `alerts` a day."""
    stream = [r for r in results if r.group is Group.RANDOM]
    scores = sorted(
        (
            sum(weights.get(name, 0) * value for name, value in features_of(r, config).items())
            for r in stream
        ),
        reverse=True,
    )
    allowed = int(alerts / RELEASES_PER_DAY * len(stream))
    # Strictly above the score of the first release over the budget.
    return scores[allowed] * 1.001 if scores[allowed] > 0 else min(s for s in scores if s > 0)


def precise_rules(rows: Sequence[Row]) -> dict[str, float]:
    """Rules with enough fires on malware and none on ordinary releases, with their confidence."""
    fires: dict[str, int] = {}
    confidence: dict[str, float] = {}
    ordinary: set[str] = set()
    for row in rows:
        for name, value in row.features.items():
            if row.malicious:
                fires[name] = fires.get(name, 0) + 1
                confidence[name] = min(confidence.get(name, 1.0), value)
            else:
                ordinary.add(name)
    return {
        name: confidence[name]
        for name, count in fires.items()
        if count >= MIN_PRECISE_FIRES and name not in ordinary and _is_code_rule(name)
    }


def _is_code_rule(name: str) -> bool:
    return not name.startswith((METADATA_PREFIX, "combo:"))


def bounds_for(rows: Sequence[Row], threshold: float) -> Bounds:
    scale = HIGH_LEVEL / threshold
    metadata = {name for row in rows for name in row.features if name.startswith(METADATA_PREFIX)}
    return Bounds(
        lower={name: threshold / value for name, value in precise_rules(rows).items()},
        upper=dict.fromkeys(metadata, MAX_METADATA_WEIGHT / scale),
    )


def apply_weights(
    config: ScoringConfig, weights: dict[str, float], threshold: float, rows: Sequence[Row]
) -> ScoringConfig:
    """Put fitted weights on the scale of the score: the threshold lands on the High level."""
    scale = HIGH_LEVEL / threshold
    rule_weights = dict(config.rule_weights)
    combos = []
    for index, combo in enumerate(config.combos):
        fitted = weights.get(f"combo:{index}")
        if fitted is None:
            combos.append(combo)
        elif round(fitted * scale) > 0:
            combos.append(Combo(rules=combo.rules, bonus=round(fitted * scale)))
    for name, value in weights.items():
        if not name.startswith("combo:"):
            rule_weights[name] = round(value * scale)
    for name, confidence in precise_rules(rows).items():
        # Rounding must not take a rule back under the level it has to reach alone.
        rule_weights[name] = max(rule_weights[name], math.ceil(HIGH_LEVEL / confidence))
    return config.model_copy(update={"rule_weights": rule_weights, "combos": combos})


def calibrate(
    config: ScoringConfig,
    weights: dict[str, float],
    threshold: float,
    rows: Sequence[Row],
    train: Sequence[Result],
) -> ScoringConfig:
    """Meet the alert budget with the real engine: rounding can lift a score onto the level."""
    top = top_packages()
    while True:
        tuned = apply_weights(config, weights, threshold, rows)
        metrics = compute_metrics(score_results(train, tuned, top))
        if metrics.alerts_per_day <= MAX_ALERTS_PER_DAY:
            return tuned
        threshold *= CALIBRATION_STEP


def main() -> int:
    config = load_scoring_config(Path("config/scoring.yaml"))
    results = [r for r in load_results(latest_results(DATA_DIR)) if r.error is None]
    train = [r for r in results if r.split is Split.TRAIN]

    rows = build_rows(train, config)
    bounds = Bounds({}, {})
    previous = math.inf
    # The bounds depend on the threshold, and the threshold on the weights.
    for _ in range(MAX_ROUNDS):
        weights = fit(rows, bounds)
        threshold = choose_threshold(train, weights, config, MAX_ALERTS_PER_DAY)
        print(f"threshold {threshold:.3f}", file=sys.stderr)
        if abs(threshold - previous) < CONVERGED * threshold:
            break
        previous = threshold
        bounds = bounds_for(rows, threshold)
    tuned = calibrate(config, weights, threshold, rows, train)

    metrics = compute_metrics(score_results(train, tuned, top_packages()))
    print(
        f"train: recall {metrics.recall:.1%}, medium recall {metrics.medium_recall:.1%}, ", end=""
    )
    print(
        f"stream FPR {metrics.stream_fpr:.2%}, {metrics.alerts_per_day:.0f} alerts a day, ", end=""
    )
    print(f"FPR {metrics.fpr:.2%}")
    print(
        yaml.safe_dump(
            {
                "rule_weights": dict(sorted(tuned.rule_weights.items())),
                "combos": [{"rules": sorted(c.rules), "bonus": c.bonus} for c in tuned.combos],
            },
            allow_unicode=True,
            sort_keys=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
