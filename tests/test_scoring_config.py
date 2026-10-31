from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from pypi_monitor.domain import Severity
from pypi_monitor.scoring import ScoringConfig, load_scoring_config

VALID: dict[str, Any] = {
    "severity_weights": {"low": 1, "medium": 2, "high": 3, "critical": 4},
    "popularity_multiplier": 1.5,
    "levels": {"critical": 80, "high": 50, "medium": 20},
}


def test_repository_config_is_valid() -> None:
    config = load_scoring_config(Path("config/scoring.yaml"))

    assert config.severity_weights[Severity.CRITICAL] > config.severity_weights[Severity.LOW]
    assert (config.levels.critical, config.levels.high, config.levels.medium) == (80, 50, 20)


@pytest.mark.parametrize(
    "override",
    [
        {"severity_weights": {"low": 1}},
        {"levels": {"critical": 50, "high": 50, "medium": 20}},
        {"popularity_multiplier": 0.5},
        {"unknown_key": 1},
        {"combos": [{"rules": ["only.one"], "bonus": 10}]},
    ],
)
def test_invalid_config_is_rejected(override: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ScoringConfig.model_validate(VALID | override)
