"""Scoring weights, loaded from YAML."""

from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from pypi_monitor.domain import Severity


class _Config(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Combo(_Config):
    rules: frozenset[str] = Field(min_length=2)
    bonus: float = Field(gt=0)


class LevelThresholds(_Config):
    critical: int = Field(le=100)
    high: int
    medium: int = Field(gt=0)

    @model_validator(mode="after")
    def _check_order(self) -> Self:
        if not self.critical > self.high > self.medium:
            raise ValueError("thresholds must satisfy critical > high > medium")
        return self


class ScoringConfig(_Config):
    severity_weights: dict[Severity, float]
    rule_weights: dict[str, float] = Field(default_factory=dict)
    combos: list[Combo] = Field(default_factory=list)
    popularity_multiplier: float = Field(ge=1)
    levels: LevelThresholds

    @model_validator(mode="after")
    def _check_all_severities(self) -> Self:
        missing = set(Severity) - self.severity_weights.keys()
        if missing:
            raise ValueError(f"severity_weights is missing: {sorted(missing)}")
        return self


def load_scoring_config(path: Path) -> ScoringConfig:
    with path.open(encoding="utf-8") as f:
        return ScoringConfig.model_validate(yaml.safe_load(f))
