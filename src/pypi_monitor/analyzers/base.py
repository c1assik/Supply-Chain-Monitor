"""Common analyzer interface: a release goes in, a list of signals comes out."""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from pypi_monitor.domain import Severity


class Signal(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    evidence: str
    file_path: str | None = None
    line: int | None = Field(default=None, ge=1)


class ReleaseContext(BaseModel):
    """Everything an analyzer may look at. Artifact code is only ever read, never executed."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    artifact_dir: Path | None = None
    previous_artifact_dir: Path | None = None


class Analyzer(ABC):
    """Base class for analyzers.

    `analyze` is synchronous because analyzers are CPU-bound; the worker decides where it runs,
    so an analyzer must survive pickling.
    Bump `version` whenever results may change, so old releases can be re-analyzed and compared.
    """

    name: ClassVar[str]
    version: ClassVar[str]

    @abstractmethod
    def analyze(self, release: ReleaseContext) -> list[Signal]:
        """Return the signals found in the release; an empty list means nothing suspicious."""
