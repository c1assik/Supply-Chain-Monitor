import pytest
from pydantic import ValidationError

from pypi_monitor.analyzers import Analyzer, ReleaseContext, Signal
from pypi_monitor.domain import Severity


class StubAnalyzer(Analyzer):
    name = "stub"
    version = "1"

    def analyze(self, release: ReleaseContext) -> list[Signal]:
        if not release.name.startswith("evil"):
            return []
        return [
            Signal(
                rule_id="stub.evil_name",
                severity=Severity.HIGH,
                confidence=0.9,
                evidence=release.name,
            )
        ]


def test_analyzer_returns_signals() -> None:
    signals = StubAnalyzer().analyze(ReleaseContext(name="evil-pkg", version="1.0"))

    assert [s.rule_id for s in signals] == ["stub.evil_name"]
    assert signals[0].severity is Severity.HIGH


def test_analyzer_returns_nothing_for_clean_release() -> None:
    assert StubAnalyzer().analyze(ReleaseContext(name="requests", version="2.0")) == []


def test_analyzer_without_analyze_cannot_be_instantiated() -> None:
    class Incomplete(Analyzer):
        name = "incomplete"
        version = "1"

    with pytest.raises(TypeError):
        Incomplete()  # type: ignore[abstract]


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_signal_rejects_confidence_out_of_range(confidence: float) -> None:
    with pytest.raises(ValidationError):
        Signal(rule_id="r", severity=Severity.LOW, confidence=confidence, evidence="e")


def test_signal_is_immutable() -> None:
    signal = Signal(rule_id="r", severity=Severity.LOW, confidence=1, evidence="e")

    with pytest.raises(ValidationError):
        signal.rule_id = "other"  # type: ignore[misc]
