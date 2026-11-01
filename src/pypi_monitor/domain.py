"""Enumerations shared by the database schema, analyzers and scoring."""

from enum import StrEnum


class Severity(StrEnum):
    """Severity of a signal; also the risk level of a verdict."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReleaseStatus(StrEnum):
    QUEUED = "queued"
    DOWNLOADED = "downloaded"
    ANALYZED = "analyzed"
    ALERTED = "alerted"
    CLEAN = "clean"
    FAILED = "failed"
    # Known only as the base of a diff: never analyzed, and no verdict of its own.
    BASELINE = "baseline"


class ArtifactType(StrEnum):
    SDIST = "sdist"
    WHEEL = "wheel"


class DecidedBy(StrEnum):
    AUTO = "auto"
    HUMAN = "human"


class Label(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
