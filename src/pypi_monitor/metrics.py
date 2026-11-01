"""Prometheus metrics of the pipeline."""

from prometheus_client import Counter, Gauge, Histogram

_DURATION_BUCKETS = (0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300)
_LATENCY_BUCKETS = (30, 60, 120, 180, 300, 450, 600, 900, 1800, 3600)

RELEASES_INGESTED = Counter(
    "scm_releases_ingested_total", "New releases written to the database", ["source"]
)
FEED_ERRORS = Counter("scm_feed_errors_total", "Failed feed polls", ["source"])
FEED_LAST_SUCCESS = Gauge(
    "scm_feed_last_success_timestamp_seconds", "Time of the last successful poll", ["source"]
)
QUEUE_SIZE = Gauge("scm_queue_size", "Jobs waiting in the queue")
STAGE_DURATION = Histogram(
    "scm_stage_duration_seconds",
    "Duration of a pipeline stage",
    ["stage"],
    buckets=_DURATION_BUCKETS,
)
STAGE_RETRIES = Counter("scm_stage_retries_total", "Retried pipeline stages", ["stage"])
STAGE_FAILURES = Counter("scm_stage_failures_total", "Releases failed at a stage", ["stage"])
ANALYZER_ERRORS = Counter("scm_analyzer_errors_total", "Analyzer crashes", ["analyzer"])
ARTIFACTS_SKIPPED = Counter("scm_artifacts_skipped_total", "Artifacts not analyzed", ["reason"])
VERDICT_LATENCY = Histogram(
    "scm_verdict_latency_seconds",
    "Time from publication on PyPI to the verdict",
    buckets=_LATENCY_BUCKETS,
)
VERDICTS = Counter("scm_verdicts_total", "Automatic verdicts", ["level"])
BASELINES = Counter("scm_baselines_total", "Releases by the base of their diff", ["outcome"])
ALERTS = Counter("scm_alerts_total", "Sent alerts", ["level"])
