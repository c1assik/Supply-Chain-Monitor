"""arq worker: runs pipeline stages, retries failures and keeps the queue moving."""

import asyncio
import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from typing import Any

from arq import Retry, cron
from arq.connections import RedisSettings
from arq.constants import default_queue_name
from prometheus_client import start_http_server

from pypi_monitor.alerts.telegram import LogNotifier, Notifier, TelegramNotifier
from pypi_monitor.analyzers.consistency import ConsistencyAnalyzer
from pypi_monitor.analyzers.context import ContextAnalyzer
from pypi_monitor.analyzers.diff import DiffAnalyzer
from pypi_monitor.analyzers.guarddog import GuardDogAnalyzer
from pypi_monitor.analyzers.metadata import MetadataAnalyzer
from pypi_monitor.analyzers.provenance import ProvenanceAnalyzer
from pypi_monitor.db.session import create_engine, create_sessions
from pypi_monitor.github import GitHubArchives
from pypi_monitor.metrics import QUEUE_SIZE, STAGE_DURATION, STAGE_FAILURES, STAGE_RETRIES
from pypi_monitor.pipeline.queue import PRIORITY_QUEUE, ArqQueue, Stage
from pypi_monitor.pipeline.stages import Pipeline
from pypi_monitor.pipeline.unpack import UnpackLimits
from pypi_monitor.pypi import PyPIClient
from pypi_monitor.scoring import load_scoring_config
from pypi_monitor.settings import get_settings
from pypi_monitor.storage import ArtifactStorage
from pypi_monitor.top_packages import load_top_packages, sync_top_packages

log = logging.getLogger(__name__)

STAGE_TIMEOUT_S = 600
QUEUE_SIZE_INTERVAL_S = 15


async def run_stage(ctx: dict[str, Any], stage: Stage, release_id: int) -> None:
    pipeline: Pipeline = ctx["pipeline"]
    settings = get_settings()
    try:
        with STAGE_DURATION.labels(stage.value).time():
            async with asyncio.timeout(STAGE_TIMEOUT_S):
                await getattr(pipeline, stage.value)(release_id)
    except Exception as e:
        # arq gives up on its own without a hook, so the last try is handled here.
        job_try: int = ctx["job_try"]
        if job_try >= settings.max_tries:
            STAGE_FAILURES.labels(stage.value).inc()
            log.exception("release %d failed at %s", release_id, stage.value)
            await pipeline.fail(release_id)
            return
        STAGE_RETRIES.labels(stage.value).inc()
        log.info("release %d: %s retry %d: %r", release_id, stage.value, job_try, e)
        raise Retry(defer=job_try * settings.retry_delay_s) from e


async def download(ctx: dict[str, Any], release_id: int) -> None:
    await run_stage(ctx, Stage.DOWNLOAD, release_id)


async def analyze(ctx: dict[str, Any], release_id: int) -> None:
    await run_stage(ctx, Stage.ANALYZE, release_id)


async def score(ctx: dict[str, Any], release_id: int) -> None:
    await run_stage(ctx, Stage.SCORE, release_id)


async def alert(ctx: dict[str, Any], release_id: int) -> None:
    await run_stage(ctx, Stage.ALERT, release_id)


async def sweep(ctx: dict[str, Any]) -> None:
    requeued = await ctx["pipeline"].sweep(get_settings().sweep_stale_after_s)
    if requeued:
        log.info("sweep: %d releases requeued", requeued)


async def refresh_top_packages(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    count = await sync_top_packages(
        ctx["client"], ctx["sessions"], settings.top_packages_url, settings.top_packages_limit
    )
    _reload_analyzers(ctx["pipeline"], await load_top_packages(ctx["sessions"]))
    log.info("top packages refreshed: %d", count)


def _reload_analyzers(pipeline: Pipeline, top_packages: dict[str, int]) -> None:
    pipeline.analyzers = [
        MetadataAnalyzer(top_packages),
        GuardDogAnalyzer(),
        DiffAnalyzer(),
        ConsistencyAnalyzer(),
        ContextAnalyzer(),
        ProvenanceAnalyzer(),
    ]


async def reload_top_packages(ctx: dict[str, Any]) -> None:
    """The nightly refresh runs on the main worker; the priority worker only picks up its result."""
    _reload_analyzers(ctx["pipeline"], await load_top_packages(ctx["sessions"]))


async def _report_queue_size(ctx: dict[str, Any]) -> None:
    queue = ctx.get("queue_name", default_queue_name)
    while True:
        QUEUE_SIZE.set(await ctx["redis"].zcard(queue))
        await asyncio.sleep(QUEUE_SIZE_INTERVAL_S)


def _notifier() -> Notifier:
    settings = get_settings()
    if settings.telegram_token and settings.telegram_chat_id:
        token = settings.telegram_token.get_secret_value()
        if token:
            return TelegramNotifier(token, settings.telegram_chat_id)
    log.warning("Telegram is not configured: alerts go to the log")
    return LogNotifier()


async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    start_http_server(settings.metrics_port)
    ctx["engine"] = create_engine(settings.database_url.get_secret_value())
    ctx["sessions"] = sessions = create_sessions(ctx["engine"])
    ctx["client"] = client = PyPIClient()
    ctx["github"] = github = GitHubArchives()
    # spawn: forking a process that already runs threads and an event loop is unsafe.
    ctx["executor"] = executor = ProcessPoolExecutor(
        settings.analyzer_processes, mp_context=multiprocessing.get_context("spawn")
    )
    ctx["pipeline"] = pipeline = Pipeline(
        sessions=sessions,
        client=client,
        storage=ArtifactStorage(
            settings.s3_endpoint,
            settings.s3_access_key.get_secret_value(),
            settings.s3_secret_key.get_secret_value(),
            settings.s3_bucket,
        ),
        queue=ArqQueue(ctx["redis"]),
        notifier=_notifier(),
        scoring=load_scoring_config(settings.scoring_config_path),
        analyzers=[],
        limits=UnpackLimits(
            settings.max_unpacked_bytes,
            settings.max_unpacked_files,
            settings.max_compression_ratio,
        ),
        max_artifact_bytes=settings.max_artifact_bytes,
        analyzer_timeout_s=settings.analyzer_timeout_s,
        executor=executor,
        github=github if settings.compare_tags else None,
        dashboard_url=settings.dashboard_url,
    )
    ctx["queue_size_task"] = asyncio.create_task(_report_queue_size(ctx))
    top_packages = await load_top_packages(sessions)
    _reload_analyzers(pipeline, top_packages)
    if not top_packages:
        try:
            await refresh_top_packages(ctx)
        except Exception:
            # Typosquat detection waits for the nightly refresh; the rest of the pipeline does not.
            log.exception("cannot load top packages")


async def shutdown(ctx: dict[str, Any]) -> None:
    ctx["queue_size_task"].cancel()
    ctx["executor"].shutdown(cancel_futures=True)
    await ctx["client"].aclose()
    await ctx["github"].aclose()
    await ctx["engine"].dispose()


class WorkerSettings:
    functions = [download, analyze, score, alert]  # noqa: RUF012
    cron_jobs = [  # noqa: RUF012
        cron(sweep, minute=set(range(0, 60, 5))),
        cron(refresh_top_packages, hour={3}, minute={17}, timeout=120),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url.get_secret_value())
    max_jobs = get_settings().worker_max_jobs
    max_tries = get_settings().max_tries
    # The stage enforces its own timeout, so that it can count the try.
    job_timeout = STAGE_TIMEOUT_S + 60
    # Job ids must stay reusable: the sweeper requeues under the same id.
    keep_result = 0


def priority_worker_options() -> dict[str, Any]:
    """Overrides of `WorkerSettings` for the worker of popular packages."""
    return {
        "queue_name": PRIORITY_QUEUE,
        "ctx": {"queue_name": PRIORITY_QUEUE},
        # Sweeping and the top list stay on the main worker: arq would run a cron job only once.
        "cron_jobs": [cron(reload_top_packages, hour={3}, minute={47}, timeout=60)],
    }
