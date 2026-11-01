from typing import Any

import pytest
from arq import Retry

from pypi_monitor.pipeline.queue import PRIORITY_QUEUE, ArqQueue, Stage
from pypi_monitor.settings import get_settings
from pypi_monitor.worker import WorkerSettings, priority_worker_options, run_stage


class FlakyPipeline:
    def __init__(self) -> None:
        self.failed: list[int] = []

    async def download(self, release_id: int) -> None:
        raise RuntimeError("PyPI is down")

    async def fail(self, release_id: int) -> None:
        self.failed.append(release_id)


async def test_failed_stage_is_retried_with_a_growing_delay() -> None:
    pipeline = FlakyPipeline()
    ctx: dict[str, Any] = {"pipeline": pipeline, "job_try": 2}

    with pytest.raises(Retry) as retry:
        await run_stage(ctx, Stage.DOWNLOAD, 1)

    assert retry.value.defer_score == 2 * get_settings().retry_delay_s * 1000
    assert pipeline.failed == []


async def test_last_try_marks_the_release_as_failed() -> None:
    pipeline = FlakyPipeline()
    ctx: dict[str, Any] = {"pipeline": pipeline, "job_try": get_settings().max_tries}

    await run_stage(ctx, Stage.DOWNLOAD, 1)

    assert pipeline.failed == [1]


async def test_queue_routes_popular_releases_to_the_priority_queue() -> None:
    class Redis:
        def __init__(self) -> None:
            self.queues: list[str | None] = []

        async def enqueue_job(
            self,
            function: str,
            *args: object,
            _job_id: str,
            _defer_by: float | None,
            _queue_name: str | None,
        ) -> None:
            self.queues.append(_queue_name)

    redis = Redis()
    queue = ArqQueue(redis)

    await queue.enqueue(Stage.DOWNLOAD, 1)
    await queue.enqueue(Stage.DOWNLOAD, 2, priority=True)

    assert redis.queues == [None, PRIORITY_QUEUE]


def test_priority_worker_reads_its_queue_and_runs_no_shared_cron_jobs() -> None:
    options = priority_worker_options()

    assert options["queue_name"] == PRIORITY_QUEUE
    assert options["ctx"]["queue_name"] == PRIORITY_QUEUE
    main_jobs = {job.coroutine for job in WorkerSettings.cron_jobs}
    assert not main_jobs & {job.coroutine for job in options["cron_jobs"]}
