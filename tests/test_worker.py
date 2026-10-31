from typing import Any

import pytest
from arq import Retry

from pypi_monitor.pipeline.queue import Stage
from pypi_monitor.settings import get_settings
from pypi_monitor.worker import run_stage


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
