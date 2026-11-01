"""Pipeline stages and how they are put on the queue."""

from enum import StrEnum
from typing import Protocol

# Popular packages have a queue and a worker of their own: a burst of ordinary releases must not
# delay the verdict on a package that millions of people install.
PRIORITY_QUEUE = "arq:queue:priority"


class Stage(StrEnum):
    DOWNLOAD = "download"
    ANALYZE = "analyze"
    SCORE = "score"
    ALERT = "alert"


class ReleaseQueue(Protocol):
    async def enqueue(
        self, stage: Stage, release_id: int, defer_s: float | None = None, *, priority: bool = False
    ) -> None:
        """Queue a stage. A stage that is already queued for the release is not queued twice."""


class ArqQueue:
    def __init__(self, redis: "ArqRedisLike") -> None:
        self._redis = redis

    async def enqueue(
        self, stage: Stage, release_id: int, defer_s: float | None = None, *, priority: bool = False
    ) -> None:
        await self._redis.enqueue_job(
            stage.value,
            release_id,
            _job_id=f"{stage.value}:{release_id}",
            _defer_by=defer_s,
            _queue_name=PRIORITY_QUEUE if priority else None,
        )


class ArqRedisLike(Protocol):
    async def enqueue_job(
        self,
        function: str,
        *args: object,
        _job_id: str,
        _defer_by: float | None,
        _queue_name: str | None,
    ) -> object: ...
