"""Pipeline stages and how they are put on the queue."""

from enum import StrEnum
from typing import Protocol


class Stage(StrEnum):
    DOWNLOAD = "download"
    ANALYZE = "analyze"
    SCORE = "score"
    ALERT = "alert"


class ReleaseQueue(Protocol):
    async def enqueue(self, stage: Stage, release_id: int, defer_s: float | None = None) -> None:
        """Queue a stage. A stage that is already queued for the release is not queued twice."""


class ArqQueue:
    def __init__(self, redis: "ArqRedisLike") -> None:
        self._redis = redis

    async def enqueue(self, stage: Stage, release_id: int, defer_s: float | None = None) -> None:
        await self._redis.enqueue_job(
            stage.value, release_id, _job_id=f"{stage.value}:{release_id}", _defer_by=defer_s
        )


class ArqRedisLike(Protocol):
    async def enqueue_job(
        self, function: str, *args: object, _job_id: str, _defer_by: float | None
    ) -> object: ...
