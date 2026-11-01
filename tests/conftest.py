import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from pypi_monitor.db.session import Sessions, create_engine, create_sessions
from pypi_monitor.pipeline.queue import Stage

DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

# Settings have no secret defaults, and tests must not depend on a local .env.
os.environ.setdefault("SCM_DATABASE_URL", "postgresql+psycopg://unused@localhost/unused")
os.environ.setdefault("SCM_REDIS_URL", "redis://localhost")
os.environ.setdefault("SCM_S3_ACCESS_KEY", "unused")
os.environ.setdefault("SCM_S3_SECRET_KEY", "unused")


class FakeQueue:
    def __init__(self) -> None:
        self.jobs: list[tuple[Stage, int]] = []
        self.priority: set[tuple[Stage, int]] = set()

    async def enqueue(
        self, stage: Stage, release_id: int, defer_s: float | None = None, *, priority: bool = False
    ) -> None:
        if (stage, release_id) not in self.jobs:
            self.jobs.append((stage, release_id))
        if priority:
            self.priority.add((stage, release_id))


class FakeStorage:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, path: Path, key: str) -> None:
        self.objects[key] = path.read_bytes()

    def get(self, key: str, path: Path) -> None:
        path.write_bytes(self.objects[key])


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
def storage() -> FakeStorage:
    return FakeStorage()


@pytest.fixture(scope="session")
def migrated_database() -> Iterator[str]:
    if not DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    command.upgrade(config, "head")
    yield DATABASE_URL
    command.downgrade(config, "base")


@pytest.fixture
async def sessions(migrated_database: str) -> AsyncIterator[Sessions]:
    engine = create_engine(migrated_database)
    factory = create_sessions(engine)
    async with factory.begin() as session:
        await session.execute(
            text("TRUNCATE packages, releases, artifacts, analysis_runs, signals, verdicts CASCADE")
        )
        await session.execute(text("TRUNCATE ingest_cursors"))
    yield factory
    await engine.dispose()
    await asyncio.sleep(0)
