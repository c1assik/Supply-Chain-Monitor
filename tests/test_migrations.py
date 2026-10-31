"""Run migrations against a real PostgreSQL. TEST_DATABASE_URL must be a disposable database."""

import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pypi_monitor.db.models import Package, Release
from pypi_monitor.domain import ReleaseStatus

TABLES = {
    "packages",
    "releases",
    "artifacts",
    "analysis_runs",
    "signals",
    "verdicts",
    "ingest_cursors",
}

DATABASE_URL = os.environ.get("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL is not set")


@pytest.fixture
def alembic_config() -> Iterator[Config]:
    assert DATABASE_URL
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    command.downgrade(config, "base")
    yield config
    command.downgrade(config, "base")


@pytest.fixture
def engine(alembic_config: Config) -> Iterator[Engine]:
    assert DATABASE_URL
    command.upgrade(alembic_config, "head")
    engine = create_engine(DATABASE_URL)
    yield engine
    engine.dispose()


def test_upgrade_creates_all_tables(engine: Engine) -> None:
    assert set(inspect(engine).get_table_names()) >= TABLES


def test_models_match_migrations(alembic_config: Config, engine: Engine) -> None:
    command.check(alembic_config)


def test_downgrade_removes_all_tables(alembic_config: Config, engine: Engine) -> None:
    command.downgrade(alembic_config, "base")

    assert not TABLES & set(inspect(engine).get_table_names())


def test_new_release_is_queued(engine: Engine) -> None:
    with Session(engine) as session:
        package = Package(name="Foo_Bar", normalized_name="foo-bar")
        release = Release(version="1.0")
        session.add(package)
        session.flush()
        release.package_id = package.id
        session.add(release)
        session.commit()

        assert release.status is ReleaseStatus.QUEUED
        assert release.maintainers == []


def test_duplicate_release_is_rejected(engine: Engine) -> None:
    with Session(engine) as session:
        package = Package(name="foo", normalized_name="foo")
        session.add(package)
        session.flush()
        session.add_all(
            [Release(package_id=package.id, version="1.0") for _ in range(2)],
        )

        with pytest.raises(IntegrityError):
            session.commit()
