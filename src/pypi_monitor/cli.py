"""Command line entry points of the services."""

import argparse
import asyncio
import logging

from arq import create_pool
from arq.connections import RedisSettings
from arq.worker import run_worker
from prometheus_client import start_http_server

from pypi_monitor.db.session import create_engine, create_sessions
from pypi_monitor.ingest.poller import Poller
from pypi_monitor.pipeline.queue import ArqQueue
from pypi_monitor.pypi import PyPIClient
from pypi_monitor.settings import get_settings
from pypi_monitor.top_packages import sync_top_packages


async def run_poller() -> None:
    settings = get_settings()
    start_http_server(settings.metrics_port)
    engine = create_engine(settings.database_url.get_secret_value())
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url.get_secret_value()))
    client = PyPIClient()
    poller = Poller(client, create_sessions(engine), ArqQueue(redis), settings.release_settle_s)
    await poller.run(settings.feed_poll_interval_s, settings.catchup_interval_s)


async def run_sync_top() -> None:
    settings = get_settings()
    engine = create_engine(settings.database_url.get_secret_value())
    client = PyPIClient()
    try:
        count = await sync_top_packages(
            client, create_sessions(engine), settings.top_packages_url, settings.top_packages_limit
        )
        print(f"{count} popular packages")
    finally:
        await client.aclose()
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(prog="pypi-monitor")
    parser.add_argument("command", choices=["poller", "worker", "sync-top"])
    command = parser.parse_args().command
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if command == "poller":
        asyncio.run(run_poller())
    elif command == "sync-top":
        asyncio.run(run_sync_top())
    else:
        from pypi_monitor.worker import WorkerSettings

        run_worker(WorkerSettings)  # type: ignore[arg-type]
