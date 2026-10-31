"""Download popularity: the reference list for typosquatting and the popularity multiplier."""

from packaging.utils import canonicalize_name
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

from pypi_monitor.db.models import Package
from pypi_monitor.db.session import Sessions
from pypi_monitor.pypi import PyPIClient


async def sync_top_packages(client: PyPIClient, sessions: Sessions, url: str, limit: int) -> int:
    projects = (await client.top_packages(url))[:limit]
    rows = [
        {
            "name": name,
            "normalized_name": canonicalize_name(name),
            "downloads_rank": rank,
            "is_popular": True,
        }
        for rank, name in enumerate(projects, start=1)
    ]
    if not rows:
        raise ValueError(f"empty top packages list: {url}")
    statement = insert(Package).values(rows)
    async with sessions.begin() as session:
        await session.execute(
            update(Package).where(Package.is_popular).values(is_popular=False, downloads_rank=None)
        )
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[Package.normalized_name],
                set_={
                    "downloads_rank": statement.excluded.downloads_rank,
                    "is_popular": statement.excluded.is_popular,
                },
            )
        )
    return len(rows)


async def load_top_packages(sessions: Sessions) -> dict[str, int]:
    """Popular packages as {normalized name: rank}."""
    async with sessions() as session:
        rows = await session.execute(
            select(Package.normalized_name, Package.downloads_rank).where(Package.is_popular)
        )
        return {name: rank for name, rank in rows if rank is not None}
