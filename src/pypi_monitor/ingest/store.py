"""Writing packages and releases. Uniqueness is left to the database, so ingestion is idempotent."""

from datetime import datetime

from packaging.utils import canonicalize_name
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from pypi_monitor.db.models import Package, Release


async def get_or_create_package(session: AsyncSession, name: str) -> int:
    normalized = canonicalize_name(name)
    await session.execute(
        insert(Package)
        .values(name=name, normalized_name=normalized)
        .on_conflict_do_nothing(index_elements=[Package.normalized_name])
    )
    package_id = await session.scalar(
        select(Package.id).where(Package.normalized_name == normalized)
    )
    assert package_id is not None  # noqa: S101
    return package_id


async def record_release(
    session: AsyncSession,
    name: str,
    version: str,
    published_at: datetime | None = None,
    serial: int | None = None,
) -> int | None:
    """Store a release and return its id, or None when it is already known."""
    package_id = await get_or_create_package(session, name)
    return await session.scalar(
        insert(Release)
        .values(package_id=package_id, version=version, published_at=published_at, serial=serial)
        .on_conflict_do_nothing(index_elements=[Release.package_id, Release.version])
        .returning(Release.id)
    )


async def package_exists(session: AsyncSession, name: str) -> bool:
    package_id = await session.scalar(
        select(Package.id).where(Package.normalized_name == canonicalize_name(name))
    )
    return package_id is not None
