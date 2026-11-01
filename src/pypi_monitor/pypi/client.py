"""Asynchronous client for the public PyPI APIs."""

import hashlib
import time
import xmlrpc.client  # Only used to talk to pypi.org over TLS.
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from pypi_monitor import __version__
from pypi_monitor.pypi.feeds import ChangelogEvent, FeedEntry, parse_changelog, parse_feed

BASE_URL = "https://pypi.org"
FILES_HOST = "files.pythonhosted.org"
# XML-RPC is rate limited per client, and the changelog depends on it: this lookup must not eat
# the limit. The usual flow is about one new package a minute.
USER_LOOKUP_INTERVAL_S = 6
USER_AGENT = f"pypi-supply-chain-monitor/{__version__}"
SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


class NotReadyError(Exception):
    """PyPI does not serve the data yet (CDN lag), or no longer does."""


class ArtifactTooLargeError(Exception):
    pass


class PyPIClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._next_user_lookup = 0.0
        self._http = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=30,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def fetch_feed(self, path: str) -> list[FeedEntry]:
        response = await self._http.get(path)
        response.raise_for_status()
        return parse_feed(response.content)

    async def last_serial(self) -> int:
        serial = await self._xmlrpc("changelog_last_serial")
        assert isinstance(serial, int)  # noqa: S101
        return serial

    async def changelog_since(self, serial: int) -> list[ChangelogEvent]:
        rows = await self._xmlrpc("changelog_since_serial", serial)
        return parse_changelog(rows)

    async def user_packages(self, username: str) -> list[list[str]] | None:
        """Packages of a user, or None when the budget for this lookup is spent."""
        now = time.monotonic()
        if now < self._next_user_lookup:
            return None
        self._next_user_lookup = now + USER_LOOKUP_INTERVAL_S
        rows: list[list[str]] = await self._xmlrpc("user_packages", username)
        return rows

    async def project(self, name: str) -> dict[str, Any]:
        return await self._json(f"/pypi/{quote(name, safe='')}/json")

    async def release(self, name: str, version: str) -> dict[str, Any]:
        return await self._json(f"/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json")

    async def simple(self, name: str) -> dict[str, Any]:
        """The PEP 691 project page: every version and file, yanked ones marked."""
        return await self._json(f"/simple/{quote(name, safe='')}/", {"Accept": SIMPLE_JSON})

    async def top_packages(self, url: str) -> list[str]:
        """Project names from a top-pypi-packages dump, most downloaded first."""
        response = await self._http.get(url, follow_redirects=True)
        response.raise_for_status()
        return [row["project"] for row in response.json()["rows"]]

    async def download(self, url: str, path: Path, max_bytes: int) -> str:
        """Stream `url` to `path` and return the sha256 of what was written."""
        if urlparse(url).hostname != FILES_HOST:
            raise ValueError(f"unexpected artifact host: {url}")
        digest = hashlib.sha256()
        size = 0
        async with self._http.stream("GET", url) as response:
            response.raise_for_status()
            with path.open("wb") as file:
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ArtifactTooLargeError(url)
                    digest.update(chunk)
                    file.write(chunk)
        return digest.hexdigest()

    async def _json(self, path: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        response = await self._http.get(path, headers=headers)
        if response.status_code == httpx.codes.NOT_FOUND:
            raise NotReadyError(path)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    async def _xmlrpc(self, method: str, *params: str | int) -> Any:
        response = await self._http.post(
            "/pypi",
            content=xmlrpc.client.dumps(params, method),
            headers={"Content-Type": "text/xml"},
        )
        response.raise_for_status()
        return xmlrpc.client.loads(response.text)[0][0]
