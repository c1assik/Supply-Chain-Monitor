"""Source archives of tagged commits.

codeload.github.com is not counted against the API limit, so this needs neither a token nor the
API client planned for stage 2b. Repository names come from package metadata and are untrusted.
"""

import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from pypi_monitor import __version__
from pypi_monitor.pypi.client import ArtifactTooLargeError

ARCHIVE_URL = "https://codeload.github.com"
_NAME = re.compile(r"[A-Za-z0-9_.-]+")
_NOT_OWNERS = frozenset({"sponsors", "orgs", "apps", "marketplace", "features", "topics"})
_TAG_TEMPLATES = (
    "v{version}",
    "{version}",
    "{name}-{version}",
    "{name}-v{version}",
    "release-{version}",
    "{name}@{version}",
)


def repository_of(info: Mapping[str, Any]) -> str | None:
    """`owner/name` of the first GitHub repository in the project links."""
    urls: list[Any] = list((info.get("project_urls") or {}).values())
    urls.append(info.get("home_page"))
    for url in urls:
        parsed = urlparse(url) if isinstance(url, str) else None
        if parsed is None or parsed.hostname not in ("github.com", "www.github.com"):
            continue
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2 or parts[0].lower() in _NOT_OWNERS:
            continue
        owner, name = parts[0], parts[1].removesuffix(".git")
        if all(_NAME.fullmatch(part) and part not in (".", "..") for part in (owner, name)):
            return f"{owner}/{name}"
    return None


def tag_candidates(name: str, version: str) -> Iterable[str]:
    return (template.format(name=name, version=version) for template in _TAG_TEMPLATES)


class GitHubArchives:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._http = httpx.AsyncClient(
            base_url=ARCHIVE_URL,
            headers={"User-Agent": f"pypi-supply-chain-monitor/{__version__}"},
            timeout=60,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def download_tag(
        self, repository: str, name: str, version: str, path: Path, max_bytes: int
    ) -> str | None:
        """Save the archive of the release tag to `path`; return the tag, or None without one."""
        for tag in tag_candidates(name, version):
            url = f"/{repository}/tar.gz/refs/tags/{quote(tag, safe='')}"
            if await self._download(url, path, max_bytes):
                return tag
        return None

    async def _download(self, url: str, path: Path, max_bytes: int) -> bool:
        size = 0
        async with self._http.stream("GET", url) as response:
            if response.status_code == httpx.codes.NOT_FOUND:
                return False
            response.raise_for_status()
            with path.open("wb") as file:
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ArtifactTooLargeError(url)
                    file.write(chunk)
        return True
