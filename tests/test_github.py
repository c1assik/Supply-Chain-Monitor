import gzip
from pathlib import Path
from typing import Any

import httpx
import pytest

from pypi_monitor.github import GitHubArchives, repository_of
from pypi_monitor.pypi.client import ArtifactTooLargeError


@pytest.mark.parametrize(
    ("info", "repository"),
    [
        ({"project_urls": {"Source": "https://github.com/a/b"}}, "a/b"),
        ({"project_urls": {"Source": "https://github.com/a/b.git"}}, "a/b"),
        ({"project_urls": {"Issues": "https://github.com/a/b/issues"}}, "a/b"),
        ({"home_page": "https://www.github.com/a/b/"}, "a/b"),
        (
            {"project_urls": {"F": "https://github.com/sponsors/x", "S": "https://github.com/a/b"}},
            "a/b",
        ),
        ({"project_urls": {"S": "https://gitlab.com/a/b"}}, None),
        ({"project_urls": {"S": "https://github.com.evil.test/a/b"}}, None),
        ({"project_urls": {"S": "https://github.com/a"}}, None),
        ({"project_urls": {"S": "https://github.com/../b"}}, None),
        ({"project_urls": {"S": "https://github.com/a/b%2f..%2fc"}}, None),
        ({"project_urls": None, "home_page": None}, None),
        ({}, None),
    ],
)
def test_repository_of(info: dict[str, Any], repository: str | None) -> None:
    assert repository_of(info) == repository


async def test_first_existing_tag_wins(tmp_path: Path) -> None:
    asked = []

    def handle(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        if request.url.path.endswith("/refs/tags/1.0"):
            return httpx.Response(200, content=gzip.compress(b"x"))
        return httpx.Response(404)

    archives = GitHubArchives(httpx.MockTransport(handle))
    tag = await archives.download_tag("a/b", "b", "1.0", tmp_path / "t.tar.gz", 1000)
    await archives.aclose()

    assert tag == "1.0"
    assert asked == ["/a/b/tar.gz/refs/tags/v1.0", "/a/b/tar.gz/refs/tags/1.0"]
    assert (tmp_path / "t.tar.gz").exists()


async def test_no_tag(tmp_path: Path) -> None:
    archives = GitHubArchives(httpx.MockTransport(lambda _: httpx.Response(404)))

    assert await archives.download_tag("a/b", "b", "1.0", tmp_path / "t", 1000) is None
    await archives.aclose()


async def test_download_is_limited(tmp_path: Path) -> None:
    archives = GitHubArchives(httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 50)))

    with pytest.raises(ArtifactTooLargeError):
        await archives.download_tag("a/b", "b", "1.0", tmp_path / "t", 10)
    await archives.aclose()
