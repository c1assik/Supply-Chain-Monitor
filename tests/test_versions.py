from typing import Any

import httpx

from pypi_monitor.pypi import PyPIClient
from pypi_monitor.pypi.versions import choose_previous


def page(*filenames: str, yanked: tuple[str, ...] = (), versions: list[str] | None = None) -> Any:
    return {
        "versions": versions or [],
        "files": [
            {
                "filename": name,
                "size": 10,
                "url": f"https://files.pythonhosted.org/{name}",
                "hashes": {"sha256": "ab"},
                "upload-time": "2026-03-19T14:22:25.026315Z",
                "yanked": name in yanked,
            }
            for name in filenames
        ],
    }


def previous(version: str, *filenames: str, **kwargs: Any) -> str | None:
    choice = choose_previous(version, page(*filenames, **kwargs))
    return None if choice is None else choice[0]


def test_versions_are_ordered_by_pep_440_not_as_strings() -> None:
    assert previous("1.10", "a-1.2.tar.gz", "a-1.9.tar.gz", "a-1.10.tar.gz") == "1.9"


def test_backport_is_compared_with_its_own_line() -> None:
    assert previous("1.9.5", "a-1.9.4.tar.gz", "a-2.0.0.tar.gz", "a-1.9.5.tar.gz") == "1.9.4"


def test_first_version_has_no_baseline() -> None:
    assert previous("1.0", "a-1.0.tar.gz", "a-2.0.tar.gz") is None


def test_final_release_skips_pre_releases() -> None:
    assert previous("2.0", "a-1.9.tar.gz", "a-2.0rc1.tar.gz", "a-2.0.dev1.tar.gz") == "1.9"


def test_final_release_falls_back_to_a_pre_release() -> None:
    assert previous("1.0", "a-1.0b1.tar.gz") == "1.0b1"


def test_pre_release_is_compared_with_the_pre_release_before_it() -> None:
    assert previous("2.0rc2", "a-1.9.tar.gz", "a-2.0rc1.tar.gz") == "2.0rc1"


def test_yanked_version_is_not_a_baseline() -> None:
    files = ("a-1.0.tar.gz", "a-1.1.tar.gz")
    assert previous("1.2", *files, yanked=("a-1.1.tar.gz",)) == "1.0"


def test_version_keeps_the_spelling_of_the_upload() -> None:
    assert previous("2024.2.1", "a-2024.1.1.tar.gz", versions=["2024.01.01"]) == "2024.01.01"


def test_invalid_versions_are_skipped() -> None:
    assert previous("not a version", "a-1.0.tar.gz") is None
    assert previous("1.0", "a-0.9.egg", "garbage.txt", "a-0.8.tar.gz") == "0.8"


def test_files_are_described_like_in_the_json_api() -> None:
    choice = choose_previous("2.0", page("a-1.0.tar.gz", "a-1.0-py3-none-any.whl"))

    assert choice is not None
    sdist, wheel = choice[1]
    assert sdist["packagetype"] == "sdist"
    assert wheel["packagetype"] == "bdist_wheel"
    assert wheel["digests"] == {"sha256": "ab"}
    assert wheel["upload_time_iso_8601"] == "2026-03-19T14:22:25.026315Z"


async def test_project_page_is_requested_by_the_normalized_name() -> None:
    """PyPI redirects other spellings, and a release of `PyYAML` must not fail on that."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/simple/zc-buildout/":
            return httpx.Response(200, json={"files": []})
        return httpx.Response(301, headers={"Location": "/simple/zc-buildout/"})

    client = PyPIClient(httpx.MockTransport(handler))
    try:
        assert await client.simple("zc.Buildout") == {"files": []}
    finally:
        await client.aclose()
