"""Which earlier version a new release is compared with."""

from typing import Any

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version


def choose_previous(
    version: str, simple: dict[str, Any]
) -> tuple[str, list[dict[str, Any]]] | None:
    """Pick the baseline from a PEP 691 project page: its version and its files.

    It is the highest lower version that users could really have installed. Yanked versions do not
    count, and a final release is compared with a final one: otherwise a payload shipped first in a
    yanked version or a pre-release would be absent from the diff of the release that spreads it.
    """
    try:
        current = Version(version)
    except InvalidVersion:
        return None

    by_version: dict[Version, list[dict[str, Any]]] = {}
    for file in simple.get("files", []):
        parsed = _file_version(file["filename"])
        if parsed is not None and parsed < current and not file.get("yanked"):
            by_version.setdefault(parsed, []).append(file)

    finals = [candidate for candidate in by_version if not candidate.is_prerelease]
    candidates = finals if finals and not current.is_prerelease else list(by_version)
    if not candidates:
        return None
    previous = max(candidates)
    return _original_spelling(previous, simple), [_as_json_file(f) for f in by_version[previous]]


def _file_version(filename: str) -> Version | None:
    try:
        if filename.endswith(".whl"):
            return parse_wheel_filename(filename)[1]
        return parse_sdist_filename(filename)[1]
    except (InvalidSdistFilename, InvalidWheelFilename, InvalidVersion):
        return None  # Eggs, and names from before PEP 440.


def _original_spelling(version: Version, simple: dict[str, Any]) -> str:
    """Filenames carry the normalized version; the JSON API and our rows use the uploaded one."""
    for spelling in simple.get("versions", []):
        try:
            if Version(spelling) == version:
                return str(spelling)
        except InvalidVersion:
            continue
    return str(version)


def _as_json_file(file: dict[str, Any]) -> dict[str, Any]:
    """Describe a Simple API file the way the JSON API does, for the common download path."""
    filename = file["filename"]
    return {
        "filename": filename,
        "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
        "size": file["size"],
        "url": file["url"],
        "digests": {"sha256": file["hashes"]["sha256"]},
        "upload_time_iso_8601": file["upload-time"],
        # PEP 740: a URL when the file was uploaded with attestations, by Trusted Publishing.
        "provenance": file.get("provenance"),
    }
