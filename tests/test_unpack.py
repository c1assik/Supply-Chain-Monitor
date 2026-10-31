import gzip
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from pypi_monitor.pipeline.unpack import (
    UnpackLimits,
    UnsafeArchiveError,
    UnsupportedArchiveError,
    unpack,
)

LIMITS = UnpackLimits(max_bytes=10_000_000, max_files=100, max_ratio=200)


def make_tar(path: Path, members: list[tarfile.TarInfo], payload: bytes = b"") -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for member in members:
            is_file = member.isreg()
            member.size = len(payload) if is_file else 0
            tar.addfile(member, io.BytesIO(payload) if is_file else None)
    return path


def symlink(name: str, target: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = tarfile.SYMTYPE
    member.linkname = target
    return member


def hardlink(name: str, target: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = tarfile.LNKTYPE
    member.linkname = target
    return member


def test_regular_archives_are_unpacked(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [tarfile.TarInfo("pkg/setup.py")], b"print('hi')")
    target = tmp_path / "out"

    unpack(archive, target, LIMITS)

    assert (target / "pkg/setup.py").read_bytes() == b"print('hi')"


def test_wheel_is_unpacked(tmp_path: Path) -> None:
    archive = tmp_path / "a-1-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("a/__init__.py", "x = 1")

    unpack(archive, tmp_path / "out", LIMITS)

    assert (tmp_path / "out/a/__init__.py").read_text() == "x = 1"


def test_unpacked_files_are_not_executable(tmp_path: Path) -> None:
    member = tarfile.TarInfo("run.sh")
    member.mode = 0o755
    archive = make_tar(tmp_path / "a.tar.gz", [member], b"#!/bin/sh")

    unpack(archive, tmp_path / "out", LIMITS)

    assert not stat.S_IMODE((tmp_path / "out/run.sh").stat().st_mode) & 0o111


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/evil.py", "..\\evil.py"])
def test_tar_path_traversal_is_rejected(tmp_path: Path, name: str) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [tarfile.TarInfo(name)], b"x")

    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "path_traversal"
    assert not (tmp_path / "evil.py").exists()


@pytest.mark.parametrize("name", ["../evil.py", "/tmp/evil.py", "C:\\evil.py"])
def test_zip_slip_is_rejected(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr(zipfile.ZipInfo(name), "x")

    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "path_traversal"


def test_links_are_not_created_and_cannot_redirect_writes(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    archive = make_tar(
        tmp_path / "a.tar.gz",
        [
            symlink("link", str(outside)),
            hardlink("hard", "/etc/passwd"),
            tarfile.TarInfo("link/evil.py"),
        ],
        b"x",
    )

    unpack(archive, tmp_path / "out", LIMITS)

    assert not (tmp_path / "out/link").is_symlink()
    assert not (tmp_path / "out/hard").exists()
    assert list(outside.iterdir()) == []


def test_zip_symlink_is_skipped(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr(info, "/etc/passwd")

    unpack(archive, tmp_path / "out", LIMITS)

    assert not (tmp_path / "out/link").exists()
    assert not (tmp_path / "out/link").is_symlink()


def test_gzip_bomb_is_stopped_by_ratio(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.tar.gz"
    member = tarfile.TarInfo("zeros")
    member.size = 200 * 1024 * 1024
    with gzip.open(archive, "wb") as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        tar.addfile(member, _Zeros(member.size))

    assert archive.stat().st_size < 1024 * 1024
    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "too_large"
    assert sum(f.stat().st_size for f in tmp_path.rglob("zeros")) < 50 * 1024 * 1024


def test_zip_bomb_with_a_lying_header_is_stopped_by_real_size(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("zeros", b"\0" * (100 * 1024 * 1024))

    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "too_large"


def test_too_many_files_are_rejected(tmp_path: Path) -> None:
    members = [tarfile.TarInfo(f"f{i}") for i in range(LIMITS.max_files + 1)]
    archive = make_tar(tmp_path / "a.tar.gz", members)

    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "too_many_files"


def test_truncated_archive_is_reported_as_corrupt(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "a.tar.gz", [tarfile.TarInfo("f")], b"x" * 100_000)
    archive.write_bytes(archive.read_bytes()[:40])

    with pytest.raises(UnsafeArchiveError) as error:
        unpack(archive, tmp_path / "out", LIMITS)

    assert error.value.reason == "corrupt"


def test_unknown_format_is_unsupported(tmp_path: Path) -> None:
    archive = tmp_path / "a.exe"
    archive.write_bytes(b"MZ")

    with pytest.raises(UnsupportedArchiveError):
        unpack(archive, tmp_path / "out", LIMITS)


class _Zeros:
    def __init__(self, size: int) -> None:
        self._left = size

    def read(self, size: int = -1) -> bytes:
        size = min(size, self._left) if size >= 0 else self._left
        self._left -= size
        return b"\0" * size
