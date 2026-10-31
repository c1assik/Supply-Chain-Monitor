"""Unpacking of untrusted archives. Nothing from an archive is ever executed.

Limits count real decompressed bytes, because sizes declared in headers can lie. Links and
special files are skipped: they are never created, so no path can lead out of the target.
"""

import bz2
import gzip
import io
import lzma
import os
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Any, cast

_CHUNK = 64 * 1024

_TAR_OPENERS: dict[str, Callable[[Path], Any]] = {
    ".tar.gz": gzip.GzipFile,
    ".tgz": gzip.GzipFile,
    ".tar.bz2": bz2.BZ2File,
    ".tar.xz": lzma.LZMAFile,
    ".tar": io.FileIO,
}
_ZIP_SUFFIXES = (".zip", ".whl", ".egg")


class UnsafeArchiveError(Exception):
    """The archive breaks a rule. `reason` is a stable identifier used in signals."""

    def __init__(self, reason: str, detail: str) -> None:
        # Both go to Exception, so that the error survives pickling on its way from a process pool.
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail


class UnsupportedArchiveError(Exception):
    pass


@dataclass(frozen=True)
class UnpackLimits:
    max_bytes: int
    max_files: int
    max_ratio: int


class _LimitedReader(io.RawIOBase):
    """Decompressed stream that stops at the byte limit, whatever the tar headers say."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._left = limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int:
        view = memoryview(cast(bytearray, buffer))
        data = self._stream.read(len(view))
        self._left -= len(data)
        if self._left < 0:
            raise UnsafeArchiveError("too_large", "decompressed stream is over the limit")
        view[: len(data)] = data
        return len(data)


def unpack(archive: Path, target: Path, limits: UnpackLimits) -> None:
    """Unpack `archive` into the empty directory `target`, or raise."""
    # A bomb is mostly recognized by its ratio, long before the absolute limit is reached.
    max_bytes = min(limits.max_bytes, archive.stat().st_size * limits.max_ratio + 1024 * 1024)
    name = archive.name.lower()
    for suffix, opener in _TAR_OPENERS.items():
        if name.endswith(suffix):
            _unpack_tar(opener(archive), target, max_bytes, limits.max_files)
            return
    if name.endswith(_ZIP_SUFFIXES):
        _unpack_zip(archive, target, max_bytes, limits.max_files)
        return
    raise UnsupportedArchiveError(archive.name)


def _unpack_tar(stream: IO[bytes], target: Path, max_bytes: int, max_files: int) -> None:
    budget = _Budget(max_bytes, max_files)
    try:
        with stream, _LimitedReader(stream, max_bytes) as raw:
            buffered = cast(IO[bytes], io.BufferedReader(raw))
            with tarfile.open(fileobj=buffered, mode="r|") as tar:
                for member in tar:
                    destination = _destination(target, member.name)
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    elif member.isreg():
                        source = tar.extractfile(member)
                        assert source is not None  # noqa: S101
                        _copy(source, destination, budget)
                    budget.count_file()
    except (tarfile.TarError, EOFError, OSError, lzma.LZMAError, ValueError) as e:
        raise UnsafeArchiveError("corrupt", str(e)) from e


def _unpack_zip(archive: Path, target: Path, max_bytes: int, max_files: int) -> None:
    budget = _Budget(max_bytes, max_files)
    try:
        with zipfile.ZipFile(archive) as zip_file:
            for info in zip_file.infolist():
                budget.count_file()
                destination = _destination(target, info.filename)
                # The Unix mode of the entry tells symlinks from regular files.
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                with zip_file.open(info) as source:
                    _copy(source, destination, budget)
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, NotImplementedError) as e:
        raise UnsafeArchiveError("corrupt", str(e)) from e


class _Budget:
    def __init__(self, max_bytes: int, max_files: int) -> None:
        self._bytes = max_bytes
        self._files = max_files

    def count_file(self) -> None:
        self._files -= 1
        if self._files < 0:
            raise UnsafeArchiveError("too_many_files", "too many archive members")

    def count_bytes(self, size: int) -> None:
        self._bytes -= size
        if self._bytes < 0:
            raise UnsafeArchiveError("too_large", "unpacked size is over the limit")


def _destination(target: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or ":" in (path.parts[0] if path.parts else ""):
        raise UnsafeArchiveError("path_traversal", repr(member_name))
    if "\0" in normalized:
        raise UnsafeArchiveError("path_traversal", repr(member_name))
    return target.joinpath(*path.parts)


def _copy(source: IO[bytes], destination: Path, budget: _Budget) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        while chunk := source.read(_CHUNK):
            budget.count_bytes(len(chunk))
            file.write(chunk)
