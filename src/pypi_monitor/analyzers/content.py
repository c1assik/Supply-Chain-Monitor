"""What a file that is not Python holds: a native binary, a script, or opaque data.

Read from the bytes and never by running anything. Names lie, so a binary is told by its magic
number. Magic numbers lie too: four bytes of a PNG header in front of a payload are cheap, so a
known media or data format counts only when its structure holds, chunk checksums, table offsets
and sizes that agree with the file. A file that fails the check is judged as if it had no header.

Archives are looked into: an `.exe` inside a zip or a gzip is a binary all the same. Members are
read with limits of their own, only their first bytes unless they are archives in turn, and never
written to disk.
"""

import bz2
import io
import lzma
import math
import re
import struct
import tarfile
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Any, Protocol

SAMPLE_BYTES = 64 * 1024
MIN_BLOB_BYTES = 1024
# Random or encrypted bytes come close to 8 bits; machine code and text stay well below.
OPAQUE_ENTROPY = 7.5
# Base64 or hex text without breaks: a payload written out as one long word.
MIN_ENCODED_RUN = 2048
_ENCODED_RUN = re.compile(rb"[A-Za-z0-9+/=_-]{%d,}" % MIN_ENCODED_RUN)
# Weights are numbers: the exponent byte of a float repeats, random bytes do not. One lane of
# 16 KiB of random bytes stays above 7.9 bits.
_NUMERIC_LANE_ENTROPY = 7.0
_TAIL_BYTES = 1024

# Archives inside an artifact: how deep, how many members and how many bytes are looked at.
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 1000
MAX_UNPACKED_BYTES = 64 * 1024 * 1024
# A nested archive or a tar stream is read into memory up to this much; past it, members are not
# seen. Enough for the archives packages ship as data, and a payload has no reason to be bigger.
MAX_NESTED_BYTES = 16 * 1024 * 1024
_CHUNK = 64 * 1024

# `.bin` is not here: it is as often a model or a table as a program, so its magic decides.
BINARY_SUFFIXES = frozenset({".dll", ".dylib", ".elf", ".exe", ".pyc", ".pyd", ".so"})
_EXECUTABLE_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xcf\xfa\xed\xfe",  # Mach-O 64
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",  # Mach-O universal, and Java classes
)
_SCRIPT_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".cjs",
        ".cmd",
        ".command",
        ".js",
        ".jse",
        ".mjs",
        ".ps1",
        ".psm1",
        ".sh",
        ".vbe",
        ".vbs",
        ".wsf",
        ".zsh",
    }
)
# A script that fetches or decodes something to run it, as droppers do.
SCRIPT_FETCHES = re.compile(
    rb"curl\s|wget\s|Invoke-WebRequest|Invoke-Expression|\biex\b|DownloadString|DownloadFile"
    rb"|FromBase64String|-enc(?:odedcommand)?\s|base64\s+(?:-d|--decode)|certutil|bitsadmin"
    rb"|mshta|child_process|\beval\(",
    re.IGNORECASE,
)
# Weights and data dumps without a magic number of their own.
_DATA_SUFFIXES = frozenset(
    {
        ".bin",
        ".ckpt",
        ".gguf",
        ".h5",
        ".msgpack",
        ".npz",
        ".onnx",
        ".pb",
        ".pt",
        ".safetensors",
        ".tflite",
        ".mo",
    }
)


class Kind(StrEnum):
    BINARY = "binary"
    SCRIPT = "script"
    OPAQUE = "opaque"
    OTHER = "other"


@dataclass(frozen=True)
class Content:
    """What a file is. For an archive, what its most telling member is."""

    kind: Kind
    # The first bytes of the file or of the member that decided: a script is searched in them.
    head: bytes
    # Why opaque data looks like a payload.
    reason: str | None = None
    # `archive.zip!dir/evil.exe` when a member decided.
    member: str | None = None

    @property
    def fetches(self) -> re.Match[bytes] | None:
        return SCRIPT_FETCHES.search(self.head) if self.kind is Kind.SCRIPT else None


def classify(path: str, real: Path) -> Content:
    """What the file at `real`, shipped as `path`, holds."""
    with real.open("rb") as file:
        return _inspect(path, file, real.stat().st_size, _Budget(), 0)


def kind_of(path: str, head: bytes) -> Kind:
    """What a file is from its name and its first bytes alone, without looking into archives."""
    return _judge(path, head, len(head), head[-_TAIL_BYTES:])[0]


def opaque_reason(sample: bytes, encoded: bool = True) -> str | None:
    """Why the bytes look like a hidden payload, or None. `encoded`: a base64 word counts."""
    if len(sample) < MIN_BLOB_BYTES:
        return None
    bits = entropy(sample)
    if bits >= OPAQUE_ENTROPY and not _is_numeric(sample):
        return f"entropy {bits:.2f} bits per byte"
    run = _ENCODED_RUN.search(sample) if encoded else None
    if run is not None:
        return f"encoded text, {len(run[0])}+ characters without a break"
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum(count / total * math.log2(count / total) for count in Counter(data).values())


def _judge(
    path: str, head: bytes, size: int, tail: bytes, in_archive: bool = False
) -> tuple[Kind, str | None]:
    """Kind of a file, and why it is opaque.

    Arrays of numbers are not opaque: weights and tables have high byte entropy too. Inside an
    archive a long base64 word is not either: archives there are mostly fixtures of other packages,
    and a payload in an archive needs code outside it to decode it.
    """
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in BINARY_SUFFIXES or head.startswith(_EXECUTABLE_MAGIC):
        return Kind.BINARY, None
    if suffix in _SCRIPT_SUFFIXES or head.startswith(b"#!"):
        return Kind.SCRIPT, None
    claimed = _claimed_format(head)
    if claimed is not None:
        name, check = claimed
        if _holds(check, head, size, tail):
            return Kind.OTHER, None
        prefix = f"{name} header without {name} structure, "
    elif suffix in _DATA_SUFFIXES:
        if _is_model(head, size):
            return Kind.OTHER, None
        prefix = f"{suffix} without a known layout, "
    else:
        prefix = ""
    reason = opaque_reason(head, encoded=not in_archive)
    if reason is None:
        return Kind.OTHER, None
    return Kind.OPAQUE, prefix + reason


def _holds(check: "_Check", head: bytes, size: int, tail: bytes) -> bool:
    try:
        return check(head, size, tail)
    except (IndexError, ValueError, struct.error):
        return False


# Structure checks: (head, file size, last bytes) -> the format is what it says.
class _Check(Protocol):
    def __call__(self, head: bytes, size: int, tail: bytes, /) -> bool: ...


def _be16(data: bytes, at: int) -> int:
    return int(struct.unpack_from(">H", data, at)[0])


def _be32(data: bytes, at: int) -> int:
    return int(struct.unpack_from(">I", data, at)[0])


def _le16(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<H", data, at)[0])


def _le32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<I", data, at)[0])


def _ascii_tag(tag: bytes) -> bool:
    return len(tag) == 4 and all(0x20 <= byte < 0x7F for byte in tag)


def _png(head: bytes, size: int, tail: bytes) -> bool:
    if not head.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    position, chunks = 8, 0
    while position + 12 <= len(head):
        length = _be32(head, position)
        kind = head[position + 4 : position + 8]
        if not (_ascii_tag(kind) and kind.isalpha()):
            return False
        if chunks == 0 and (kind != b"IHDR" or length != 13):
            return False
        end = position + 12 + length
        if end > len(head):
            break  # The rest of the file was not read: what was is consistent.
        if zlib.crc32(head[position + 4 : end - 4]) != _be32(head, end - 4):
            return False
        chunks += 1
        if kind == b"IEND":
            # Bytes after the end are not part of an image.
            return size - end < MIN_BLOB_BYTES
        position = end
    return chunks > 0


# Segments that may follow the start of a JPEG: frames, tables, restart interval, comments, APPn.
_JPEG_MARKERS = frozenset([*range(0xC0, 0xD0), 0xDB, 0xDD, 0xFE, *range(0xE0, 0xF0)]) - {0xC8}


def _jpeg(head: bytes, size: int, tail: bytes) -> bool:
    position, segments = 2, 0
    while position + 4 <= len(head):
        if head[position] != 0xFF:
            return False
        marker = head[position + 1]
        if marker == 0xFF:
            position += 1
            continue
        if marker == 0xDA:  # Start of scan: entropy-coded data follows.
            return segments > 0
        length = _be16(head, position + 2)
        if marker not in _JPEG_MARKERS or length < 2:
            return False
        segments += 1
        position += 2 + length
    # The headers go on past the sample: only possible when the file does.
    return segments > 0 and size > len(head)


def _gif(head: bytes, size: int, tail: bytes) -> bool:
    if head[:6] not in (b"GIF87a", b"GIF89a") or not (_le16(head, 6) and _le16(head, 8)):
        return False
    packed = head[10]
    following = 13 + (3 * 2 ** ((packed & 0x07) + 1) if packed & 0x80 else 0)
    # A block follows: an extension, an image, or the end.
    return following >= len(head) or head[following] in (0x21, 0x2C, 0x3B)


def _riff(head: bytes, size: int, tail: bytes) -> bool:
    return abs(_le32(head, 4) + 8 - size) <= 1 and _ascii_tag(head[8:12])


def _pdf(head: bytes, size: int, tail: bytes) -> bool:
    return re.match(rb"%PDF-\d\.\d", head) is not None and b"%%EOF" in tail


def _woff(head: bytes, size: int, tail: bytes) -> bool:
    return _be32(head, 8) == size


def _sfnt(head: bytes, size: int, tail: bytes) -> bool:
    tables = _be16(head, 4)
    if not 1 <= tables <= 128:
        return False
    if _be16(head, 6) != 16 * 2 ** int(math.log2(tables)):
        return False
    for index in range(tables):
        record = 12 + 16 * index
        if record + 16 > len(head):
            break
        offset, length = _be32(head, record + 8), _be32(head, record + 12)
        if not _ascii_tag(head[record : record + 4]) or offset + length > size:
            return False
    return True


def _ico(head: bytes, size: int, tail: bytes) -> bool:
    count = _le16(head, 4)
    if not 1 <= count <= 256:
        return False
    for index in range(count):
        entry = 6 + 16 * index
        length, offset = _le32(head, entry + 8), _le32(head, entry + 12)
        if offset < 6 + 16 * count or offset + length > size:
            return False
    return True


def _icns(head: bytes, size: int, tail: bytes) -> bool:
    return _be32(head, 4) == size


def _numpy(head: bytes, size: int, tail: bytes) -> bool:
    major = head[6]
    start = 10 if major == 1 else 12
    if major not in (1, 2, 3):
        return False
    return head[start : start + 1] == b"{" and b"descr" in head[start : start + 128]


def _hdf(head: bytes, size: int, tail: bytes) -> bool:
    return head.startswith(b"\x89HDF\r\n\x1a\n")


def _parquet(head: bytes, size: int, tail: bytes) -> bool:
    return tail.endswith(b"PAR1")


def _arrow(head: bytes, size: int, tail: bytes) -> bool:
    return tail.endswith(b"ARROW1")


def _sqlite(head: bytes, size: int, tail: bytes) -> bool:
    page = _be16(head, 16)
    return (page == 1 or (512 <= page <= 32768 and page & (page - 1) == 0)) and head[
        21:24
    ] == b"\x40\x20\x20"


def _id3(head: bytes, size: int, tail: bytes) -> bool:
    return head[3] in (2, 3, 4) and head[4] != 0xFF and all(byte < 0x80 for byte in head[6:10])


def _ogg(head: bytes, size: int, tail: bytes) -> bool:
    if head[4] != 0 or head[5] & ~0x07:
        return False
    segments = head[26]
    following = 27 + segments + sum(head[27 : 27 + segments])
    return following >= len(head) or head[following : following + 4] in (b"OggS", b"")


def _flac(head: bytes, size: int, tail: bytes) -> bool:
    return head[4] & 0x7F == 0 and int.from_bytes(head[5:8]) == 34


def _tiff(head: bytes, size: int, tail: bytes) -> bool:
    offset = _le32(head, 4) if head.startswith(b"II") else _be32(head, 4)
    return 8 <= offset < size


def _mp4(head: bytes, size: int, tail: bytes) -> bool:
    return _ascii_tag(head[8:12])


def _seven_zip(head: bytes, size: int, tail: bytes) -> bool:
    return head[:6] == b"7z\xbc\xaf\x27\x1c" and zlib.crc32(head[12:32]) == _le32(head, 8)


def _zstd_frame(head: bytes, size: int, tail: bytes) -> bool:
    return head[4] & 0x08 == 0  # A reserved bit of the frame header.


# Formats that are high-entropy by nature: media, fonts, data. Archives are below.
_DATA_FORMATS: tuple[tuple[bytes, str, _Check], ...] = (
    (b"\x89PNG", "PNG", _png),
    (b"\xff\xd8\xff", "JPEG", _jpeg),
    (b"GIF8", "GIF", _gif),
    (b"RIFF", "RIFF", _riff),
    (b"7z\xbc\xaf", "7z", _seven_zip),
    (b"%PDF", "PDF", _pdf),
    (b"wOFF", "WOFF", _woff),
    (b"wOF2", "WOFF2", _woff),
    (b"\x00\x01\x00\x00", "TrueType", _sfnt),
    (b"OTTO", "OpenType", _sfnt),
    (b"true", "TrueType", _sfnt),
    (b"\x00\x00\x01\x00", "ICO", _ico),
    (b"icns", "ICNS", _icns),
    (b"\x93NUMPY", "NumPy", _numpy),
    (b"\x89HDF", "HDF5", _hdf),
    (b"PAR1", "Parquet", _parquet),
    (b"ARROW1", "Arrow", _arrow),
    (b"SQLite format 3\x00", "SQLite", _sqlite),
    (b"ID3", "MP3", _id3),
    (b"OggS", "Ogg", _ogg),
    (b"fLaC", "FLAC", _flac),
    (b"II*\x00", "TIFF", _tiff),
    (b"MM\x00*", "TIFF", _tiff),
    (b"\x00\x00\x00\x18ftyp", "MP4", _mp4),
    (b"\x00\x00\x00\x1cftyp", "MP4", _mp4),
    (b"\x00\x00\x00\x20ftyp", "MP4", _mp4),
    (b"\x28\xb5\x2f\xfd", "zstd", _zstd_frame),
    # Archives get here only when they could not be opened.
    (b"PK\x03\x04", "zip", lambda head, size, tail: False),
    (b"PK\x05\x06", "zip", lambda head, size, tail: size == 22),
    (b"\x1f\x8b", "gzip", lambda head, size, tail: False),
    (b"BZh", "bzip2", lambda head, size, tail: False),
    (b"\xfd7zXZ", "xz", lambda head, size, tail: False),
)


def _claimed_format(head: bytes) -> tuple[str, _Check] | None:
    for magic, name, check in _DATA_FORMATS:
        if head.startswith(magic):
            return name, check
    return None


def _is_model(head: bytes, size: int) -> bool:
    """Layouts of weights that have no magic of their own at the start."""
    if len(head) >= 9 and head[8:9] == b"{" and 2 <= _le32(head, 0) < size:
        return True  # safetensors: the length of a JSON header, then the header.
    if head[:1] == b"\x80" and head[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return True  # A pickle: legacy PyTorch checkpoints.
    if head[:4] == b"GGUF" or head[4:8] == b"TFL3":
        return True
    return head[:4] in (b"\xde\x12\x04\x95", b"\x95\x04\x12\xde")  # gettext


def _is_numeric(sample: bytes) -> bool:
    """Arrays of 16 or 32-bit numbers: one byte of each number is far from random."""
    if len(sample) < MIN_BLOB_BYTES:
        return False
    for stride in (2, 4, 8):
        lanes = (sample[offset::stride] for offset in range(stride))
        if min(entropy(lane) for lane in lanes) < _NUMERIC_LANE_ENTROPY:
            return True
    return False


# Archives.


@dataclass
class _Budget:
    """What one file may cost, its nested archives included."""

    bytes_left: int = MAX_UNPACKED_BYTES
    members_left: int = MAX_ARCHIVE_MEMBERS

    def take(self, count: int) -> bool:
        self.bytes_left -= count
        return self.bytes_left >= 0


_RANK = {Kind.BINARY: 4, Kind.SCRIPT: 2, Kind.OPAQUE: 1, Kind.OTHER: 0}


def _rank(found: Content) -> int:
    # A script that downloads is worse than a plain one, still below a binary.
    return _RANK[found.kind] + (1 if found.fetches is not None else 0)


def _archive_format(head: bytes) -> str | None:
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd") and _zstd is not None:
        return "zstd"
    if head[257:262] == b"ustar":
        return "tar"
    return None


def _inspect(path: str, file: IO[bytes], size: int, budget: _Budget, depth: int) -> Content:
    file.seek(0)
    head = file.read(SAMPLE_BYTES)
    file.seek(max(0, size - _TAIL_BYTES))
    tail = file.read(_TAIL_BYTES)
    archive = _archive_format(head)
    if archive is not None and depth < MAX_ARCHIVE_DEPTH:
        members = _members(archive, path, file, head, budget)
        if members is not None:
            worst = Content(Kind.OTHER, head)
            for member in members:
                found = _inspect_member(member, budget, depth + 1)
                if _rank(found) > _rank(worst):
                    worst = found
                if worst.kind is Kind.BINARY:
                    break
            return worst
    kind, reason = _judge(path, head, size, tail, in_archive=depth > 0)
    return Content(kind, head, reason)


@dataclass(frozen=True)
class _Member:
    name: str
    data: bytes  # The first bytes, or all of it up to the limit for an archive.
    encrypted: bool = False


def _inspect_member(member: _Member, budget: _Budget, depth: int) -> Content:
    if member.encrypted:
        return Content(Kind.OPAQUE, b"", "encrypted archive member", member.name)
    found = _inspect(member.name, io.BytesIO(member.data), len(member.data), budget, depth)
    if found.member is None:
        return Content(found.kind, found.head, found.reason, member.name)
    return found


def _members(
    archive: str, path: str, file: IO[bytes], head: bytes, budget: _Budget
) -> list[_Member] | None:
    """The members of an archive, or None when it is not the archive its header claims."""
    try:
        if archive == "zip":
            return list(_zip_members(path, file, budget))
        if archive == "tar":
            file.seek(0)
            raw = file.read(MAX_NESTED_BYTES)
            if not budget.take(len(raw)):
                return []
            return list(_tar_members(path, raw, budget))
        data = _decompress(archive, file, budget)
        if data is None:
            return None
        inner = PurePosixPath(path).stem or path
        if data[257:262] == b"ustar":
            return list(_tar_members(path, data, budget))
        return [_Member(f"{path}!{inner}", data)]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, tarfile.TarError, EOFError, OSError):
        return None


def _member_bytes(read: Callable[[int], bytes], budget: _Budget) -> bytes:
    data = read(SAMPLE_BYTES)
    if _archive_format(data) is not None:
        data += read(MAX_NESTED_BYTES - len(data))
    budget.take(len(data))
    return data


def _zip_members(path: str, file: IO[bytes], budget: _Budget) -> Iterator[_Member]:
    file.seek(0)
    with zipfile.ZipFile(file) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if budget.members_left <= 0 or budget.bytes_left <= 0:
                return
            budget.members_left -= 1
            name = f"{path}!{info.filename}"
            if info.flag_bits & 0x1:
                # Encrypted: what is inside cannot be told, and packages have no reason for it.
                yield _Member(name, b"", encrypted=True)
                continue
            try:
                with archive.open(info) as stream:
                    data = _member_bytes(stream.read, budget)
            except (NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError, OSError):
                continue
            yield _Member(name, data)


def _tar_members(path: str, data: bytes, budget: _Budget) -> Iterator[_Member]:
    archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115
    try:
        while budget.members_left > 0 and budget.bytes_left > 0:
            try:
                info = archive.next()
            except (tarfile.TarError, EOFError, OSError):
                return  # The stream was cut at the limit.
            if info is None:
                return
            if not info.isfile():
                continue
            budget.members_left -= 1
            stream = archive.extractfile(info)
            if stream is None:
                continue
            try:
                member = _member_bytes(stream.read, budget)
            except (tarfile.TarError, EOFError, OSError):
                return
            yield _Member(f"{path}!{info.name}", member)
    finally:
        archive.close()


class _Decompressor(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...


_zstd: Any
try:
    from compression import zstd as _zstd  # type: ignore[import-not-found,no-redef,unused-ignore]
except ImportError:  # Python before 3.14: zstd frames are only checked by their header.
    _zstd = None

_DECOMPRESSORS: dict[str, Callable[[], _Decompressor]] = {
    "bzip2": bz2.BZ2Decompressor,
    "xz": lzma.LZMADecompressor,
}
if _zstd is not None:
    _DECOMPRESSORS["zstd"] = _zstd.ZstdDecompressor
_DECOMPRESSION_ERRORS: tuple[type[Exception], ...] = (zlib.error, lzma.LZMAError, OSError, EOFError)
if _zstd is not None:
    _DECOMPRESSION_ERRORS += (_zstd.ZstdError,)


def _decompress(archive: str, file: IO[bytes], budget: _Budget) -> bytes | None:
    """The start of a compressed stream: its first bytes, all of it up to the limit for a tar."""
    file.seek(0)
    out = bytearray()
    limit = SAMPLE_BYTES
    try:
        if archive == "gzip":
            gzip_stream = zlib.decompressobj(wbits=31)
            while len(out) < limit and not gzip_stream.eof:
                chunk = gzip_stream.unconsumed_tail or file.read(_CHUNK)
                if not chunk:
                    break
                out += gzip_stream.decompress(chunk, limit - len(out))
                limit = _limit(out, limit)
        else:
            stream = _DECOMPRESSORS[archive]()
            while len(out) < limit and not stream.eof:
                chunk = file.read(_CHUNK) if stream.needs_input else b""
                if not chunk and stream.needs_input:
                    break
                out += stream.decompress(chunk, limit - len(out))
                limit = _limit(out, limit)
    except _DECOMPRESSION_ERRORS:
        if not out:
            return None
    if not out:
        return None
    budget.take(len(out))
    return bytes(out)


def _limit(out: bytearray, limit: int) -> int:
    """Read on past the sample only for what has to be read as a whole: a tar or an archive."""
    if (
        limit == SAMPLE_BYTES
        and len(out) >= 262
        and (out[257:262] == b"ustar" or _archive_format(bytes(out[:262])) is not None)
    ):
        return MAX_NESTED_BYTES
    return limit
