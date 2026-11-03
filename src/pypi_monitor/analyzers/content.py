"""What a file that is not Python holds: a native binary, a script, or opaque data.

Read from the first bytes and never by running anything. Names lie, so a binary is told by its
magic number, and a known compressed or media format by its own; a payload dressed as `logo.png`
without the PNG header is still opaque data.
"""

import math
import re
from collections import Counter
from enum import StrEnum
from pathlib import PurePosixPath

SAMPLE_BYTES = 64 * 1024
MIN_BLOB_BYTES = 1024
# Random or encrypted bytes come close to 8 bits; machine code and text stay well below.
OPAQUE_ENTROPY = 7.5
# Base64 or hex text without breaks: a payload written out as one long word.
MIN_ENCODED_RUN = 2048
_ENCODED_RUN = re.compile(rb"[A-Za-z0-9+/=_-]{%d,}" % MIN_ENCODED_RUN)

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
# Formats that are high-entropy by nature: archives, media, fonts, model weights.
_DATA_MAGIC = (
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"RIFF",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ",
    b"\x28\xb5\x2f\xfd",  # zstd
    b"7z\xbc\xaf",
    b"%PDF",
    b"wOFF",
    b"wOF2",
    b"\x00\x01\x00\x00",  # TrueType
    b"OTTO",
    b"\x00\x00\x01\x00",  # ICO
    b"icns",
    b"\x93NUMPY",
    b"\x89HDF",
    b"PAR1",
    b"ARROW1",
    b"SQLite format 3",
    b"ID3",
    b"OggS",
    b"fLaC",
    b"II*\x00",
    b"MM\x00*",
    b"\x00\x00\x00\x18ftyp",
    b"\x00\x00\x00\x1cftyp",
    b"\x00\x00\x00\x20ftyp",
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


def kind_of(path: str, head: bytes) -> Kind:
    """What a file is, from its name and its first bytes."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in BINARY_SUFFIXES or head.startswith(_EXECUTABLE_MAGIC):
        return Kind.BINARY
    if suffix in _SCRIPT_SUFFIXES or head.startswith(b"#!"):
        return Kind.SCRIPT
    if head.startswith(_DATA_MAGIC) or suffix in _DATA_SUFFIXES:
        return Kind.OTHER
    if opaque_reason(head) is not None:
        return Kind.OPAQUE
    return Kind.OTHER


def opaque_reason(sample: bytes) -> str | None:
    """Why the bytes look like a hidden payload, or None."""
    if len(sample) < MIN_BLOB_BYTES:
        return None
    bits = entropy(sample)
    if bits >= OPAQUE_ENTROPY:
        return f"entropy {bits:.2f} bits per byte"
    run = _ENCODED_RUN.search(sample)
    if run is not None:
        return f"encoded text, {len(run[0])}+ characters without a break"
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum(count / total * math.log2(count / total) for count in Counter(data).values())
