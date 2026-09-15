"""Safe, in-memory reader for hostile package archives (sdist tarballs, zip sdists, wheels).

Every byte handled here is attacker-controlled. The reader never writes to the filesystem,
never follows links and never executes anything; it produces a bounded, hashed inventory of
archive members plus size-capped text and binary contents for the analyzers.

Guards and the attack each is designed to defeat:

* **Format by magic bytes** (zip, gzip, bzip2, xz, plain tar) — a misleading file extension
  cannot route bytes to the wrong parser.
* **Bounded decompression** — tar streams are decompressed through a reader that counts
  decompressed bytes and refuses a read that would exceed the archive budget *before*
  performing it. Tar is opened in streaming mode (``"r|"``), so skipping a member still
  decompresses it; the budget therefore also covers skipped members and tar metadata.
* **Declared-size budget** — the sum of every member's declared size (including members that
  are skipped) is checked as each header is seen, before its data is decompressed, so a
  multi-gigabyte zero-filled member compressed to a few megabytes aborts immediately.
* **Tar metadata caps** — pax extended headers and GNU long-name records are buffered in
  memory by :mod:`tarfile`; their size is capped per header and in total before they are
  read. GNU sparse members (unbounded sparse maps) are refused.
* **Zip central-directory pre-walk** — entries are counted with a small parser that mirrors
  :mod:`zipfile` before ``ZipFile`` materialises one object per entry, so a small zip with
  hundreds of thousands of entries is refused cheaply. Declared sizes are summed before any
  entry is read; stored entries with inconsistent sizes and deflate entries claiming more
  expansion than deflate can produce are treated as lying headers.
* **Bounded zip codecs** — :mod:`zipfile` bounds output per read only for deflate; bzip2 and
  LZMA members are decompressed whole on the first read, so a few hundred bytes can expand to
  gigabytes before any size check runs. Those members are therefore streamed through
  :class:`_ZipCodecReader`, which asks the decompressor for at most one chunk per call, caps
  the LZMA dictionary and verifies the CRC-32.
* **Path safety** — backslashes are normalised; absolute, drive-letter, UNC and ``..`` paths
  abort extraction (v1 semantics). Names with control characters or invalid encodings and
  over-long / over-deep paths are recorded and skipped. Tar symlinks, hardlinks, devices and
  FIFOs are recorded, never read or followed.
* **Zip member types follow installers, not mode bits** — pip (wheel install and zip-sdist
  unpack) and :mod:`zipfile` treat an entry as a directory only when its name ends with
  ``/`` and write every other entry's bytes as a regular file, whatever Unix mode bits
  ``external_attr`` claims. Such an entry is analysed as a file; a contradicting symlink /
  directory / device mode is kept in ``InventoryEntry.declared_kind`` so the mismatch is
  reported instead of hiding importable code.
* **Retention budgets** — per-file analysis cap (truncating), total retained text, per-file
  and total retained binary bytes, member count, and a wall-clock budget. Member order is
  attacker-controlled, so the shared text budget never aborts extraction: a text member that
  no longer fits is hashed, inventoried with ``skipped_reason="text_budget_exceeded"`` and
  processing continues. Install- and interpreter-startup files (``setup.py``, ``setup.cfg``,
  ``pyproject.toml``, ``*.pth``, ``sitecustomize.py``, ``usercustomize.py``) draw on a separate
  reserve, so bulk text placed before them cannot keep them from being analysed; exhausting
  that reserve is itself treated as hostile.

Skipping content is itself an evasion vector, so every skipped member stays in the inventory
with a ``skipped_reason`` for the inventory analyzer to report. A tripped hostile-input guard
sets ``aborted_reason``; members processed before the abort are still returned.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import re
import stat
import struct
import tarfile
import time
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from app.analysis.analyzers.base import InventoryEntry, SourceFile
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.extraction")

CHUNK_SIZE = 64 * 1024
SNIFF_BYTES = 8 * 1024  # magic detection + "no NUL in the first 8 KiB" text rule
MAX_TAR_METADATA_HEADER_BYTES = 64 * 1024  # one pax extended header / GNU long-name record
MAX_TAR_METADATA_TOTAL_BYTES = 4 * 1024 * 1024
MAX_TAR_METADATA_CHAIN = 16  # consecutive pax / long-name headers before one real member
TAR_OVERHEAD_PER_MEMBER = 1536  # header block + worst-case data padding
DEFAULT_TIME_BUDGET_SECONDS = 60.0
MAX_WARNINGS = 200
# Deflate cannot expand input by more than ~1032:1; a larger claimed ratio is a lying header.
DEFLATE_MAX_RATIO = 1100
SUSPICIOUS_RATIO = 100
SUSPICIOUS_RATIO_MIN_BYTES = 10 * 1024 * 1024
# LZMA allocates its dictionary up front; an honest member never needs more than its own size.
MAX_LZMA_DICT_BYTES = 64 * 1024 * 1024
LZMA_DICT_MIN_BYTES = 4096
# Separate retention reserve for install/startup files (see module docstring).
PRIORITY_TEXT_RESERVE_BYTES = 16 * 1024 * 1024
PRIORITY_TEXT_NAMES = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "sitecustomize.py", "usercustomize.py"})
PRIORITY_TEXT_SUFFIXES = (".pth",)
TEXT_BUDGET_SKIP_REASON = "text_budget_exceeded"

TEXT_SUFFIXES = (
    ".py", ".pyi", ".pth", ".cfg", ".toml", ".ini", ".txt", ".json", ".yml", ".yaml",
    ".sh", ".bat", ".cmd", ".ps1", ".js",
)
TEXT_NAMES = frozenset({
    "setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO", "METADATA", "entry_points.txt", "RECORD", "WHEEL",
    "Dockerfile",
})
EXECUTABLE_MAGIC = frozenset({"elf", "pe", "macho"})
ARCHIVE_MAGIC = frozenset({"zip", "gzip", "bzip2", "xz", "7z", "rar", "tar"})
# Path problems that abort the whole extraction; every other problem skips the member.
ABORTING_PATH_PROBLEMS = frozenset({"absolute_path", "drive_letter", "unc_path", "traversal"})

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CONTROL_RE = re.compile("[\x00-\x1f\x7f]")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_MACHO_MAGIC = frozenset({b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"})
_MACHO_FAT_MAGIC = frozenset({b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"})
_BZIP2_BLOCK_MAGIC = (b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90")
_TAR_METADATA_TYPES = (
    tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
)


class _Abort(Exception):
    """A hostile-input guard tripped. ``reason`` is a stable machine-readable token."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass
class ExtractionResult:
    files: list[SourceFile] = field(default_factory=list)
    inventory: list[InventoryEntry] = field(default_factory=list)
    binaries: dict[str, bytes] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    aborted_reason: str | None = None
    # Sanitised, log-safe context for the abort (e.g. the offending member name).
    abort_detail: str | None = None
    archive_format: str | None = None  # zip | gzip | bzip2 | xz | tar | None (unrecognised)
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def aborted(self) -> bool:
        return self.aborted_reason is not None


# --------------------------------------------------------------------------- path safety
def display_name(name: object, max_len: int = 200) -> str:
    """Log/report-safe rendering of an attacker-controlled member name."""
    return sanitize_text(str(name).replace("\\", "/"), max_len=max_len, redact=False)


def _is_traversal_component(part: str) -> bool:
    # ".." plus Windows-equivalent spellings: Win32 strips trailing dots and spaces, so
    # ".. " or "..." can resolve to a parent directory when materialised on Windows.
    return part == ".." or (".." in part and part.strip(" .") == "")


def normalize_member_path(
    name: object, *, max_length: int | None = None, max_depth: int | None = None
) -> tuple[str, str | None]:
    """Normalise an archive member name to a safe ``/``-separated relative path.

    Returns ``(path, None)`` when safe, otherwise ``(display_name, problem)`` where ``problem``
    is one of: ``empty_name``, ``absolute_path``, ``drive_letter``, ``unc_path``,
    ``traversal`` (these abort extraction), ``control_character``, ``invalid_encoding``,
    ``path_too_deep``, ``path_too_long`` (these skip the member).
    """
    max_length = settings.MAX_PATH_LENGTH if max_length is None else max_length
    max_depth = settings.MAX_PATH_DEPTH if max_depth is None else max_depth
    if not isinstance(name, str) or not name:
        return "", "empty_name"
    unified = name.replace("\\", "/")
    shown = display_name(name, max_len=max(16, min(max_length, 512)))
    if unified.startswith("//"):
        return shown, "unc_path"
    if unified.startswith("/"):
        return shown, "absolute_path"
    if _DRIVE_RE.match(unified):
        return shown, "drive_letter"
    raw_parts = unified.split("/")
    if any(_is_traversal_component(p) for p in raw_parts):
        return shown, "traversal"
    if _CONTROL_RE.search(unified):
        return shown, "control_character"
    if _SURROGATE_RE.search(unified):
        return shown, "invalid_encoding"
    parts = [p for p in raw_parts if p not in ("", ".")]
    if not parts:
        return "", "empty_name"
    if len(parts) > max_depth:
        return shown, "path_too_deep"
    normalized = "/".join(parts)
    if len(normalized) > max_length:
        return shown, "path_too_long"
    return normalized, None


# --------------------------------------------------------------------------- magic bytes
def _is_pe(head: bytes) -> bool:
    if len(head) < 0x40:
        return False
    (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
    return e_lfanew + 4 <= len(head) and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def detect_magic(head: bytes) -> str | None:
    """Identify executables and archives from leading bytes (``None`` when unrecognised)."""
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ") and _is_pe(head):
        return "pe"
    if head[:4] in _MACHO_MAGIC:
        return "macho"
    if head[:4] in _MACHO_FAT_MAGIC and len(head) >= 8:
        # 0xCAFEBABE is shared with Java class files; a fat Mach-O has a small arch count
        # where a class file has its version number (>= 45).
        (count,) = struct.unpack_from(">I", head, 4)
        return "macho" if 0 < count < 20 else None
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[4:10] in _BZIP2_BLOCK_MAGIC:
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def detect_archive_format(data: bytes) -> str | None:
    """Container format of a distribution file: ``zip``, ``gzip``, ``bzip2``, ``xz``, ``tar`` or ``None``."""
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    magic = detect_magic(data[:SNIFF_BYTES])
    return magic if magic in {"gzip", "bzip2", "xz", "tar"} else None


# --------------------------------------------------------------------------- bounded I/O
class _BoundedReader:
    """File-like wrapper that refuses any read which would exceed ``limit`` decompressed bytes."""

    def __init__(self, raw: io.BufferedIOBase | io.BytesIO, limit: int, tick: Callable[[], None]) -> None:
        self._raw = raw
        self._limit = limit
        self._tick = tick
        self.consumed = 0

    def read(self, size: int = -1) -> bytes:
        self._tick()
        if size is None or size < 0:
            size = CHUNK_SIZE
        if self.consumed + size > self._limit:
            raise _Abort("decompressed_size_exceeded")
        chunk = self._raw.read(size)
        self.consumed += len(chunk)
        return chunk

    def close(self) -> None:  # the caller owns the underlying stream
        pass


def _lzma_filter(raw: bytes | memoryview, file_size: int) -> dict:
    """LZMA1 filter for a zip ``ZIP_LZMA`` member (APPNOTE 5.8.8 header), with a bounded dictionary."""
    if len(raw) < 4:
        raise EOFError("truncated LZMA member header")
    (props_size,) = struct.unpack_from("<H", raw, 2)
    if props_size != 5 or len(raw) < 9:
        raise zipfile.BadZipFile("unsupported LZMA properties header")
    packed = raw[4]
    if packed >= 9 * 5 * 5:
        raise zipfile.BadZipFile("invalid LZMA properties")
    lc, rest = packed % 9, packed // 9
    lp, pb = rest % 5, rest // 5
    (declared_dict,) = struct.unpack_from("<I", raw, 5)
    # Match distances can never exceed the bytes produced so far, so a dictionary larger than the
    # member's declared size is never needed by an honest stream (a lying size aborts anyway).
    dict_size = max(LZMA_DICT_MIN_BYTES, min(declared_dict, max(file_size, LZMA_DICT_MIN_BYTES)))
    if dict_size > MAX_LZMA_DICT_BYTES:
        raise _Abort("lzma_dictionary_too_large")
    return {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}


class _ZipCodecReader:
    """Bounded streaming reader for a bzip2 or LZMA zip member.

    Each :meth:`read` asks the decompressor for at most ``size`` bytes (``max_length``), feeding
    it compressed input only when it needs more, so memory stays bounded by one chunk however
    far the stream expands. The CRC-32 is verified at end of stream, as :mod:`zipfile` does.
    """

    _MAX_STALLS = 8

    def __init__(self, compressed: bytes | memoryview, compress_type: int, expected_crc: int, file_size: int) -> None:
        self._raw = memoryview(compressed)
        self._pos = 0
        self._expected_crc = expected_crc & 0xFFFFFFFF
        self._crc = 0
        if compress_type == zipfile.ZIP_BZIP2:
            self._dec = bz2.BZ2Decompressor()
        elif compress_type == zipfile.ZIP_LZMA:
            filt = _lzma_filter(self._raw, file_size)
            self._dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filt])
            self._pos = 9
        else:  # pragma: no cover - callers only route bzip2 / LZMA here
            raise ValueError("unsupported codec")

    def read(self, size: int = -1) -> bytes:
        if size is None or size <= 0:
            size = CHUNK_SIZE
        stalls = 0
        while not self._dec.eof:
            if self._dec.needs_input:
                chunk = bytes(self._raw[self._pos:self._pos + CHUNK_SIZE])
                self._pos += len(chunk)
                if not chunk:
                    raise EOFError("compressed zip member is truncated")
            else:
                chunk = b""
            out = self._dec.decompress(chunk, max_length=size)
            if out:
                self._crc = zlib.crc32(out, self._crc)
                return out
            if not chunk:
                stalls += 1
                if stalls > self._MAX_STALLS:
                    raise EOFError("decompressor made no progress")
        if self._crc != self._expected_crc:
            raise zipfile.BadZipFile("Bad CRC-32 for zip member")
        return b""

    def close(self) -> None:
        self._raw = memoryview(b"")

    def __enter__(self) -> _ZipCodecReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _SafeTarInfo(tarfile.TarInfo):
    """TarInfo that caps in-memory tar metadata before :mod:`tarfile` buffers it."""

    def _proc_member(self, tarfile_obj):
        # tarfile processes a metadata header by recursively reading the next header, so a long
        # chain of (even zero-sized) pax headers would otherwise exhaust the recursion limit.
        chain = getattr(tarfile_obj, "_warden_metadata_chain", 0) + 1 if self.type in _TAR_METADATA_TYPES else 0
        tarfile_obj._warden_metadata_chain = chain
        if chain > MAX_TAR_METADATA_CHAIN:
            raise _Abort("tar_metadata_chain_too_long")
        if self.type in _TAR_METADATA_TYPES:
            if self.size > MAX_TAR_METADATA_HEADER_BYTES:
                raise _Abort("tar_metadata_header_too_large")
            used = getattr(tarfile_obj, "_warden_metadata_bytes", 0) + max(self.size, 0)
            if used > MAX_TAR_METADATA_TOTAL_BYTES:
                raise _Abort("tar_metadata_exceeded")
            tarfile_obj._warden_metadata_bytes = used
        elif self.type == tarfile.GNUTYPE_SPARSE:
            raise _Abort("sparse_member_unsupported")
        return super()._proc_member(tarfile_obj)

    def _refuse_sparse(self, *args, **kwargs):
        raise _Abort("sparse_member_unsupported")

    # pax-format GNU sparse maps (0.0 / 0.1 / 1.0) are unbounded; refuse them too.
    _proc_gnusparse_00 = _refuse_sparse
    _proc_gnusparse_01 = _refuse_sparse
    _proc_gnusparse_10 = _refuse_sparse


@dataclass(frozen=True)
class _Limits:
    max_members: int
    max_declared_bytes: int
    max_text_bytes: int
    max_file_bytes: int
    max_binary_bytes: int
    max_binary_file_bytes: int
    max_path_length: int
    max_path_depth: int
    time_budget_seconds: float
    max_priority_text_bytes: int = PRIORITY_TEXT_RESERVE_BYTES


class _State:
    """Per-``read`` counters. A reader instance is stateless between calls."""

    def __init__(self, limits: _Limits, clock: Callable[[], float]) -> None:
        self.limits = limits
        self.clock = clock
        self.started = clock()
        self.deadline = self.started + limits.time_budget_seconds
        self.members = 0
        self.declared_bytes = 0
        self.read_bytes = 0
        self.text_bytes = 0
        self.priority_text_bytes = 0
        self.budget_skipped = 0
        self.binary_bytes = 0
        self.suppressed_warnings = 0
        self.seen: set[str] = set()
        self.top_dirs: set[str] = set()

    def tick(self) -> None:
        if self.clock() > self.deadline:
            raise _Abort("time_budget_exceeded")

    def count_member(self) -> None:
        self.tick()
        self.members += 1
        if self.members > self.limits.max_members:
            raise _Abort("too_many_members")

    def add_declared(self, size: int) -> None:
        self.declared_bytes += max(int(size), 0)
        if self.declared_bytes > self.limits.max_declared_bytes:
            raise _Abort("declared_size_exceeded")


def _warn(result: ExtractionResult, state: _State, message: str) -> None:
    if len(result.warnings) < MAX_WARNINGS:
        result.warnings.append(message)
    else:
        state.suppressed_warnings += 1


def _zip_central_directory_count(data: bytes, stop_after: int) -> int | None:
    """Count central-directory entries the way :mod:`zipfile` walks them, stopping early.

    Returns ``None`` when the structure cannot be located (``zipfile`` then reports the error).
    """
    size = len(data)
    if size >= 22 and data[-22:-18] == b"PK\x05\x06" and data[-2:] == b"\x00\x00":
        eocd = size - 22
    else:
        eocd = data.rfind(b"PK\x05\x06", max(size - 65536 - 22, 0))
    if eocd < 0 or eocd + 22 > size:
        return None
    _sig, _d1, _d2, _n1, _n2, cd_size, cd_offset, _clen = struct.unpack("<4s4H2LH", data[eocd:eocd + 22])
    concat = eocd - cd_size - cd_offset
    locator = eocd - 20
    has_zip64 = locator >= 56 and data[locator:locator + 4] == b"PK\x06\x07"
    if has_zip64 and data[locator - 56:locator - 52] == b"PK\x06\x06":
        fields = struct.unpack("<4sQ2H2L4Q", data[locator - 56:locator])
        cd_size, cd_offset = fields[8], fields[9]
        concat = eocd - cd_size - cd_offset - 76
    start = cd_offset + concat
    if start < 0 or start + cd_size > size:
        return None
    count = total = 0
    pos = start
    while total < cd_size:
        if pos + 46 > size or data[pos:pos + 4] != b"PK\x01\x02":
            return None
        name_len, extra_len, comment_len = struct.unpack_from("<3H", data, pos + 28)
        step = 46 + name_len + extra_len + comment_len
        total += step
        pos += step
        count += 1
        if count > stop_after:
            break
    return count


def _tar_kind(member: tarfile.TarInfo) -> tuple[str, str | None]:
    if member.isreg():
        return "file", None
    if member.isdir():
        return "dir", None
    if member.issym():
        return "symlink", "symlink"
    if member.islnk():
        return "hardlink", "hardlink"
    if member.ischr() or member.isblk():
        return "device", "device"
    if member.isfifo():
        return "other", "fifo"
    if member.type not in tarfile.SUPPORTED_TYPES:
        # tarfile (and therefore pip) extracts unknown member types as regular files, so they
        # must be analysed as files rather than skipped.
        return "file", None
    return "other", "unsupported_member_type"


def _zip_declared_kind(info: zipfile.ZipInfo) -> str | None:
    """Non-regular member type claimed by Unix mode bits in ``external_attr`` (``None`` otherwise)."""
    mode = info.external_attr >> 16
    if info.create_system != 3 or not mode:
        return None
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISDIR(mode):
        return "dir"
    return None


def _zip_kind(info: zipfile.ZipInfo) -> tuple[str, str | None]:
    """``(kind, declared_kind)``: what installers do with the entry, and any contradicting mode bits.

    pip and :mod:`zipfile` decide file-vs-directory by the trailing ``/`` alone and write every
    other entry's bytes as a regular file, so mode bits must never keep content from analysis.
    """
    if info.orig_filename.endswith(("/", "\\")):
        return "dir", None
    return "file", _zip_declared_kind(info)


class SafeArchiveReader:
    """Reads a distribution archive held in memory into an :class:`ExtractionResult`.

    Limits default to the ``settings`` values at the time :meth:`read` is called; keyword
    arguments override them (used by tests and by callers with tighter budgets).
    """

    def __init__(
        self,
        *,
        max_members: int | None = None,
        max_declared_bytes: int | None = None,
        max_text_bytes: int | None = None,
        max_file_bytes: int | None = None,
        max_binary_bytes: int | None = None,
        max_binary_file_bytes: int | None = None,
        time_budget_seconds: float | None = None,
        max_priority_text_bytes: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._overrides = {
            "max_members": max_members,
            "max_declared_bytes": max_declared_bytes,
            "max_text_bytes": max_text_bytes,
            "max_file_bytes": max_file_bytes,
            "max_binary_bytes": max_binary_bytes,
            "max_binary_file_bytes": max_binary_file_bytes,
            "time_budget_seconds": time_budget_seconds,
            "max_priority_text_bytes": max_priority_text_bytes,
        }
        self._clock = clock

    def _limits(self) -> _Limits:
        defaults = {
            "max_members": settings.MAX_EXTRACTED_FILES,
            "max_declared_bytes": settings.MAX_DECLARED_ARCHIVE_BYTES,
            "max_text_bytes": settings.MAX_EXTRACTED_BYTES,
            "max_file_bytes": settings.MAX_ANALYZED_FILE_BYTES,
            "max_binary_bytes": settings.MAX_RETAINED_BINARY_BYTES,
            "max_binary_file_bytes": settings.MAX_RETAINED_BINARY_FILE_BYTES,
            "time_budget_seconds": float(settings.EXTRACTION_TIMEOUT_SECONDS or DEFAULT_TIME_BUDGET_SECONDS),
            "max_priority_text_bytes": PRIORITY_TEXT_RESERVE_BYTES,
        }
        values = {k: (v if v is not None else defaults[k]) for k, v in self._overrides.items()}
        return _Limits(max_path_length=settings.MAX_PATH_LENGTH, max_path_depth=settings.MAX_PATH_DEPTH, **values)

    # ------------------------------------------------------------------ entry point
    def read(self, data: bytes, filename: str) -> ExtractionResult:
        result = ExtractionResult()
        state = _State(self._limits(), self._clock)
        name = str(filename or "")
        is_wheel = name.lower().endswith(".whl")
        fmt = detect_archive_format(data) if data else None
        result.archive_format = fmt
        try:
            if fmt is None:
                raise _Abort("unsupported_format")
            expected_zip = name.lower().endswith((".whl", ".zip", ".egg"))
            if expected_zip != (fmt == "zip"):
                _warn(result, state, f"format_mismatch: content is {fmt}, filename is {display_name(name, 120)}")
            if fmt == "zip":
                self._read_zip(data, not is_wheel, state, result)
            else:
                self._read_tar(data, fmt, not is_wheel, state, result)
            if not result.inventory:
                _warn(result, state, "empty_archive")
        except _Abort as exc:
            result.aborted_reason, result.abort_detail = exc.reason, exc.detail
        except (tarfile.TarError, zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, OSError, zlib.error,
                lzma.LZMAError, ValueError, struct.error, UnicodeError) as exc:
            result.aborted_reason, result.abort_detail = "corrupt_archive", type(exc).__name__
        except Exception as exc:  # fail closed: a parser bug must never crash the scan
            result.aborted_reason, result.abort_detail = "extraction_error", type(exc).__name__
        if state.suppressed_warnings:
            result.warnings.append(f"{state.suppressed_warnings} further warnings suppressed")
        result.stats = {
            "members": state.members,
            "declared_bytes": state.declared_bytes,
            "read_bytes": state.read_bytes,
            "retained_text_bytes": state.text_bytes + state.priority_text_bytes,
            "retained_priority_text_bytes": state.priority_text_bytes,
            "text_budget_skipped": state.budget_skipped,
            "retained_binary_bytes": state.binary_bytes,
            "elapsed_ms": int((self._clock() - state.started) * 1000),
        }
        if result.aborted_reason:
            log.warning("extraction_aborted", reason=result.aborted_reason, archive_format=fmt,
                        members=state.members)
        return result

    # ------------------------------------------------------------------ tar
    def _read_tar(self, data: bytes, fmt: str, strip_top: bool, state: _State, result: ExtractionResult) -> None:
        source = io.BytesIO(data)
        raw: io.BufferedIOBase | io.BytesIO
        if fmt == "gzip":
            raw = gzip.GzipFile(fileobj=source, mode="rb")
        elif fmt == "bzip2":
            raw = bz2.BZ2File(source)
        elif fmt == "xz":
            raw = lzma.LZMAFile(source)
        else:
            raw = source
        limits = state.limits
        overhead = (limits.max_members + 64) * TAR_OVERHEAD_PER_MEMBER + MAX_TAR_METADATA_TOTAL_BYTES
        reader = _BoundedReader(raw, limits.max_declared_bytes + overhead, state.tick)
        try:
            with tarfile.open(fileobj=reader, mode="r|", tarinfo=_SafeTarInfo, encoding="utf-8",
                              errors="surrogateescape") as tar:
                while True:
                    member = tar.next()
                    if member is None:
                        break
                    tar.members.clear()  # streaming: never accumulate TarInfo objects
                    self._tar_member(tar, member, strip_top, state, result)
        finally:
            state.read_bytes = max(state.read_bytes, reader.consumed)
            raw.close()

    def _tar_member(self, tar: tarfile.TarFile, member: tarfile.TarInfo, strip_top: bool, state: _State,
                    result: ExtractionResult) -> None:
        state.count_member()
        rel, problem = normalize_member_path(member.name, max_length=state.limits.max_path_length,
                                             max_depth=state.limits.max_path_depth)
        if problem in ABORTING_PATH_PROBLEMS:
            raise _Abort("unsafe_path", f"{problem}: {rel}")
        size = max(int(member.size), 0)
        state.add_declared(size)  # before tarfile decompresses (or skips) the data
        kind, reason = _tar_kind(member)
        mode = member.mode & 0o7777 if isinstance(member.mode, int) else None
        if member.type not in tarfile.SUPPORTED_TYPES:
            _warn(result, state, f"unknown tar member type treated as file: {rel}")
        if kind in ("symlink", "hardlink") and not problem:
            target, target_problem = normalize_member_path(member.linkname)
            if target_problem in ABORTING_PATH_PROBLEMS:
                _warn(result, state, f"{kind} {rel} points outside the archive ({target_problem})")
        self._record(lambda: tar.extractfile(member), rel, problem, kind, reason, size, mode, strip_top, state,
                     result)

    # ------------------------------------------------------------------ zip
    def _read_zip(self, data: bytes, strip_top: bool, state: _State, result: ExtractionResult) -> None:
        limits = state.limits
        counted = _zip_central_directory_count(data, limits.max_members)
        if counted is not None and counted > limits.max_members:
            raise _Abort("too_many_members")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_members:
                raise _Abort("too_many_members")
            for info in infos:  # every declared size is budgeted before any entry is read
                state.add_declared(info.file_size)
            for info in infos:
                self._zip_member(zf, data, info, strip_top, state, result)

    def _zip_member(self, zf: zipfile.ZipFile, data: bytes, info: zipfile.ZipInfo, strip_top: bool, state: _State,
                    result: ExtractionResult) -> None:
        state.count_member()
        rel, problem = normalize_member_path(info.orig_filename, max_length=state.limits.max_path_length,
                                             max_depth=state.limits.max_path_depth)
        if problem in ABORTING_PATH_PROBLEMS:
            raise _Abort("unsafe_path", f"{problem}: {rel}")
        kind, declared_kind = _zip_kind(info)
        reason: str | None = None
        mode_bits = info.external_attr >> 16
        mode = mode_bits & 0o7777 if info.create_system == 3 and mode_bits else None
        size = max(int(info.file_size), 0)
        opener: Callable[[], io.BufferedIOBase | _ZipCodecReader | None] = lambda: zf.open(info)  # noqa: E731
        if kind == "file" and not problem:
            if declared_kind:
                _warn(result, state, f"zip entry {rel} claims {declared_kind} mode bits but installers write it as a "
                                     "regular file; analysed as a file")
            if info.flag_bits & 0x1:
                kind, reason = "file", "encrypted"
                _warn(result, state, f"encrypted zip entry skipped: {rel}")
            elif info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2,
                                            zipfile.ZIP_LZMA):
                kind, reason = "file", "unsupported_compression"
                _warn(result, state, f"zip entry with unsupported compression skipped: {rel}")
            else:
                self._check_zip_ratio(info, rel, state, result)
                if info.compress_type in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
                    opener = lambda: self._open_codec_member(zf, data, info, rel)  # noqa: E731
        self._record(opener, rel, problem, kind, reason, size, mode, strip_top, state, result,
                     declared_kind=declared_kind)

    @staticmethod
    def _open_codec_member(zf: zipfile.ZipFile, data: bytes, info: zipfile.ZipInfo, rel: str) -> _ZipCodecReader:
        """Validate the local header with :mod:`zipfile`, then stream the raw data through a bounded codec."""
        zf.open(info).close()  # name / signature checks only; nothing is decompressed
        offset = info.header_offset
        header = data[offset:offset + 30]
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise zipfile.BadZipFile("bad local file header")
        name_len, extra_len = struct.unpack_from("<2H", header, 26)
        start = offset + 30 + name_len + extra_len
        compressed = memoryview(data)[start:start + info.compress_size]
        if len(compressed) != info.compress_size:
            raise EOFError("zip member data is truncated")
        try:
            return _ZipCodecReader(compressed, info.compress_type, info.CRC, max(int(info.file_size), 0))
        except _Abort as exc:
            raise _Abort(exc.reason, rel) from None

    @staticmethod
    def _check_zip_ratio(info: zipfile.ZipInfo, rel: str, state: _State, result: ExtractionResult) -> None:
        if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
            raise _Abort("inconsistent_member_header", rel)
        compressed = max(info.compress_size, 1)
        if info.compress_type == zipfile.ZIP_DEFLATED and info.file_size > compressed * DEFLATE_MAX_RATIO + 1024:
            raise _Abort("suspicious_compression_ratio", rel)
        if info.file_size >= SUSPICIOUS_RATIO_MIN_BYTES and info.file_size > compressed * SUSPICIOUS_RATIO:
            ratio = info.file_size // compressed
            _warn(result, state, f"suspicious compression ratio {ratio}:1 for {rel}")

    # ------------------------------------------------------------------ shared member handling
    def _record(self, opener: Callable[[], io.BufferedIOBase | _ZipCodecReader | None], rel: str,
                problem: str | None, kind: str, reason: str | None, size: int, mode: int | None, strip_top: bool,
                state: _State, result: ExtractionResult, *, declared_kind: str | None = None) -> None:
        if problem:
            if problem != "empty_name":
                _warn(result, state, f"member skipped ({problem}): {rel}")
                result.inventory.append(InventoryEntry(relpath=rel, size=size, kind=kind, mode=mode,
                                                       skipped_reason=problem))
            return
        if strip_top:
            head, sep, rest = rel.partition("/")
            if not sep:
                if kind == "dir":
                    return  # the sdist's top-level directory itself
            else:
                state.top_dirs.add(head)
                if len(state.top_dirs) == 2:
                    _warn(result, state, "sdist has more than one top-level directory")
                rel = rest
        if sanitize_text(rel, max_len=0, redact=False) != rel:
            _warn(result, state, f"deceptive (bidi / zero-width) characters in member name: {display_name(rel)}")
        if kind == "file" and reason is None:
            if rel in state.seen:
                _warn(result, state, f"duplicate member name: {rel}")
            state.seen.add(rel)
            self._consume(opener, rel, size, mode, state, result, declared_kind=declared_kind)
            return
        if kind == "file" and reason:  # encrypted / unsupported compression: never read
            state.seen.add(rel)
        result.inventory.append(InventoryEntry(relpath=rel, size=size, kind=kind, mode=mode, skipped_reason=reason,
                                               declared_kind=declared_kind))

    def _consume(self, opener: Callable[[], io.BufferedIOBase | _ZipCodecReader | None], rel: str, size: int,
                 mode: int | None, state: _State, result: ExtractionResult, *,
                 declared_kind: str | None = None) -> None:
        limits = state.limits
        base = rel.rsplit("/", 1)[-1]
        text_candidate = base in TEXT_NAMES or base.lower().endswith(TEXT_SUFFIXES)
        priority = text_candidate and (base in PRIORITY_TEXT_NAMES or base.lower().endswith(PRIORITY_TEXT_SUFFIXES))
        retain_text = text_candidate
        if text_candidate:
            need = min(size, limits.max_file_bytes)
            if priority:
                if state.priority_text_bytes + need > limits.max_priority_text_bytes:
                    raise _Abort("priority_text_budget_exceeded", rel)
            elif state.text_bytes + need > limits.max_text_bytes:
                # Never abort on the shared budget: member order is attacker-controlled, and an abort
                # would leave every later member (install hooks included) unread.
                retain_text = False
        keep_binary = (not text_candidate and size <= limits.max_binary_file_bytes
                       and state.binary_bytes + size <= limits.max_binary_bytes)
        handle = opener()
        if handle is None:
            result.inventory.append(InventoryEntry(relpath=rel, size=size, kind="other", mode=mode,
                                                   skipped_reason="no_data", declared_kind=declared_kind))
            return
        hasher = hashlib.sha256()
        head = bytearray()
        text_buf = bytearray()
        bin_buf = bytearray()
        total = 0
        with handle:
            while True:
                state.tick()
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise _Abort("member_size_mismatch", rel)
                hasher.update(chunk)
                if len(head) < SNIFF_BYTES:
                    head += chunk[:SNIFF_BYTES - len(head)]
                if retain_text and len(text_buf) < limits.max_file_bytes:
                    text_buf += chunk[:limits.max_file_bytes - len(text_buf)]
                if keep_binary:
                    bin_buf += chunk
        state.read_bytes += total
        if total != size:
            raise _Abort("member_size_mismatch", rel)
        digest = hasher.hexdigest()
        magic = detect_magic(bytes(head))
        entry = InventoryEntry(relpath=rel, size=size, kind="file", sha256=digest, magic=magic,
                               is_executable_binary=magic in EXECUTABLE_MAGIC, mode=mode, declared_kind=declared_kind)
        if text_candidate and not retain_text:
            state.budget_skipped += 1
            entry.skipped_reason = TEXT_BUDGET_SKIP_REASON
            _warn(result, state, f"retained-text budget exhausted; member hashed but not analysed: {display_name(rel)}")
        elif text_candidate and b"\x00" not in head:
            if priority:
                state.priority_text_bytes += len(text_buf)
            else:
                state.text_bytes += len(text_buf)
            result.files.append(SourceFile(relpath=rel, text=text_buf.decode("utf-8", errors="replace"), size=size,
                                           truncated=size > limits.max_file_bytes, sha256=digest))
            entry.is_text = entry.retained = True
        else:
            data = bin_buf if keep_binary else (text_buf if text_candidate and len(text_buf) == size else None)
            fits = size <= limits.max_binary_file_bytes and state.binary_bytes + size <= limits.max_binary_bytes
            if data is not None and fits and rel not in result.binaries:
                result.binaries[rel] = bytes(data)
                state.binary_bytes += size
                entry.retained = True
        result.inventory.append(entry)
