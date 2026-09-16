"""Local snapshot of public package-index project names (privacy-preserving presence checks).

Asking the public registry "does ``acme-internal-auth`` exist?" discloses the internal name to
the registry operator and anyone observing the traffic. Warden therefore answers presence
questions from a local snapshot of *all* public project names, built offline with::

    python -m app.analysis.depconf.index_snapshot build --out /var/lib/warden/pypi-names.txt.gz

and configured with ``PUBLIC_INDEX_SNAPSHOT_PATH``. The builder downloads the PEP 691 JSON root
index (``GET {PYPI_SIMPLE_BASE}/`` with ``Accept: application/vnd.pypi.simple.v1+json``) through
:class:`~app.core.http.SafeHttpClient` (host allowlist, HTTPS only, response size cap) - a single
request that names no private package.

File format
===========

Plain UTF-8/ASCII text, optionally gzip-compressed (detected by magic bytes, not by file name)::

    # warden-public-index-snapshot v1
    # source: https://pypi.org/simple/
    # generated_at: 2026-09-15T12:00:00Z
    # count: 612345
    a
    a-b
    ...

One PEP 503 canonical name per line, sorted. ``#`` lines before the first name form the header
(unknown keys are ignored; a file without a header loads with unknown source/date/count). Blank
lines and later comments are skipped. Lines that are not valid PEP 508 names - embedded spaces,
invalid characters, non-ASCII, longer than ``MAX_LINE_BYTES`` - are skipped and counted. Valid but
non-canonical names are canonicalised.

Loading is bounded because the file may be stale, corrupt or planted: at most ``max_bytes``
decompressed bytes (a gzip bomb aborts with ``kind="too_large"``), at most ``max_names`` names,
line reads capped at ``MAX_LINE_BYTES``. A file with no valid name is rejected (``kind="empty"``).

Membership is stored compactly as a sorted ``array('Q')`` of 64-bit BLAKE2b digests of the
canonical names (8 bytes per name; ~6 MiB for 700k names) and answered by binary search. Two names
sharing a digest is possible in principle; for a PyPI-sized snapshot the chance that a given
absent name reads as present is about n / 2**64 (around 4e-14).

When the header's ``count`` is larger than the number of valid names loaded, the snapshot is
marked incomplete and :meth:`PublicIndexSnapshot.presence` answers ``"unknown"`` instead of
``"absent"`` for names it does not contain: a truncated snapshot is not evidence of absence.
A snapshot is a point-in-time view; ``generated_at`` is reported so consumers can judge staleness.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import sys
import tempfile
import threading
import zlib
from array import array
from bisect import bisect_left
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from app.analysis.depconf import canonical_name
from app.core.config import settings
from app.core.http import OutboundHTTPError, SafeHttpClient, safe_url
from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.depconf.snapshot")

FORMAT_ID = "warden-public-index-snapshot"
FORMAT_VERSION = 1
SIMPLE_JSON_ACCEPT = "application/vnd.pypi.simple.v1+json"
GZIP_MAGIC = b"\x1f\x8b"

MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_NAMES = 3_000_000
MAX_LINE_BYTES = 512
MAX_HEADER_LINES = 64
MAX_HEADER_VALUE = 200
DEFAULT_BUILD_MAX_BYTES = 256 * 1024 * 1024
HARD_BUILD_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_BUILD_TIMEOUT_SECONDS = 120.0

PRESENT = "present"
ABSENT = "absent"
UNKNOWN = "unknown"


class SnapshotError(Exception):
    """A snapshot that cannot be loaded or built. ``kind`` is machine-readable and log-safe."""

    def __init__(self, message: str, *, kind: str) -> None:
        super().__init__(message)
        # not_found | not_a_file | io | too_large | corrupt | empty | invalid_response | network
        self.kind = kind


@dataclass(frozen=True)
class SnapshotHeader:
    format: str | None = None
    source: str | None = None
    generated_at: str | None = None
    count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"format": self.format, "source": self.source, "generated_at": self.generated_at, "count": self.count}


def _digest(canonical: str) -> int:
    return int.from_bytes(hashlib.blake2b(canonical.encode("ascii"), digest_size=8).digest(), "big")


class PublicIndexSnapshot:
    """Immutable, thread-safe membership view of public project names."""

    __slots__ = ("header", "names_read", "skipped_lines", "compressed", "_digests")

    def __init__(self, digests: Iterable[int], header: SnapshotHeader | None = None, *, names_read: int | None = None,
                 skipped_lines: int = 0, compressed: bool = False) -> None:
        ordered = array("Q", sorted(set(digests)))
        self._digests = ordered
        self.header = header or SnapshotHeader()
        self.names_read = len(ordered) if names_read is None else int(names_read)
        self.skipped_lines = int(skipped_lines)
        self.compressed = bool(compressed)

    @classmethod
    def from_names(cls, names: Iterable[str], header: SnapshotHeader | None = None) -> PublicIndexSnapshot:
        """Build a snapshot from names in memory (invalid names are ignored)."""
        canonical = [c for c in (canonical_name(n) for n in names) if c]
        return cls((_digest(c) for c in canonical), header, names_read=len(canonical))

    def __len__(self) -> int:
        return len(self._digests)

    def __contains__(self, name: object) -> bool:
        canonical = canonical_name(name)
        if canonical is None:
            return False
        value = _digest(canonical)
        index = bisect_left(self._digests, value)
        return index < len(self._digests) and self._digests[index] == value

    @property
    def complete(self) -> bool:
        """False when the header promised more names than were loaded (truncated or damaged file)."""
        return self.header.count is None or self.names_read >= self.header.count

    def presence(self, name: object) -> str:
        if name in self:
            return PRESENT
        return ABSENT if self.complete else UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.header.source,
            "generated_at": self.header.generated_at,
            "header_count": self.header.count,
            "loaded": len(self),
            "skipped_lines": self.skipped_lines,
            "complete": self.complete,
        }


# --------------------------------------------------------------------------- loading
def _parse_header_line(text: bytes, fields: dict[str, Any]) -> None:
    try:
        line = text[1:].decode("ascii").strip()
    except UnicodeDecodeError:
        return
    if line.startswith(FORMAT_ID):
        fields["format"] = sanitize_text(line, max_len=MAX_HEADER_VALUE)
        return
    key, sep, value = line.partition(":")
    key, value = key.strip().lower(), value.strip()
    if not sep or not value:
        return
    if key == "count":
        if value.isascii() and value.isdigit() and len(value) <= 12:
            fields["count"] = int(value)
    elif key in ("source", "generated_at"):
        fields[key] = sanitize_text(value, max_len=MAX_HEADER_VALUE)


def _parse_stream(stream: IO[bytes], *, max_bytes: int, max_names: int, compressed: bool) -> PublicIndexSnapshot:
    fields: dict[str, Any] = {}
    digests: list[int] = []
    in_header = True
    header_lines = skipped = names = total = 0

    def read() -> bytes:
        nonlocal total
        chunk = stream.readline(MAX_LINE_BYTES + 1)
        total += len(chunk)
        if total > max_bytes:
            raise SnapshotError(f"snapshot exceeds {max_bytes} decompressed bytes", kind="too_large")
        return chunk

    while True:
        line = read()
        if not line:
            break
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            while line and not line.endswith(b"\n"):  # drain an overlong line without buffering it
                line = read()
            skipped += 1
            in_header = False
            continue
        text = line.strip()
        if not text:
            continue
        if text.startswith(b"#"):
            if in_header and header_lines < MAX_HEADER_LINES:
                header_lines += 1
                _parse_header_line(text, fields)
            continue
        in_header = False
        try:
            candidate = text.decode("ascii")
        except UnicodeDecodeError:
            skipped += 1
            continue
        canonical = canonical_name(candidate)
        if canonical is None:
            skipped += 1
            continue
        names += 1
        if names > max_names:
            raise SnapshotError(f"snapshot has more than {max_names} names", kind="too_large")
        digests.append(_digest(canonical))

    if not names:
        raise SnapshotError("snapshot contains no valid project names", kind="empty")
    header = SnapshotHeader(format=fields.get("format"), source=fields.get("source"),
                            generated_at=fields.get("generated_at"), count=fields.get("count"))
    return PublicIndexSnapshot(digests, header, names_read=names, skipped_lines=skipped, compressed=compressed)


def load_snapshot(path: str | os.PathLike[str], *, max_bytes: int = MAX_DECOMPRESSED_BYTES,
                  max_names: int = MAX_SNAPSHOT_NAMES) -> PublicIndexSnapshot:
    """Load a snapshot file (plain or gzip). Raises :class:`SnapshotError`."""
    p = Path(path)
    try:
        stat = p.stat()
    except FileNotFoundError as exc:
        raise SnapshotError("snapshot file not found", kind="not_found") from exc
    except OSError as exc:
        raise SnapshotError("snapshot file is not accessible", kind="io") from exc
    if not p.is_file():
        raise SnapshotError("snapshot path is not a regular file", kind="not_a_file")
    if stat.st_size > max_bytes:
        raise SnapshotError(f"snapshot file exceeds {max_bytes} bytes", kind="too_large")
    try:
        with p.open("rb") as raw:
            compressed = raw.read(2) == GZIP_MAGIC
            raw.seek(0)
            if compressed:
                with gzip.GzipFile(fileobj=raw, mode="rb") as unzipped:
                    return _parse_stream(unzipped, max_bytes=max_bytes, max_names=max_names, compressed=True)
            return _parse_stream(raw, max_bytes=max_bytes, max_names=max_names, compressed=False)
    except SnapshotError:
        raise
    except (EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise SnapshotError("snapshot file is corrupt", kind="corrupt") from exc
    except OSError as exc:
        raise SnapshotError("snapshot file could not be read", kind="io") from exc


@dataclass(frozen=True)
class SnapshotStatus:
    """Outcome of loading the configured snapshot: ``ok`` | ``not_configured`` | ``error``."""

    status: str
    snapshot: PublicIndexSnapshot | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"status": self.status, "detail": self.detail}
        if self.snapshot is not None:
            out.update(self.snapshot.to_dict())
        return out


_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, tuple[tuple[int, int], PublicIndexSnapshot]] = {}


def load_configured_snapshot(path: str | None = None) -> SnapshotStatus:
    """Load ``PUBLIC_INDEX_SNAPSHOT_PATH`` (or ``path``), cached per file size + mtime.

    Never raises: a missing or broken snapshot is reported as ``error`` with a machine-readable
    detail (the file path is not included, so the status is safe to put in findings).
    """
    configured = settings.PUBLIC_INDEX_SNAPSHOT_PATH if path is None else path
    if not configured:
        return SnapshotStatus("not_configured", None, "PUBLIC_INDEX_SNAPSHOT_PATH is not set")
    key = os.path.abspath(str(configured))
    try:
        stat = os.stat(key)
        fingerprint = (stat.st_size, stat.st_mtime_ns)
    except OSError:
        fingerprint = None
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None and fingerprint is not None and cached[0] == fingerprint:
            return SnapshotStatus("ok", cached[1], None)
        try:
            snapshot = load_snapshot(key)
        except SnapshotError as exc:
            _CACHE.pop(key, None)
            log.warning("public_index_snapshot_unavailable", kind=exc.kind)
            return SnapshotStatus("error", None, f"snapshot {exc.kind}")
        if fingerprint is not None:
            _CACHE[key] = (fingerprint, snapshot)
        return SnapshotStatus("ok", snapshot, None)


def clear_snapshot_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


# --------------------------------------------------------------------------- building
@dataclass(frozen=True)
class BuildResult:
    path: str
    count: int
    skipped: int
    source: str
    generated_at: str


def render_snapshot(names: Iterable[str], *, source: str, generated_at: str) -> tuple[bytes, int]:
    """Snapshot file bytes (uncompressed) and name count: canonical, de-duplicated, sorted names."""
    unique = sorted({c for c in (canonical_name(n) for n in names) if c})
    header = [
        f"# {FORMAT_ID} v{FORMAT_VERSION}",
        f"# source: {sanitize_text(source, max_len=MAX_HEADER_VALUE)}",
        f"# generated_at: {sanitize_text(generated_at, max_len=MAX_HEADER_VALUE)}",
        f"# count: {len(unique)}",
    ]
    return ("\n".join([*header, *unique]) + "\n").encode("ascii"), len(unique)


def write_snapshot(names: Iterable[str], out: str | os.PathLike[str], *, source: str, generated_at: str,
                   compress: bool | None = None) -> int:
    """Atomically write a snapshot file; gzip when ``compress`` (default: ``out`` ends in ``.gz``).

    Output is deterministic for the same inputs (gzip mtime is fixed at 0). Returns the name count.
    """
    target = Path(out)
    data, count = render_snapshot(names, source=source, generated_at=generated_at)
    if compress is None:
        compress = target.name.lower().endswith(".gz")
    if compress:
        data = gzip.compress(data, compresslevel=9, mtime=0)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".snapshot-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return count


def fetch_public_project_names(http: SafeHttpClient, *, simple_base: str | None = None,
                               max_bytes: int = DEFAULT_BUILD_MAX_BYTES,
                               max_names: int = MAX_SNAPSHOT_NAMES) -> tuple[list[str], int, str]:
    """Download the PEP 691 JSON root index. Returns ``(canonical names, skipped entries, source URL)``."""
    url = (simple_base or settings.PYPI_SIMPLE_BASE).rstrip("/") + "/"
    try:
        result = http.request("GET", url, headers={"Accept": SIMPLE_JSON_ACCEPT}, max_bytes=max_bytes)
    except OutboundHTTPError as exc:
        kind = {"too_large": "too_large", "host_not_allowed": "refused", "scheme": "refused"}.get(exc.kind, "network")
        raise SnapshotError(f"public index download failed ({exc.kind})", kind=kind) from exc
    if result.status != 200:
        raise SnapshotError(f"public index returned HTTP {result.status}", kind="invalid_response")
    media_type = result.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != SIMPLE_JSON_ACCEPT:
        raise SnapshotError("public index did not return PEP 691 JSON", kind="invalid_response")
    try:
        data = result.json()
    except OutboundHTTPError as exc:
        raise SnapshotError("public index returned malformed JSON", kind="invalid_response") from exc
    meta = data.get("meta") if isinstance(data, dict) else None
    version = meta.get("api-version") if isinstance(meta, dict) else None
    if not isinstance(version, str) or version.split(".", 1)[0] != "1":
        raise SnapshotError("unsupported PEP 691 api-version", kind="invalid_response")
    projects = data.get("projects")
    if not isinstance(projects, list):
        raise SnapshotError("public index response has no project list", kind="invalid_response")
    if len(projects) > max_names:
        raise SnapshotError(f"public index lists more than {max_names} projects", kind="too_large")
    names: set[str] = set()
    skipped = 0
    for entry in projects:
        canonical = canonical_name(entry.get("name")) if isinstance(entry, dict) else None
        if canonical is None:
            skipped += 1
        else:
            names.add(canonical)
    if not names:
        raise SnapshotError("public index listed no valid project names", kind="empty")
    return sorted(names), skipped, safe_url(url)


def build_snapshot(out: str | os.PathLike[str], *, http: SafeHttpClient | None = None, simple_base: str | None = None,
                   max_bytes: int = DEFAULT_BUILD_MAX_BYTES, timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
                   clock: Callable[[], datetime] | None = None) -> BuildResult:
    """Download the public root index and write a snapshot to ``out``."""
    if not 0 < int(max_bytes) <= HARD_BUILD_MAX_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {HARD_BUILD_MAX_BYTES}")
    owned = http is None
    client = http or SafeHttpClient(
        name="public-index-snapshot", allowed_hosts=settings.REGISTRY_HOST_ALLOWLIST,
        max_response_bytes=int(max_bytes), timeout=float(timeout), retries=2,
        total_timeout=max(600.0, float(timeout) * 10),
    )
    try:
        names, skipped, source = fetch_public_project_names(client, simple_base=simple_base, max_bytes=int(max_bytes))
    finally:
        if owned:
            client.close()
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    generated_at = now.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    count = write_snapshot(names, out, source=source, generated_at=generated_at)
    return BuildResult(path=str(out), count=count, skipped=skipped, source=source, generated_at=generated_at)


# --------------------------------------------------------------------------- CLI
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.analysis.depconf.index_snapshot",
        description="Build or inspect Warden's local snapshot of public package-index project names.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="download the PEP 691 JSON root index and write a snapshot file")
    build.add_argument("--out", required=True, help="output file (gzip-compressed when it ends in .gz)")
    build.add_argument("--max-bytes", type=int, default=DEFAULT_BUILD_MAX_BYTES,
                       help=f"response size cap in bytes (default {DEFAULT_BUILD_MAX_BYTES})")
    build.add_argument("--simple-base", default=None, help="simple index base URL (default: PYPI_SIMPLE_BASE)")
    build.add_argument("--timeout", type=float, default=DEFAULT_BUILD_TIMEOUT_SECONDS,
                       help="per-operation network timeout in seconds")
    info = sub.add_parser("info", help="load a snapshot file and print its header and statistics")
    info.add_argument("path")
    return parser


def main(argv: list[str] | None = None, *, http: SafeHttpClient | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            result = build_snapshot(args.out, http=http, simple_base=args.simple_base, max_bytes=args.max_bytes,
                                    timeout=args.timeout)
            print(f"wrote {result.count} project names to {sanitize_text(result.path, max_len=500)} "
                  f"(source {result.source}, generated_at {result.generated_at}, skipped {result.skipped})")
            return 0
        snapshot = load_snapshot(args.path)
        for key, value in snapshot.to_dict().items():
            print(f"{key}: {sanitize_text(value, max_len=MAX_HEADER_VALUE)}")
        return 0
    except SnapshotError as exc:
        print(f"error ({exc.kind}): {sanitize_text(str(exc), max_len=300)}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {sanitize_text(str(exc), max_len=300)}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    raise SystemExit(main())
