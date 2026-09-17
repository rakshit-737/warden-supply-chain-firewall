"""Filesystem discovery of dependency manifests for local project scans.

``discover_manifests(root)`` walks a checkout and returns the *contents* of known manifest files
(``requirements*.txt``, ``pyproject.toml``, ``poetry.lock``, ``Pipfile``, ``Pipfile.lock``, ...)
keyed by POSIX relative path, ready for :func:`app.sbom.parsers.parse_project`.

A checkout is attacker-influenced (a pull request controls its tree), so the walk is defensive:

* **No link following.** Symlinks are never followed, and on Windows neither are directory
  junctions or other reparse-point directories, so a link cannot pull files from outside the tree.
  Files are opened with ``O_NOFOLLOW`` where the platform supports it and the opened handle is
  compared with the pre-open ``lstat`` to catch a swap between listing and opening.
* **Bounded.** Directory depth (default 4), number of directory entries visited, number of
  manifests returned and bytes read per file are all capped. A directory listing is consumed
  lazily and never beyond the remaining entry budget, so one flat directory with millions of
  entries costs no more than the cap (in that case the visited entries are the first ones the
  OS lists, sorted by name). A file larger than
  ``MAX_MANIFEST_BYTES`` is returned truncated to ``MAX_MANIFEST_BYTES + 1`` bytes so that
  ``parse_project`` reports it as oversized instead of silently dropping it.
* **Known filenames only**, and dependency / build / VCS directories (``.git``, ``node_modules``,
  ``.venv``, ``venv``, ``__pycache__``, ``dist``, ``build``, tool caches) are skipped.

Files are only read, never executed or imported.
"""

from __future__ import annotations

import itertools
import os
import stat
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger
from app.sbom.npm import is_npm_manifest
from app.sbom.parsers import manifest_type

log = get_logger("warden.sbom.discover")

SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".hg", ".svn", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
})
MAX_DISCOVERED_FILES = 200
MAX_SCANNED_ENTRIES = 50_000
MAX_DEPTH_CAP = 16

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def discover_manifests(
    root: Path | str,
    max_depth: int = 4,
    *,
    warnings: list[str] | None = None,
    max_files: int = MAX_DISCOVERED_FILES,
) -> dict[str, bytes]:
    """Return ``{relative_posix_path: content}`` for known manifests under ``root``.

    ``max_depth`` counts directory levels below ``root`` (files directly in ``root`` are depth 0).
    Problems (unreadable directories, bounds reached) are appended to ``warnings`` when given.
    """
    notes = warnings if warnings is not None else []
    root_path = Path(root)
    try:
        if not root_path.is_dir():
            notes.append("discovery root is not a directory")
            return {}
    except OSError:
        notes.append("discovery root is not accessible")
        return {}
    depth_limit = max(0, min(int(max_depth), MAX_DEPTH_CAP))
    found: dict[str, bytes] = {}
    scanned = 0
    stack: list[tuple[str, tuple[str, ...], int]] = [(os.fspath(root_path), (), 0)]
    while stack:
        directory, rel_parts, depth = stack.pop()
        remaining = MAX_SCANNED_ENTRIES - scanned
        try:
            with os.scandir(directory) as iterator:
                # Never pull more than one entry past the budget out of the OS listing.
                listed = list(itertools.islice(iterator, remaining + 1))
        except OSError:
            notes.append(f"could not list directory {'/'.join(rel_parts) or '.'}")
            continue
        exhausted = len(listed) > remaining
        entries = sorted(listed[:remaining], key=lambda e: e.name)
        subdirs: list[tuple[str, tuple[str, ...], int]] = []
        for entry in entries:
            scanned += 1
            parts = (*rel_parts, entry.name)
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if entry.name.lower() in SKIP_DIRS or depth >= depth_limit or _is_link_like_dir(entry):
                    continue
                subdirs.append((entry.path, parts, depth + 1))
                continue
            rel = "/".join(parts)
            if manifest_type(rel) is None and is_npm_manifest(rel) is None:
                continue
            if len(found) >= max_files:
                notes.append(f"stopped after {max_files} manifest files")
                return found
            data = _read_regular_file(entry.path, rel, notes)
            if data is not None:
                found[rel] = data
        if exhausted:
            notes.append(f"stopped after visiting {MAX_SCANNED_ENTRIES} directory entries")
            log.warning("sbom_discovery_entry_limit", limit=MAX_SCANNED_ENTRIES)
            return found
        stack.extend(reversed(subdirs))
    return found


def _is_link_like_dir(entry: os.DirEntry) -> bool:
    """True for junctions / reparse-point directories (Windows) or anything that is not a plain dir."""
    try:
        is_junction = getattr(entry, "is_junction", None)
        if is_junction is not None and is_junction():
            return True
        st = os.lstat(entry.path)
    except OSError:
        return True
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return True
    return not stat.S_ISDIR(st.st_mode)


def _read_regular_file(path: str, rel: str, notes: list[str]) -> bytes | None:
    limit = settings.MAX_MANIFEST_BYTES
    try:
        before = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(before.st_mode):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY)
    except OSError:
        notes.append(f"could not open {rel}")
        return None
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode):
            return None
        if (before.st_ino and after.st_ino and before.st_ino != after.st_ino) or (
            before.st_dev and after.st_dev and before.st_dev != after.st_dev
        ):
            notes.append(f"{rel} changed while being read; skipped")
            return None
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)
    except OSError:
        notes.append(f"could not read {rel}")
        return None
    finally:
        os.close(fd)
