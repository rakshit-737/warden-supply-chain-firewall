"""Manifest parsing: turn in-memory dependency manifests into a :class:`ProjectInventory`.

Design and security rationale
-----------------------------
* **Pure and in-memory.** Parsers receive file *contents* (``dict[path, bytes | str]``); they
  never open files, follow ``-r`` includes on disk, fetch URLs, expand environment variables or
  run a build backend. A manifest is attacker-influenced input (a pull request can edit it), so
  nothing in it may cause I/O.
* **Bounded.** Every manifest is capped at ``settings.MAX_MANIFEST_BYTES``, logical lines at
  :data:`MAX_LINE_CHARS`, the number of manifests at :data:`MAX_MANIFEST_FILES`, and components
  at ``settings.MAX_PROJECT_COMPONENTS``. Hitting a bound produces a warning, never a crash.
* **Fail soft, never silently.** Malformed input becomes an inventory warning;
  :func:`parse_project` never lets an exception escape.
* **Honest provenance.** Line numbers are only recorded when they are known exactly; index URLs
  are credential-redacted before they are stored anywhere.

Merging rules (``parse_project``)
---------------------------------
* Lock files (``poetry.lock``, ``Pipfile.lock``) take precedence for versions and edges.
* pip constraints (``-c`` / ``constraints*.txt``) can pin the version of a declared package but
  never add a component of their own, matching pip's semantics.
* Repeated declarations in one requirements file and conflicting exact pins are warned about; a
  conflict keeps one component per pinned version rather than silently choosing one.
* A component is *direct* when a top-level manifest (requirements file, ``pyproject.toml``,
  ``Pipfile``) declares it, or - for a lock file with no paired manifest in its directory - when
  it is a root of that lock's dependency graph.
* ``depth`` is the BFS distance from the project root; ``introduced_by`` lists the direct
  dependencies from which a transitive component is reachable (empty for direct components).
* A lock dependency is linked to **one** locked version of the child: the highest one its
  specifier allows (the highest one overall when the specifier cannot be evaluated). When
  versions exist but none satisfies the specifier, no edge is invented; a warning is recorded.
  Linking every allowed version made a small lock with N versions of one name produce N×(N-1)
  edges. The total number of edges is additionally capped at ``MAX_EDGES_PER_COMPONENT`` ×
  ``MAX_PROJECT_COMPONENTS``.
* When the component bound truncates the inventory, parents that lose edges no longer claim
  ``dependencies_known``.
* ``scope``: explicit scopes win; every other component takes the widest scope of its parents,
  computed to a fixed point, so a parent whose scope widens later still widens its children.
"""

from __future__ import annotations

import codecs
import hashlib
import posixpath
import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app.core.config import settings
from app.core.redaction import find_secrets, redact_text, sanitize_text
from app.sbom.models import (
    Component,
    DependencyEdge,
    ManifestDependency,
    ProjectInventory,
    make_bom_ref,
    make_purl,
)

# --- manifest types ---------------------------------------------------------------------
REQUIREMENTS = "requirements"
CONSTRAINTS = "constraints"
PYPROJECT = "pyproject"
POETRY_LOCK = "poetry-lock"
PIPFILE = "pipfile"
PIPFILE_LOCK = "pipfile-lock"
LOCK_TYPES = frozenset({POETRY_LOCK, PIPFILE_LOCK})
TOP_LEVEL_TYPES = frozenset({REQUIREMENTS, PYPROJECT, PIPFILE})

# --- bounds ------------------------------------------------------------------------------
MAX_MANIFEST_FILES = 200
MAX_LINE_CHARS = 32_768
MAX_WARNINGS = 500
MAX_INTRODUCED_BY = 50
MAX_NAME_LEN = 214
MAX_VERSION_LEN = 64
MAX_SPECIFIER_LEN = 200
MAX_EDGES_PER_COMPONENT = 20

SCOPE_RANK = {"required": 0, "optional": 1, "dev": 2}
PUBLIC_INDEX_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
NON_REGISTRY_SOURCES = frozenset({"git", "url", "file", "directory", "path", "vcs"})
HASH_LENGTHS = {"sha256": 64, "sha384": 96, "sha512": 128}

_REQ_NAME_RE = re.compile(r"^[\w.-]*requirements[\w.-]*\.(?:txt|in)$", re.IGNORECASE)
_CONSTRAINT_NAME_RE = re.compile(r"^[\w.-]*constraints[\w.-]*\.(?:txt|in)$", re.IGNORECASE)
_PROJECT_NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
_VERSION_CHARS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!\-*]{0,63}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")
# Userinfo of any URL-looking substring. Tokens frequently travel as a bare username
# (``https://<token>@private.example/simple``), which the generic credential pattern
# (``user:password@``) does not cover.
_URL_USERINFO_RE = re.compile(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.\-]{0,20}://)(?P<userinfo>[^\s/@?#\[\]]{1,256})@")
# Byte-order marks, longest first (the UTF-32-LE BOM starts with the UTF-16-LE BOM).
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
_TOML_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


# ======================================================================================
# Parse result types
# ======================================================================================
@dataclass
class LockedPackage:
    """One package entry of a lock file."""

    name: str
    normalized_name: str
    version: str | None
    source_file: str
    line: int | None = None
    hashes: list[str] = field(default_factory=list)  # "sha256:<hex>"
    scope: str = "required"
    groups: list[str] = field(default_factory=list)
    dependencies: list[tuple[str, str]] = field(default_factory=list)  # (normalized child name, specifier)
    dependencies_known: bool = False
    source_type: str | None = None  # None / "legacy" = a package index; git/url/file/directory otherwise
    source_url: str | None = None  # credential-redacted
    index_url: str | None = None  # credential-redacted index the lock names for this package, when known


@dataclass
class ManifestParseResult:
    """What one parser call extracted (a requirements parse may cover included files too)."""

    file: str
    type: str
    dependencies: list[ManifestDependency] = field(default_factory=list)
    packages: list[LockedPackage] = field(default_factory=list)
    index_sources: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)  # [{file, type, sha256, status}] for every file read
    project_name: str | None = None
    project_version: str | None = None


# ======================================================================================
# Small shared helpers
# ======================================================================================
def scrub_url_userinfo(text: str) -> str:
    """Replace the userinfo of every URL in ``text`` with ``[REDACTED]`` (``git@`` is kept)."""
    return _URL_USERINFO_RE.sub(
        lambda m: f"{m.group('scheme')}{'git' if m.group('userinfo') == 'git' else '[REDACTED]'}@", text
    )


def warn(warnings: list[str], message: str) -> None:
    """Append a display-safe (control-char escaped, secret-redacted, bounded) warning."""
    warnings.append(sanitize_text(scrub_url_userinfo(str(message)), max_len=300))


_DISPLAY_INPUT_CAP = 4096


def display(value: object) -> str:
    """Attacker-influenced text (paths, names) made safe to embed in a warning.

    Output is at most 160 characters, so input is cut at 4 KiB *before* redaction: running every
    secret pattern over a 32 KiB hostile line only to discard all but 160 characters is wasted work.
    A secret starting inside the visible part is still matched in full unless it is longer than the
    cap (the private-key pattern also matches a truncated block).
    """
    raw = value if isinstance(value, str) else str(value)
    return sanitize_text(scrub_url_userinfo(raw[:_DISPLAY_INPUT_CAP]), max_len=160)


def normalize_path(path: str) -> str:
    """POSIX-style relative path key: backslashes to slashes, ``./`` and ``a/../`` collapsed."""
    p = str(path).replace("\\", "/").strip()
    if not p:
        return ""
    return posixpath.normpath(p)


def manifest_type(path: str) -> str | None:
    """Manifest type for a known manifest filename, else ``None``."""
    p = normalize_path(path)
    base = posixpath.basename(p)
    lower = base.lower()
    if lower == "pyproject.toml":
        return PYPROJECT
    if lower == "poetry.lock":
        return POETRY_LOCK
    if lower == "pipfile.lock":
        return PIPFILE_LOCK
    if lower == "pipfile":
        return PIPFILE
    if _CONSTRAINT_NAME_RE.match(base):
        return CONSTRAINTS
    if _REQ_NAME_RE.match(base):
        return REQUIREMENTS
    parent = posixpath.basename(posixpath.dirname(p)).lower()
    if parent == "requirements" and lower.endswith((".txt", ".in")):
        return REQUIREMENTS
    return None


def load_manifest(path: str, content: object, warnings: list[str]) -> tuple[str | None, str | None, str]:
    """Bounded decode of manifest content. Returns ``(text, sha256, status)``.

    ``status`` is ``parsed``, ``too_large`` or ``error``. Oversized content is never decoded and
    gets no digest (a digest of a truncated read would misidentify the file). Like pip, a
    UTF-16/UTF-32 byte-order mark selects that encoding (``pip freeze > requirements.txt`` in
    Windows PowerShell writes UTF-16); everything else is decoded as UTF-8.
    """
    if isinstance(content, str):
        data = content.encode("utf-8", "surrogatepass")
    elif isinstance(content, (bytes, bytearray, memoryview)):
        data = bytes(content)
    else:
        warn(warnings, f"{display(path)}: unsupported content type {type(content).__name__}; skipped")
        return None, None, "error"
    if len(data) > settings.MAX_MANIFEST_BYTES:
        warn(warnings, f"{display(path)}: exceeds MAX_MANIFEST_BYTES ({settings.MAX_MANIFEST_BYTES}); skipped")
        return None, None, "too_large"
    digest = hashlib.sha256(data).hexdigest()
    encoding = next((enc for bom, enc in _BOMS if data.startswith(bom)), "utf-8")
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        warn(warnings, f"{display(path)}: not valid {encoding.upper()}; undecodable bytes replaced")
        text = data.decode(encoding, "replace")
    return text.lstrip("﻿"), digest, "parsed"


def redact_url(url: str) -> str:
    """Credential-free, display-safe form of an index / VCS / direct URL.

    Userinfo (``user:token@``) is replaced by ``[REDACTED]@`` (the conventional ``git`` SSH user
    is kept) and any query string - where tokens often travel - by ``?[REDACTED]``.
    """
    raw = str(url).strip()
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        # e.g. scp-like "git+ssh://git@host:org/repo.git": keep the shape, drop credentials and query.
        head, sep, _query = raw.partition("?")
        return sanitize_text(scrub_url_userinfo(head) + ("?[REDACTED]" if sep else ""), max_len=300)
    if not parts.scheme or not parts.netloc:
        return sanitize_text(scrub_url_userinfo(raw), max_len=300)
    userinfo = ""
    if parts.username is not None or parts.password is not None:
        userinfo = "git@" if parts.username == "git" and parts.password is None else "[REDACTED]@"
    if ":" in host:
        host = f"[{host}]"
    rebuilt = f"{parts.scheme}://{userinfo}{host}{f':{port}' if port else ''}{parts.path}"
    if parts.query:
        rebuilt += "?[REDACTED]"
    if parts.fragment:
        rebuilt += f"#{parts.fragment}"
    return sanitize_text(rebuilt, max_len=300)


def url_host(url: str) -> str | None:
    """Lower-cased host of ``url`` (userinfo ignored), or ``None`` when there is none."""
    try:
        netloc = urlsplit(str(url).strip()).netloc.rpartition("@")[2]
        host = urlsplit(f"//{netloc}").hostname if netloc else None
    except ValueError:
        return None
    return sanitize_text(host.lower(), max_len=255) if host else None


def credential_like(value: object) -> bool:
    """True when ``value`` contains a high-confidence secret pattern.

    Package names, versions, extras and markers are normalised later (lower-cased, ``_`` -> ``-``),
    after which the redaction patterns can no longer recognise a secret. Such values are therefore
    refused at parse time instead of being stored.
    """
    return isinstance(value, str) and bool(value) and bool(find_secrets(value))


def valid_project_name(name: object) -> bool:
    """A syntactically valid project name that does not look like a credential."""
    return (isinstance(name, str) and len(name) <= MAX_NAME_LEN and bool(_PROJECT_NAME_RE.match(name))
            and not credential_like(name))


def clean_version(value: object, warnings: list[str], where: str) -> str | None:
    """A version string safe to store (bounded, conservative charset), else ``None`` + warning."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    if not _VERSION_CHARS_RE.match(v) or "*" in v:
        warn(warnings, f"{where}: ignoring malformed version {display(v)!s}")
        return None
    if credential_like(v):
        warn(warnings, f"{where}: ignoring credential-like version {display(v)!s}")
        return None
    return v


def version_key(version: str) -> object:
    """Grouping key: PEP 440 equality (``2.31`` == ``2.31.0``) when valid, else the raw string."""
    try:
        return Version(version)
    except InvalidVersion:
        return version.lower()


def version_sort_key(version: str | None) -> tuple:
    if version is None:
        return (2, "")
    try:
        return (0, Version(version))
    except InvalidVersion:
        return (1, version)


def pinned_version(specifier: SpecifierSet) -> str | None:
    """The exact version when a specifier set is a single ``==X`` (no wildcard) or ``===X``."""
    specs = list(specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator == "===" or (spec.operator == "==" and not spec.version.endswith(".*")):
        return spec.version
    return None


def bound_specifier(spec: str, warnings: list[str], where: str) -> str:
    """A specifier safe to store: credential-like text redacted, length bounded."""
    if credential_like(spec):
        warn(warnings, f"{where}: credential-like text redacted from a version specifier")
        spec = redact_text(spec)
    if len(spec) > MAX_SPECIFIER_LEN:
        warn(warnings, f"{where}: specifier longer than {MAX_SPECIFIER_LEN} characters truncated")
        return spec[: MAX_SPECIFIER_LEN - 1] + "…"
    return spec


def parse_hash_token(value: str) -> str | None:
    """Validate ``alg:hexdigest`` (sha256/sha384/sha512) and return it normalised, else ``None``."""
    if not isinstance(value, str) or ":" not in value:
        return None
    alg, _, digest = value.strip().partition(":")
    alg = alg.lower()
    expected = HASH_LENGTHS.get(alg)
    if expected is None or len(digest) != expected or not _HEX_RE.match(digest):
        return None
    return f"{alg}:{digest.lower()}"


def safe_marker(value: object, warnings: list[str], where: str) -> str | None:
    """A PEP 508 marker string normalised by ``packaging``; invalid markers are dropped with a warning."""
    if not isinstance(value, str) or not value.strip():
        return None
    if len(value) > MAX_LINE_CHARS:
        warn(warnings, f"{where}: marker too long; ignored")
        return None
    if credential_like(value):
        warn(warnings, f"{where}: credential-like environment marker ignored")
        return None
    try:
        return str(Marker(value))
    except InvalidMarker:
        warn(warnings, f"{where}: invalid environment marker ignored")
        return None


def dependency_from_pep508(
    text: str,
    *,
    source_file: str,
    line: int | None,
    warnings: list[str],
    scope: str = "required",
    group: str | None = None,
    kind: str = "requirement",
    direct: bool = True,
    hashes: Iterable[str] = (),
) -> ManifestDependency | None:
    """Parse one PEP 508 requirement string into a declaration (``None`` + warning when invalid)."""
    where = f"{display(source_file)}{f':{line}' if line else ''}"
    if len(text) > MAX_LINE_CHARS:
        warn(warnings, f"{where}: requirement too long; skipped")
        return None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        warn(warnings, f"{where}: invalid requirement {display(text)!s}; skipped")
        return None
    if len(req.name) > MAX_NAME_LEN:
        warn(warnings, f"{where}: package name too long; skipped")
        return None
    if credential_like(req.name) or any(credential_like(e) for e in req.extras) or \
            (req.marker is not None and credential_like(str(req.marker))):
        warn(warnings, f"{where}: requirement contains credential-like text; skipped")
        return None
    specifier = bound_specifier(str(req.specifier), warnings, where)
    pinned = pinned_version(req.specifier)
    if pinned is not None:
        pinned = clean_version(pinned, warnings, where)
    url = None
    if req.url:
        url = redact_url(req.url)
        warn(warnings, f"{where}: '{req.name}' uses a direct URL reference; recorded as unresolved (never fetched)")
        pinned = None
    return ManifestDependency(
        name=req.name,
        normalized_name=canonicalize_name(req.name),
        specifier=specifier,
        pinned_version=pinned,
        extras=sorted(req.extras),
        markers=str(req.marker) if req.marker is not None else None,
        source_file=source_file,
        line=line,
        hashes=sorted(set(hashes)),
        direct=direct,
        scope=scope,
        group=group,
        url=url,
        kind=kind,
    )


def index_source(kind: str, url: str, file: str, line: int | None, **extra: object) -> dict:
    """An ``index_sources`` entry. ``host`` comes from the raw URL, ``url`` is credential-redacted."""
    entry = {"kind": kind, "url": redact_url(url), "host": url_host(url), "file": file, "line": line}
    for key, value in extra.items():
        if value is not None:
            entry[key] = sanitize_text(value, max_len=60)
    return entry


# ======================================================================================
# TOML source positions
# ======================================================================================
class _ScanError(Exception):
    pass


def _unescape_basic(raw: str) -> str | None:
    """Decode the escapes of a single-line TOML basic string; ``None`` when unsupported."""
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1 : i + 2]
        if nxt in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[nxt])
            i += 2
        elif nxt in ("u", "U"):
            width = 4 if nxt == "u" else 8
            digits = raw[i + 2 : i + 2 + width]
            if len(digits) != width or not _HEX_RE.match(digits):
                return None
            try:
                out.append(chr(int(digits, 16)))
            except (ValueError, OverflowError):
                return None
            i += 2 + width
        else:
            return None
    return "".join(out)


@dataclass
class TomlPositions:
    """Line numbers of TOML keys and top-level array items, keyed by full key path.

    Paths are tuples of unquoted key segments; elements of an array of tables are addressed by
    an ``"[i]"`` segment (``("package", "[0]", "name")``). Only positions the scanner is sure
    about are recorded; lookups return ``None`` otherwise.
    """

    keys: dict[tuple[str, ...], int] = field(default_factory=dict)
    arrays: dict[tuple[str, ...], list[tuple[str | None, int]]] = field(default_factory=dict)

    def line_of(self, *path: str) -> int | None:
        return self.keys.get(tuple(path))

    def item_lines(self, path: tuple[str, ...], values: list) -> list[int | None]:
        """Line of each parsed array element, verified against the literal found in the source."""
        items = self.arrays.get(tuple(path))
        if items is None or len(items) != len(values):
            return [None] * len(values)
        return [line if isinstance(v, str) and literal == v else None for (literal, line), v in zip(items, values)]


class _TomlScanner:
    """Minimal position scanner for TOML that ``tomllib`` already accepted.

    ``tomllib`` does not expose source positions. This scanner walks the text once, tracking
    table headers, key/value statements and the string items of arrays, so declarations can be
    given real line numbers. It gives up (keeping what it found) on anything unexpected.
    """

    _MAX_NESTING = 256

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        self.i = 0
        self.line = 1
        self.table: tuple[str, ...] = ()
        self.array_tables: dict[tuple[str, ...], int] = {}
        self.pos = TomlPositions()

    # -- low level ------------------------------------------------------------------
    def _peek(self) -> str | None:
        return self.s[self.i] if self.i < self.n else None

    def _skip_space(self, newlines: bool) -> None:
        s = self.s
        while self.i < self.n:
            ch = s[self.i]
            if ch in " \t\r":
                self.i += 1
            elif ch == "\n":
                if not newlines:
                    return
                self.line += 1
                self.i += 1
            elif ch == "#":
                end = s.find("\n", self.i)
                self.i = self.n if end < 0 else end
            else:
                return

    def _string(self) -> str | None:
        """Consume a string at the cursor; return its value when it has no escapes, else None."""
        s = self.s
        for delim in ('"""', "'''"):
            if s.startswith(delim, self.i):
                j = self.i + 3
                while True:
                    k = s.find(delim, j)
                    if k < 0:
                        raise _ScanError
                    if delim == '"""':
                        backslashes = 0
                        while k - 1 - backslashes >= self.i + 3 and s[k - 1 - backslashes] == "\\":
                            backslashes += 1
                        if backslashes % 2:
                            j = k + 1
                            continue
                    break
                end = k + 3
                while end < self.n and s[end] == delim[0] and end - k < 5:
                    end += 1
                self.line += s.count("\n", self.i, end)
                self.i = end
                return None
        quote = s[self.i]
        j = self.i + 1
        escaped = False
        while j < self.n:
            ch = s[j]
            if ch == "\n":
                raise _ScanError
            if quote == '"' and ch == "\\":
                escaped = True
                j += 2
                continue
            if ch == quote:
                break
            j += 1
        else:
            raise _ScanError
        value = s[self.i + 1 : j]
        self.i = j + 1
        return _unescape_basic(value) if escaped else value

    def _key_path(self) -> list[str]:
        segments: list[str] = []
        while True:
            self._skip_space(newlines=False)
            ch = self._peek()
            if ch in ('"', "'"):
                value = self._string()
                segments.append(value if value is not None else "\x00escaped")
            else:
                m = _BARE_KEY_RE.match(self.s, self.i)
                if not m:
                    raise _ScanError
                segments.append(m.group(0))
                self.i = m.end()
            self._skip_space(newlines=False)
            if self._peek() == ".":
                self.i += 1
                continue
            return segments

    def _indexed(self, raw: Iterable[str]) -> tuple[str, ...]:
        out: tuple[str, ...] = ()
        for seg in raw:
            out = out + (seg,)
            count = self.array_tables.get(out)
            if count:
                out = out + (f"[{count - 1}]",)
        return out

    # -- values -----------------------------------------------------------------------
    def _skip_value(self, depth: int = 0, path: tuple[str, ...] | None = None) -> None:
        """Consume one value. With ``path``, keys of an inline table (and their arrays) are recorded."""
        if depth > self._MAX_NESTING:
            raise _ScanError
        ch = self._peek()
        if ch is None:
            raise _ScanError
        if ch in ('"', "'"):
            self._string()
        elif ch == "[":
            self.i += 1
            while True:
                self._skip_space(newlines=True)
                if self._peek() == "]":
                    self.i += 1
                    return
                self._skip_value(depth + 1)
                self._skip_space(newlines=True)
                ch = self._peek()
                if ch == ",":
                    self.i += 1
                elif ch == "]":
                    self.i += 1
                    return
                else:
                    raise _ScanError
        elif ch == "{":
            self.i += 1
            while True:
                self._skip_space(newlines=True)
                if self._peek() == "}":
                    self.i += 1
                    return
                key_line = self.line
                keys = self._key_path()
                if self._peek() != "=":
                    raise _ScanError
                self.i += 1
                self._skip_space(newlines=False)
                if path is None:
                    self._skip_value(depth + 1)
                else:
                    full = path + tuple(keys)
                    self.pos.keys.setdefault(full, key_line)
                    if self._peek() == "[":
                        self._array_items(full)
                    else:
                        self._skip_value(depth + 1, full)
                self._skip_space(newlines=True)
                ch = self._peek()
                if ch == ",":
                    self.i += 1
                elif ch == "}":
                    self.i += 1
                    return
                else:
                    raise _ScanError
        else:
            start = self.i
            while self.i < self.n and self.s[self.i] not in ",]}\n#":
                self.i += 1
            if self.i == start:
                raise _ScanError

    def _array_items(self, path: tuple[str, ...]) -> None:
        self.i += 1  # "["
        items: list[tuple[str | None, int]] = []
        while True:
            self._skip_space(newlines=True)
            ch = self._peek()
            if ch is None:
                raise _ScanError
            if ch == "]":
                self.i += 1
                break
            line = self.line
            if ch in ('"', "'"):
                items.append((self._string(), line))
            else:
                self._skip_value(1)
                items.append((None, line))
            self._skip_space(newlines=True)
            ch = self._peek()
            if ch == ",":
                self.i += 1
            elif ch == "]":
                self.i += 1
                break
            else:
                raise _ScanError
        self.pos.arrays.setdefault(path, items)

    # -- statements -------------------------------------------------------------------
    def _header(self) -> None:
        header_line = self.line
        is_array = self.s.startswith("[[", self.i)
        self.i += 2 if is_array else 1
        raw = self._key_path()
        closing = "]]" if is_array else "]"
        if not self.s.startswith(closing, self.i):
            raise _ScanError
        self.i += len(closing)
        if is_array:
            parent = self._indexed(raw[:-1])
            key = parent + (raw[-1],)
            index = self.array_tables.get(key, 0)
            self.array_tables[key] = index + 1
            self.table = key + (f"[{index}]",)
        else:
            self.table = self._indexed(raw)
        self.pos.keys.setdefault(self.table, header_line)

    def _keyval(self) -> None:
        key_line = self.line
        path = self.table + tuple(self._key_path())
        if self._peek() != "=":
            raise _ScanError
        self.i += 1
        self._skip_space(newlines=False)
        self.pos.keys.setdefault(path, key_line)
        if self._peek() == "[":
            self._array_items(path)
        else:
            self._skip_value(0, path)

    def run(self) -> TomlPositions:
        try:
            while True:
                self._skip_space(newlines=True)
                if self.i >= self.n:
                    break
                before = self.i
                if self.s[self.i] == "[":
                    self._header()
                else:
                    self._keyval()
                if self.i <= before:
                    break
        except (_ScanError, IndexError, RecursionError):
            pass
        return self.pos


def scan_toml_positions(text: str) -> TomlPositions:
    return _TomlScanner(text).run()


# ======================================================================================
# parse_project
# ======================================================================================
def project_root_ref(project_name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", project_name).strip("-.").lower()
    return f"warden:project/{slug or 'project'}"


def _parse_one(path: str, mtype: str, files: Mapping[str, object]) -> ManifestParseResult:
    # Imported lazily: the format modules import helpers from this package.
    if mtype in (REQUIREMENTS, CONSTRAINTS):
        from app.sbom.parsers.requirements import parse_requirements

        return parse_requirements(path, files, constraints=mtype == CONSTRAINTS)
    if mtype == PYPROJECT:
        from app.sbom.parsers.pyproject import parse_pyproject

        return parse_pyproject(path, files[path])
    if mtype == POETRY_LOCK:
        from app.sbom.parsers.poetry_lock import parse_poetry_lock

        return parse_poetry_lock(path, files[path])
    if mtype == PIPFILE:
        from app.sbom.parsers.pipfile_lock import parse_pipfile

        return parse_pipfile(path, files[path])
    from app.sbom.parsers.pipfile_lock import parse_pipfile_lock

    return parse_pipfile_lock(path, files[path])


def parse_project(files: Mapping[str, bytes | str], project_name: str = "project") -> ProjectInventory:
    """Parse every supported manifest in ``files`` into one merged, bounded inventory.

    Never raises: malformed manifests, bound violations and internal errors become warnings.
    """
    name = sanitize_text(project_name if isinstance(project_name, str) and project_name.strip() else "project",
                         max_len=120)
    inventory = ProjectInventory(project_name=name, root_ref=project_root_ref(name))
    try:
        _Builder(inventory).build(files)
    except Exception as exc:  # fail soft: a parser bug must not take down a project scan
        inventory.components, inventory.edges, inventory.dependencies = [], [], []
        warn(inventory.warnings, f"project manifest parsing aborted ({type(exc).__name__}); inventory is incomplete")
    return inventory


class _Builder:
    def __init__(self, inventory: ProjectInventory) -> None:
        self.inv = inventory
        self.warnings: list[str] = []

    # -- collection ---------------------------------------------------------------------
    def build(self, files: Mapping[str, bytes | str]) -> None:
        if not isinstance(files, Mapping):
            warn(self.warnings, "manifest input must be a mapping of path to content")
            self._finish([], [], [], [])
            return
        normalized: dict[str, object] = {}
        for key in sorted((k for k in files if isinstance(k, str)), key=str):
            nk = normalize_path(key)
            if not nk or nk == ".":
                continue
            if sanitize_text(nk, max_len=512) != nk:
                warn(self.warnings, f"manifest path {display(nk)} contains control characters or credential-like "
                     "text (or is too long); skipped")
                continue
            if nk in normalized:
                warn(self.warnings, f"duplicate manifest path after normalisation: {display(nk)}; first kept")
                continue
            normalized[nk] = files[key]
        if any(not isinstance(k, str) for k in files):
            warn(self.warnings, "ignored manifest entries with non-string paths")

        candidates = sorted(p for p in normalized if manifest_type(p))
        if len(candidates) > MAX_MANIFEST_FILES:
            warn(self.warnings, f"{len(candidates)} manifests provided; only the first {MAX_MANIFEST_FILES} parsed")
            candidates = candidates[:MAX_MANIFEST_FILES]

        results: list[ManifestParseResult] = []
        declaration_budget = settings.MAX_PROJECT_COMPONENTS * 5
        declared = 0
        for path in candidates:
            if declared >= declaration_budget:
                warn(self.warnings, "declaration budget exhausted; remaining manifests not parsed")
                break
            mtype = manifest_type(path) or ""
            try:
                result = _parse_one(path, mtype, normalized)
            except Exception as exc:  # fail soft per manifest
                result = ManifestParseResult(file=path, type=mtype)
                result.manifests.append({"file": path, "type": mtype, "sha256": None, "status": "error"})
                warn(result.warnings, f"{display(path)}: could not be parsed ({type(exc).__name__})")
            declared += len(result.dependencies) + len(result.packages)
            results.append(result)

        parsed_files = {m["file"] for r in results for m in r.manifests}
        ignored = [p for p in normalized if p not in parsed_files and not manifest_type(p)]
        if ignored:
            warn(self.warnings, f"ignored {len(ignored)} file(s) that are not supported manifests")

        manifests: list[dict] = []
        seen_files: set[str] = set()
        decls: list[ManifestDependency] = []
        seen_decls: set[tuple] = set()
        packages: list[LockedPackage] = []
        sources: list[dict] = []
        seen_sources: set[tuple] = set()
        for result in results:
            self.warnings.extend(result.warnings)
            for m in result.manifests:
                if m["file"] not in seen_files:
                    seen_files.add(m["file"])
                    manifests.append(m)
            for d in result.dependencies:
                key = (d.source_file, d.line, d.normalized_name, d.kind, d.scope, d.group, d.specifier,
                       d.markers, d.url, d.pinned_version, d.direct)
                if key not in seen_decls:
                    seen_decls.add(key)
                    decls.append(d)
            packages.extend(result.packages)
            for s in result.index_sources:
                key = (s.get("kind"), s.get("url"), s.get("file"), s.get("line"))
                if key not in seen_sources:
                    seen_sources.add(key)
                    sources.append(s)
            if result.type == PYPROJECT and result.file == "pyproject.toml" and result.project_version:
                self.inv.project_version = result.project_version
        self._finish(manifests, decls, packages, sources)

    # -- merge --------------------------------------------------------------------------
    def _finish(self, manifests: list[dict], decls: list[ManifestDependency], packages: list[LockedPackage],
                sources: list[dict]) -> None:
        inv = self.inv
        decls.sort(key=lambda d: (d.source_file, d.line or 0, d.normalized_name))
        packages.sort(key=lambda p: (p.source_file, p.line or 0, p.normalized_name, version_sort_key(p.version)))

        lock_decls = [
            ManifestDependency(
                name=p.name, normalized_name=p.normalized_name, specifier=f"=={p.version}" if p.version else "",
                pinned_version=p.version, source_file=p.source_file, line=p.line, hashes=list(p.hashes),
                index_url=p.source_url if p.source_type == "legacy" else p.index_url,
                direct=False, scope=p.scope, group=",".join(p.groups) or None,
                url=p.source_url if p.source_type in NON_REGISTRY_SOURCES else None, kind="lock",
            )
            for p in packages
        ]

        file_types = {m["file"]: m["type"] for m in manifests}
        components, comp_index, explicit_scope = self._components(decls, packages, file_types)
        edges = self._edges(components, comp_index, decls, packages, manifests)

        # Component bound: keep direct components first, then by name/version.
        limit = settings.MAX_PROJECT_COMPONENTS
        if len(components) > limit:
            warn(self.warnings, f"{len(components)} components exceed MAX_PROJECT_COMPONENTS ({limit}); truncated")
            components.sort(key=lambda c: (not c.direct, c.normalized_name, version_sort_key(c.version)))
            components = components[:limit]
            kept = {c.bom_ref for c in components}
            lost_children = {e.parent for e in edges if e.parent in kept and e.child not in kept}
            edges = [e for e in edges if (e.parent == inv.root_ref or e.parent in kept) and e.child in kept]
            for c in components:
                if c.bom_ref in lost_children:
                    c.dependencies_known = False  # its recorded dependency list is no longer complete

        inv.components = sorted(components, key=lambda c: c.bom_ref)
        inv.edges = sorted(edges, key=lambda e: (e.parent, e.child))
        inv.manifests = manifests
        inv.dependencies = decls + lock_decls
        inv.index_sources = sources
        inv.index_urls = _unique(s["url"] for s in sources if s["kind"] in ("index-url", "poetry-source",
                                                                           "pipenv-source", "poetry-lock-source"))
        inv.extra_index_urls = _unique(s["url"] for s in sources if s["kind"] == "extra-index-url")
        inv.private_index_hints = sorted({
            s["url"] for s in sources
            if s["kind"] != "no-index" and s.get("host") and s["host"] not in PUBLIC_INDEX_HOSTS
        })
        order = compute_graph_metadata(inv)
        propagate_scope(inv, explicit_scope, order)
        unreachable = sum(1 for c in inv.components if c.depth is None)
        if unreachable:
            warn(self.warnings, f"{unreachable} component(s) are not reachable from any declared dependency")
        inv.warnings = bounded_warnings(inv.warnings + self.warnings)

    def _components(self, decls: list[ManifestDependency], packages: list[LockedPackage],
                    file_types: Mapping[str, str]):
        decls_by_name: dict[str, list[ManifestDependency]] = {}
        for d in decls:
            decls_by_name.setdefault(d.normalized_name, []).append(d)
        locks_by_name: dict[str, list[LockedPackage]] = {}
        for p in packages:
            locks_by_name.setdefault(p.normalized_name, []).append(p)

        components: list[Component] = []
        comp_index: dict[tuple[str, object], Component] = {}
        explicit_scope: dict[str, str | None] = {}
        for name in sorted(set(decls_by_name) | set(locks_by_name)):
            named_decls = decls_by_name.get(name, [])
            named_locks = locks_by_name.get(name, [])
            if not named_locks and not any(d.kind == "requirement" for d in named_decls):
                continue  # pip constraints restrict versions but never add a package
            self._declaration_warnings(named_decls, file_types)
            versions: dict[object, str] = {}
            resolution = "unresolved"
            for p in named_locks:
                if p.version:
                    versions.setdefault(version_key(p.version), p.version)
            if versions:
                resolution = "locked"
            else:
                # Requirement pins first; a constraint pin only applies when no requirement pins.
                for kinds in (("requirement",), ("constraint",)):
                    for d in named_decls:
                        if d.pinned_version and d.kind in kinds:
                            versions.setdefault(version_key(d.pinned_version), d.pinned_version)
                    if versions:
                        resolution = "pinned"
                        break
            if resolution == "locked":
                for d in named_decls:
                    if d.pinned_version and version_key(d.pinned_version) not in versions:
                        warn(self.warnings, f"{display(d.source_file)}:{d.line or '?'}: {d.name} pinned to "
                             f"{display(d.pinned_version)} but lock file(s) record {', '.join(versions.values())}")
            display_name = named_locks[0].name if named_locks else named_decls[0].name
            keys: list[object | None] = list(versions) or [None]
            for key in keys:
                version = versions.get(key) if key is not None else None
                attached_decls = [
                    d for d in named_decls
                    if key is None or not d.pinned_version or version_key(d.pinned_version) == key
                    or version_key(d.pinned_version) not in versions
                ]
                attached_locks = [p for p in named_locks
                                  if (key is None and not p.version)
                                  or (key is not None and p.version and version_key(p.version) == key)]
                comp = self._component(display_name, name, version, resolution if key is not None else "unresolved",
                                       attached_decls, attached_locks, key)
                components.append(comp)
                comp_index[(name, key)] = comp
                scopes = [d.scope for d in attached_decls if d.direct] + [p.scope for p in attached_locks]
                explicit_scope[comp.bom_ref] = min(scopes, key=lambda s: SCOPE_RANK.get(s, 0)) if scopes else None
        return components, comp_index, explicit_scope

    def _declaration_warnings(self, decls: list[ManifestDependency], file_types: Mapping[str, str]) -> None:
        """Warn about a package declared repeatedly in one requirements file or pinned inconsistently."""
        if not decls:
            return
        label = display(decls[0].name)
        lines_by_file: dict[str, set[int]] = {}
        for d in decls:
            if d.kind == "requirement" and d.line and file_types.get(d.source_file) == REQUIREMENTS:
                lines_by_file.setdefault(d.source_file, set()).add(d.line)
        for file in sorted(lines_by_file):
            lines = sorted(lines_by_file[file])
            if len(lines) > 1:
                shown = ", ".join(str(n) for n in lines[:10])
                warn(self.warnings, f"{display(file)}: '{label}' is declared {len(lines)} times (lines {shown})")
        pins: dict[object, tuple[str, set[str]]] = {}
        for d in decls:
            if d.pinned_version:
                entry = pins.setdefault(version_key(d.pinned_version), (d.pinned_version, set()))
                entry[1].add(f"{d.source_file}:{d.line or '?'}")
        if len(pins) > 1:
            detail = "; ".join(f"{display(v)} ({', '.join(sorted(where)[:3])})"
                               for v, where in sorted(pins.values(), key=lambda p: version_sort_key(p[0])))
            warn(self.warnings, f"'{label}' is pinned to conflicting versions: {detail}")

    @staticmethod
    def _component(display_name: str, name: str, version: str | None, resolution: str,
                   decls: list[ManifestDependency], locks: list[LockedPackage], key: object) -> Component:
        file_hashes: set[str] = set()
        for d in decls:
            if d.pinned_version and key is not None and version_key(d.pinned_version) == key:
                file_hashes.update(d.hashes)
        for p in locks:
            file_hashes.update(p.hashes)
        sha256 = sorted(h for h in file_hashes if h.startswith("sha256:"))
        declared_at: list[dict] = []
        seen: set[tuple] = set()
        for file, line in sorted({(d.source_file, d.line) for d in decls} | {(p.source_file, p.line) for p in locks},
                                 key=lambda fl: (fl[0], fl[1] or 0)):
            if (file, line) not in seen:
                seen.add((file, line))
                declared_at.append({"file": file, "line": line})
        direct_specs = [d.specifier for d in decls if d.direct and d.specifier]
        non_registry = any(p.source_type in NON_REGISTRY_SOURCES for p in locks)
        purl = None if non_registry or version is None else make_purl(name, version)
        return Component(
            bom_ref=make_bom_ref(name, version),
            name=display_name,
            normalized_name=name,
            version=version,
            purl=purl,
            direct=any(d.direct for d in decls),
            hashes={"sha256": sha256[0].split(":", 1)[1]} if len(sha256) == 1 else {},
            source_files=sorted({f for f, _ in seen}),
            declared_at=declared_at,
            resolution=resolution,
            specifier=direct_specs[0] if direct_specs else "",
            file_hashes=sorted(file_hashes),
            # Edges are only built for versioned lock entries, so only those can vouch for completeness.
            dependencies_known=any(p.dependencies_known for p in locks if p.version),
        )

    def _edges(self, components: list[Component], comp_index: dict, decls: list[ManifestDependency],
               packages: list[LockedPackage], manifests: list[dict]) -> list[DependencyEdge]:
        inv = self.inv
        by_name: dict[str, list[Component]] = {}
        for c in components:
            by_name.setdefault(c.normalized_name, []).append(c)

        # Lock roots for lock files without a paired top-level manifest in the same directory.
        declared_dirs: dict[str, set[str]] = {}
        for d in decls:
            if d.direct:
                declared_dirs.setdefault(posixpath.dirname(d.source_file), set()).add(
                    manifest_type(d.source_file) or "")
        lock_files = sorted({p.source_file for p in packages})
        for lock_file in lock_files:
            lock_type = manifest_type(lock_file)
            paired = PYPROJECT if lock_type == POETRY_LOCK else PIPFILE
            if paired in declared_dirs.get(posixpath.dirname(lock_file), set()):
                continue
            file_pkgs = [p for p in packages if p.source_file == lock_file]
            children = {child for p in file_pkgs for child, _ in p.dependencies}
            roots = [p for p in file_pkgs if p.normalized_name not in children]
            if lock_type == PIPFILE_LOCK:
                warn(self.warnings, f"{display(lock_file)}: Pipfile.lock records no dependency relationships and no "
                     "Pipfile was provided; all locked packages treated as direct dependencies")
            else:
                warn(self.warnings, f"{display(lock_file)}: no pyproject.toml declarations in the same directory; "
                     "lock graph roots treated as direct dependencies")
            for p in roots:
                comp = comp_index.get((p.normalized_name, version_key(p.version) if p.version else None))
                if comp is not None:
                    comp.direct = True

        edges: dict[tuple[str, str], DependencyEdge] = {}
        for c in sorted(components, key=lambda c: c.bom_ref):
            if c.direct:
                edges.setdefault((inv.root_ref, c.bom_ref),
                                 DependencyEdge(inv.root_ref, c.bom_ref, c.specifier or None))

        lock_members: dict[str, dict[str, list[Component]]] = {}
        for p in packages:
            comp = comp_index.get((p.normalized_name, version_key(p.version) if p.version else None))
            if comp is not None:
                lock_members.setdefault(p.source_file, {}).setdefault(p.normalized_name, []).append(comp)
        max_edges = settings.MAX_PROJECT_COMPONENTS * MAX_EDGES_PER_COMPONENT
        unsatisfied = 0
        for p in packages:
            if not p.version:
                continue
            parent = comp_index.get((p.normalized_name, version_key(p.version)))
            if parent is None:
                continue
            members = lock_members.get(p.source_file, {})
            for child_name, spec in p.dependencies:
                candidates = [c for c in members.get(child_name, []) if c.bom_ref != parent.bom_ref]
                if not candidates:
                    continue
                child = _select_lock_candidate(candidates, spec)
                if child is None:
                    unsatisfied += 1
                    continue
                if (parent.bom_ref, child.bom_ref) in edges:
                    continue
                if len(edges) >= max_edges:
                    warn(self.warnings, f"dependency edge limit ({max_edges}) reached; remaining edges dropped")
                    return list(edges.values())
                edges[(parent.bom_ref, child.bom_ref)] = DependencyEdge(parent.bom_ref, child.bom_ref, spec or None)
        if unsatisfied:
            warn(self.warnings, f"{unsatisfied} lock dependency specifier(s) match no locked version; not linked")
        return list(edges.values())


def _select_lock_candidate(candidates: list[Component], spec: str) -> Component | None:
    """The highest locked version allowed by ``spec`` (highest overall when ``spec`` cannot be evaluated)."""
    ordered = sorted({c.bom_ref: c for c in candidates}.values(),
                     key=lambda c: (version_sort_key(c.version), c.bom_ref), reverse=True)
    if not spec:
        return ordered[0]
    try:
        specifier = SpecifierSet(spec)
    except InvalidSpecifier:
        return ordered[0]
    for c in ordered:
        try:
            if c.version and specifier.contains(Version(c.version), prereleases=True):
                return c
        except InvalidVersion:
            continue
    return None


def _unique(values: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        seen.setdefault(v, None)
    return list(seen)


def bounded_warnings(warnings: list[str]) -> list[str]:
    """De-duplicated warnings (order kept), capped at :data:`MAX_WARNINGS` with a suppression note."""
    unique = _unique(warnings)
    if len(unique) > MAX_WARNINGS:
        extra = len(unique) - (MAX_WARNINGS - 1)
        return unique[: MAX_WARNINGS - 1] + [f"{extra} further warnings suppressed"]
    return unique


# ======================================================================================
# Graph metadata (also used by the resolver after it adds components)
# ======================================================================================
def compute_graph_metadata(inventory: ProjectInventory) -> list[str]:
    """Recompute ``depth`` and ``introduced_by`` for every component; return the BFS order.

    Deterministic: children are visited in sorted order. Cycles and components that are not
    reachable from the root are handled (unreachable components get ``depth=None``).
    """
    refs = {c.bom_ref for c in inventory.components}
    adjacency: dict[str, list[str]] = {}
    for e in inventory.edges:
        if e.child in refs and (e.parent in refs or e.parent == inventory.root_ref):
            adjacency.setdefault(e.parent, []).append(e.child)
    for parent in adjacency:
        adjacency[parent] = sorted(set(adjacency[parent]))

    depth: dict[str, int] = {inventory.root_ref: 0}
    order: list[str] = []
    queue = deque([inventory.root_ref])
    while queue:
        node = queue.popleft()
        for child in adjacency.get(node, ()):
            if child not in depth:
                depth[child] = depth[node] + 1
                order.append(child)
                queue.append(child)

    direct_refs = sorted(c.bom_ref for c in inventory.components if c.direct)
    bit_of = {ref: 1 << i for i, ref in enumerate(direct_refs)}
    nodes = sorted(refs)
    comp_adj = {n: [c for c in adjacency.get(n, ()) if c != inventory.root_ref] for n in nodes}
    sccs = _strongly_connected(nodes, comp_adj)
    scc_of = {node: idx for idx, members in enumerate(sccs) for node in members}
    own = [0] * len(sccs)
    for idx, members in enumerate(sccs):
        for m in members:
            own[idx] |= bit_of.get(m, 0)
    incoming = [0] * len(sccs)
    for idx in reversed(range(len(sccs))):  # Tarjan emits sinks first; reversed = topological order
        reach = incoming[idx] | own[idx]
        for m in sccs[idx]:
            for child in comp_adj[m]:
                target = scc_of[child]
                if target != idx:
                    incoming[target] |= reach

    truncated = 0
    for c in inventory.components:
        c.depth = depth.get(c.bom_ref)
        if c.direct:
            c.introduced_by = []
            continue
        idx = scc_of[c.bom_ref]
        bits = incoming[idx] | (own[idx] & ~bit_of.get(c.bom_ref, 0))
        found: list[str] = []
        while bits and len(found) < MAX_INTRODUCED_BY:
            low = bits & -bits
            found.append(direct_refs[low.bit_length() - 1])
            bits ^= low
        if bits:
            truncated += 1
        c.introduced_by = found
    if truncated:
        warn(inventory.warnings, f"introduced_by truncated to {MAX_INTRODUCED_BY} entries for {truncated} component(s)")
    return order


def _strongly_connected(nodes: list[str], adjacency: Mapping[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan SCC (no recursion limit issues on hostile graphs)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    for start in nodes:
        if start in index:
            continue
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        work = [(start, iter(adjacency.get(start, ())))]
        while work:
            node, children = work[-1]
            descended = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(adjacency.get(child, ()))))
                    descended = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == node:
                        break
                result.append(sorted(members))
    return result


def propagate_scope(inventory: ProjectInventory, explicit: Mapping[str, str | None], order: list[str]) -> None:
    """Explicit scopes win; other components inherit the widest scope of their parents.

    Computed to a fixed point with a worklist: whenever a component's scope widens, its children
    are re-evaluated. Scopes only widen and there are three ranks, so each component is updated at
    most three times. A component that no scoped parent reaches is ``required``.
    """
    by_ref = {c.bom_ref: c for c in inventory.components}
    children: dict[str, list[str]] = {}
    for e in inventory.edges:
        if e.parent in by_ref and e.child in by_ref and e.parent != e.child:
            children.setdefault(e.parent, []).append(e.child)
    ordered = set(order)
    sequence = [r for r in order if r in by_ref] + sorted(r for r in by_ref if r not in ordered)
    scope_of: dict[str, str | None] = {ref: explicit.get(ref) for ref in by_ref}
    queue = deque(ref for ref in sequence if scope_of[ref] is not None)
    while queue:
        ref = queue.popleft()
        scope = scope_of[ref]
        for child in children.get(ref, ()):
            if explicit.get(child) is not None:
                continue
            current = scope_of[child]
            if current is None or SCOPE_RANK.get(scope, 0) < SCOPE_RANK.get(current, 0):
                scope_of[child] = scope
                queue.append(child)
    for ref, comp in by_ref.items():
        comp.scope = scope_of[ref] or "required"


__all__ = [
    "CONSTRAINTS",
    "LOCK_TYPES",
    "PIPFILE",
    "PIPFILE_LOCK",
    "POETRY_LOCK",
    "PYPROJECT",
    "REQUIREMENTS",
    "LockedPackage",
    "ManifestParseResult",
    "TomlPositions",
    "bounded_warnings",
    "compute_graph_metadata",
    "manifest_type",
    "normalize_path",
    "parse_project",
    "propagate_scope",
    "redact_url",
    "scan_toml_positions",
    "scrub_url_userinfo",
]
