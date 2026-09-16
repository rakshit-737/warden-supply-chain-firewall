"""Dependency-confusion support: private-namespace matching and package-index classification.

Dependency confusion (a substitution attack) happens when an installer that can see a public
index resolves an *internal* package name from it - typically because someone registered that
name on PyPI, often with an implausibly high version so it outranks the internal release. This
package provides the building blocks Warden uses to provide signals for that risk:

* :class:`PrivateNamespaces` - fnmatch-style globs describing internal package names
  (``settings.PRIVATE_PACKAGE_PATTERNS`` plus per-scan ``ScanOptions.private_namespaces``);
* :class:`IndexClassifier` - classifies index URLs as ``private`` (``settings.PRIVATE_INDEX_URLS``),
  ``public`` (PyPI / TestPyPI hosts) or ``other`` (neither: a mirror or proxy Warden cannot place);
* :mod:`app.analysis.depconf.index_snapshot` - a local snapshot of public project names, so
  presence checks do not disclose private names to the public registry;
* :mod:`app.analysis.depconf.project` - project-level findings over a ``ProjectInventory``.

Pattern semantics
=================

Patterns are matched against PEP 503 canonical names, so case and ``-``/``_``/``.`` spelling cannot
be used to slip past them:

* ``*`` matches any run of characters (including none), ``?`` exactly one, ``[seq]`` / ``[!seq]``
  one character from / not from a set of ASCII letters, digits, separators or ``a-z`` style ranges;
* literal letters are lower-cased and the separators ``-``, ``_`` and ``.`` are equivalent, with runs
  collapsed to one separator (``Acme__Internal.*`` is the same pattern as ``acme-internal-*``);
* matching is anchored at both ends: ``acme-*`` matches ``acme-auth`` but not ``acme`` or ``xacme-auth``;
* a leading ``!`` marks an exclusion (for names an organisation deliberately publishes publicly, e.g.
  ``acme-*,!acme-sdk``). Exclusions are honoured only from settings: a scan request must not be able
  to switch off the administrator's private-namespace protection.

Patterns are refused (and reported in :attr:`PrivateNamespaces.rejected`) when they contain fewer
than two literal letters/digits (``*``, ``?*``, ``a*`` would mark most of PyPI as internal), a
character that can never occur in a canonical name, a malformed character class, more than
``MAX_PATTERN_LENGTH`` characters, or exceed ``MAX_PATTERNS``. Each pattern compiles to a regular
expression whose wildcard segments are atomic groups (the construction CPython's ``fnmatch`` uses),
which avoids catastrophic backtracking on hostile package names.
"""

from __future__ import annotations

import re
import string
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from typing import Any
from urllib.parse import urlsplit

from packaging.utils import canonicalize_name

from app.core.redaction import sanitize_text

MAX_PATTERNS = 256
MAX_PATTERN_LENGTH = 128
MIN_LITERAL_CHARS = 2
MAX_NAME_LENGTH = 214
MAX_URL_LENGTH = 2048

SOURCE_SETTINGS = "settings"
SOURCE_SCAN_OPTIONS = "scan_options"
_SOURCE_RANK = {SOURCE_SETTINGS: 0, SOURCE_SCAN_OPTIONS: 1}

PRIVATE = "private"
PUBLIC = "public"
OTHER = "other"
LOCAL = "local"

# Hosts of public package indexes anyone can upload to. Kept in step with
# app.sbom.parsers.PUBLIC_INDEX_HOSTS, plus TestPyPI (also open to anyone).
PUBLIC_REGISTRY_HOSTS = frozenset({
    "pypi.org", "files.pythonhosted.org", "test.pypi.org", "test-files.pythonhosted.org",
})

# PEP 508 project name grammar (the same grammar the PyPI client validates).
_NAME_RE = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
_ALNUM = frozenset(string.ascii_lowercase + string.digits)
_SEPARATORS = frozenset("-_.")
_URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)")


def canonical_name(name: object) -> str | None:
    """PEP 503 canonical form of a valid PEP 508 project name, or ``None`` for anything else."""
    if not isinstance(name, str):
        return None
    value = name.strip()
    if not value or len(value) > MAX_NAME_LENGTH or not _NAME_RE.match(value):
        return None
    return canonicalize_name(value)


# ======================================================================================
# private namespace patterns
# ======================================================================================
class PatternError(ValueError):
    """A private-namespace pattern that cannot be used. ``reason`` is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NamespacePattern:
    raw: str  # the configured text, sanitised for display
    glob: str  # canonical glob form, e.g. "acme-*"
    source: str  # SOURCE_SETTINGS | SOURCE_SCAN_OPTIONS
    regex: re.Pattern[str] = field(repr=False, compare=False)
    exclude: bool = False

    def matches(self, canonical: str) -> bool:
        return self.regex.match(canonical) is not None


@dataclass(frozen=True)
class NamespaceMatch:
    name: str  # canonical name that matched
    pattern: str  # canonical glob of the winning pattern
    raw: str
    source: str

    def to_evidence(self) -> dict[str, str]:
        return {"matched_pattern": self.pattern, "pattern_source": self.source}


def _class_end(body: str, start: int) -> int | None:
    j = start + 1
    if j < len(body) and body[j] == "!":
        j += 1
    if j < len(body) and body[j] == "]":
        j += 1
    while j < len(body) and body[j] != "]":
        j += 1
    return j if j < len(body) else None


def _class_regex(content: str) -> str:
    negate = content.startswith("!")
    if negate:
        content = content[1:]
    items: list[str] = []
    k = 0
    while k < len(content):
        if k + 2 < len(content) and content[k + 1] == "-":
            lo, hi = content[k].lower(), content[k + 2].lower()
            same_kind = (lo in string.digits) == (hi in string.digits)
            if lo not in _ALNUM or hi not in _ALNUM or not same_kind or lo > hi:
                raise PatternError("invalid_class")
            items.append(f"{lo}-{hi}")
            k += 3
            continue
        char = content[k].lower()
        if char in _SEPARATORS:
            items.append(r"\-")
        elif char in _ALNUM:
            items.append(char)
        else:
            raise PatternError("invalid_character")
        k += 1
    if not items:
        raise PatternError("invalid_class")
    return "[" + ("^" if negate else "") + "".join(items) + "]"


def _tokenize(body: str) -> list[tuple[str, str, str]]:
    """``(kind, regex fragment or literal, display text)`` tokens of a canonicalised glob."""
    tokens: list[tuple[str, str, str]] = []
    i = 0
    while i < len(body):
        char = body[i]
        if char == "*":
            if not tokens or tokens[-1][0] != "star":
                tokens.append(("star", "*", "*"))
            i += 1
        elif char == "?":
            tokens.append(("any", "?", "?"))
            i += 1
        elif char == "[":
            end = _class_end(body, i)
            if end is None:
                raise PatternError("invalid_class")
            tokens.append(("class", _class_regex(body[i + 1:end]), body[i:end + 1].lower()))
            i = end + 1
        else:
            lower = char.lower()
            if lower in _SEPARATORS:
                if not tokens or tokens[-1][:2] != ("lit", "-"):
                    tokens.append(("lit", "-", "-"))
            elif lower in _ALNUM:
                tokens.append(("lit", lower, lower))
            else:
                raise PatternError("invalid_character")
            i += 1
    return tokens


def _regex_for(tokens: Sequence[tuple[str, str, str]]) -> str:
    segments: list[str] = []
    current: list[str] = []
    stars = 0
    for kind, value, _display in tokens:
        if kind == "star":
            segments.append("".join(current))
            current = []
            stars += 1
        elif kind == "any":
            current.append(".")
        elif kind == "class":
            current.append(value)
        else:
            current.append(re.escape(value))
    segments.append("".join(current))
    if not stars:
        return segments[0] + r"\Z"
    head, *middle, tail = segments
    # Each wildcard segment is matched lazily inside an atomic group: glob segments have a fixed
    # width, so the earliest placement is always a valid one and no backtracking is needed.
    return head + "".join(f"(?>.*?{m})" for m in middle) + ".*" + tail + r"\Z"


def compile_pattern(raw: object, source: str = SOURCE_SETTINGS) -> NamespacePattern:
    """Compile one configured pattern; raises :class:`PatternError` when it is unusable."""
    if not isinstance(raw, str):
        raise PatternError("not_a_string")
    text = raw.strip()
    if not text:
        raise PatternError("empty")
    if len(text) > MAX_PATTERN_LENGTH:
        raise PatternError("too_long")
    exclude = text.startswith("!")
    body = text[1:].strip() if exclude else text
    if exclude and source != SOURCE_SETTINGS:
        raise PatternError("exclusion_not_allowed")
    if not body:
        raise PatternError("empty")
    tokens = _tokenize(body)
    literal = sum(1 for kind, value, _ in tokens if kind == "lit" and value in _ALNUM)
    if literal < MIN_LITERAL_CHARS:
        raise PatternError("too_broad")
    try:
        regex = re.compile(_regex_for(tokens))
    except re.error as exc:  # defensive: the tokenizer only emits valid fragments
        raise PatternError("invalid_pattern") from exc
    glob = "".join(display for _, _, display in tokens)
    return NamespacePattern(raw=sanitize_text(text, max_len=MAX_PATTERN_LENGTH), glob=glob, source=source,
                            regex=regex, exclude=exclude)


class PrivateNamespaces:
    """A set of compiled include / exclude patterns. Immutable after construction; thread-safe."""

    def __init__(self, patterns: Iterable[NamespacePattern] = (), rejected: Iterable[dict] = ()) -> None:
        unique: dict[tuple[bool, str], NamespacePattern] = {}
        for p in sorted(patterns, key=lambda p: (p.exclude, p.glob, _SOURCE_RANK.get(p.source, 9))):
            unique.setdefault((p.exclude, p.glob), p)
        self.includes: tuple[NamespacePattern, ...] = tuple(p for (excl, _), p in unique.items() if not excl)
        self.excludes: tuple[NamespacePattern, ...] = tuple(p for (excl, _), p in unique.items() if excl)
        self.rejected: tuple[dict, ...] = tuple(rejected)

    @classmethod
    def from_sources(cls, sources: Mapping[str, Iterable[object] | None]) -> PrivateNamespaces:
        """Compile patterns from ``{source: patterns}``; unusable patterns are recorded, not raised.

        At most ``MAX_PATTERNS`` patterns (across sources) are examined; any further ones are only
        counted, into one ``too_many`` entry per source, so ``rejected`` stays bounded too.
        """
        compiled: list[NamespacePattern] = []
        rejected: list[dict] = []
        budget = MAX_PATTERNS
        for source in sorted(sources, key=lambda s: _SOURCE_RANK.get(s, 9)):
            values = sources[source]
            if values is None:
                continue
            if isinstance(values, str):
                values = values.split(",")
            overflow = 0
            for raw in values:
                if isinstance(raw, str) and not raw.strip():
                    continue
                if budget <= 0:
                    overflow += 1
                    continue
                budget -= 1
                try:
                    compiled.append(compile_pattern(raw, source))
                except PatternError as exc:
                    rejected.append({"pattern": sanitize_text(raw, max_len=MAX_PATTERN_LENGTH), "source": source,
                                     "reason": exc.reason})
            if overflow:
                rejected.append({"pattern": f"<{overflow} more>", "source": source, "reason": "too_many"})
        return cls(compiled, rejected)

    @property
    def configured(self) -> bool:
        return bool(self.includes)

    def __bool__(self) -> bool:
        return self.configured

    def excluded(self, name: object) -> NamespacePattern | None:
        canonical = canonical_name(name)
        if canonical is None:
            return None
        return next((p for p in self.excludes if p.matches(canonical)), None)

    def match(self, name: object) -> NamespaceMatch | None:
        """The first (sorted) include pattern matching ``name``, unless an exclusion matches it."""
        canonical = canonical_name(name)
        if canonical is None or not self.includes:
            return None
        if any(p.matches(canonical) for p in self.excludes):
            return None
        for p in self.includes:
            if p.matches(canonical):
                return NamespaceMatch(name=canonical, pattern=p.glob, raw=p.raw, source=p.source)
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "patterns": [{"pattern": p.glob, "source": p.source} for p in self.includes],
            "exclusions": [{"pattern": p.glob, "source": p.source} for p in self.excludes],
            "rejected": [dict(r) for r in self.rejected],
        }


def _items(values: object) -> tuple[Any, ...]:
    if values is None:
        return ()
    if isinstance(values, str):  # "a-*,b-*" - never explode a string into one pattern per character
        return tuple(values.split(","))
    try:
        return tuple(values)  # type: ignore[arg-type]
    except TypeError:
        return (values,)


@lru_cache(maxsize=64)
def _cached_namespaces(settings_patterns: tuple[str, ...], scan_patterns: tuple[str, ...]) -> PrivateNamespaces:
    return PrivateNamespaces.from_sources({SOURCE_SETTINGS: settings_patterns, SOURCE_SCAN_OPTIONS: scan_patterns})


def resolve_private_namespaces(options: Any = None, *, settings_patterns: Iterable[str] | None = None,
                               ) -> PrivateNamespaces:
    """Patterns from settings (``PRIVATE_PACKAGE_PATTERNS``) plus a scan's ``private_namespaces``.

    Settings are read at call time so configuration changes apply to the next scan. Compiled sets
    are immutable and cached by pattern values, so concurrent scans share them safely.
    """
    if settings_patterns is None:
        from app.core.config import settings

        settings_patterns = settings.PRIVATE_PACKAGE_PATTERNS
    settings_items = _items(settings_patterns)
    scan_items = _items(getattr(options, "private_namespaces", None) if options is not None else None)
    cacheable = len(settings_items) + len(scan_items) <= 4 * MAX_PATTERNS and all(
        isinstance(v, str) for v in (*settings_items, *scan_items))
    if cacheable:
        return _cached_namespaces(settings_items, scan_items)
    return PrivateNamespaces.from_sources({SOURCE_SETTINGS: settings_items, SOURCE_SCAN_OPTIONS: scan_items})


# ======================================================================================
# index classification
# ======================================================================================
@dataclass(frozen=True)
class IndexLocation:
    host: str
    port: int | None
    path: str  # without trailing "/"


def parse_index_url(url: object) -> IndexLocation | None:
    """Host / port / path of an index URL, ignoring userinfo and query. ``None`` when unparseable."""
    if not isinstance(url, str):
        return None
    match = _URL_RE.match(url.strip()[:MAX_URL_LENGTH])
    if not match:
        return None
    scheme, netloc, path = match.groups()
    hostport = netloc.rpartition("@")[2]  # redacted userinfo ("[REDACTED]@") is dropped here too
    if not hostport:
        return None
    try:
        parts = urlsplit(f"//{hostport}")
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host:
        return None
    default = {"https": 443, "http": 80}.get(scheme.lower())
    if port == default:
        port = None
    return IndexLocation(host=host.lower().rstrip("."), port=port, path=path.rstrip("/"))


class IndexClassifier:
    """Classifies package-index URLs against ``PRIVATE_INDEX_URLS``.

    ``public``: the host is a public registry anyone can publish to (checked first, so listing PyPI
    as "private" cannot hide it). ``private``: same host and port as a configured private index and
    a path inside its path (segment-wise prefix). ``local``: no host (a file path / find-links
    directory). ``other``: everything else - a mirror or proxy whose contents Warden cannot know.
    """

    def __init__(self, private_index_urls: Iterable[object] | None = None) -> None:
        if private_index_urls is None:
            from app.core.config import settings

            private_index_urls = settings.PRIVATE_INDEX_URLS
        locations = [parse_index_url(u) for u in private_index_urls]
        self.private: tuple[IndexLocation, ...] = tuple(loc for loc in locations if loc is not None)
        self.invalid_count = sum(1 for loc in locations if loc is None)

    @staticmethod
    def _inside(candidate: IndexLocation, private: IndexLocation) -> bool:
        if candidate.host != private.host or candidate.port != private.port:
            return False
        return not private.path or candidate.path == private.path or candidate.path.startswith(private.path + "/")

    def classify(self, url: object) -> str:
        location = parse_index_url(url)
        if location is None:
            return LOCAL if isinstance(url, str) and url.strip() and "://" not in url else OTHER
        if location.host in PUBLIC_REGISTRY_HOSTS:
            return PUBLIC
        if any(self._inside(location, p) for p in self.private):
            return PRIVATE
        return OTHER


# ======================================================================================
# lazy exports (keep ``import app.analysis.depconf`` free of HTTP / SBOM imports)
# ======================================================================================
_EXPORTS: dict[str, tuple[str, str]] = {
    "PublicIndexSnapshot": ("app.analysis.depconf.index_snapshot", "PublicIndexSnapshot"),
    "SnapshotError": ("app.analysis.depconf.index_snapshot", "SnapshotError"),
    "load_snapshot": ("app.analysis.depconf.index_snapshot", "load_snapshot"),
    "load_configured_snapshot": ("app.analysis.depconf.index_snapshot", "load_configured_snapshot"),
    "PublicIndexLookup": ("app.analysis.depconf.project", "PublicIndexLookup"),
    "project_confusion_findings": ("app.analysis.depconf.project", "project_confusion_findings"),
}

__all__ = sorted([
    "IndexClassifier", "IndexLocation", "NamespaceMatch", "NamespacePattern", "PatternError", "PrivateNamespaces",
    "PUBLIC_REGISTRY_HOSTS", "canonical_name", "compile_pattern", "parse_index_url", "resolve_private_namespaces",
    *_EXPORTS,
])


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'app.analysis.depconf' has no attribute {name!r}")
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value
