"""pip requirements-file parser (``requirements*.txt``, ``constraints*.txt``), pure and in-memory.

The line model mirrors pip's own ``req_file`` preprocessing so Warden sees what pip would
install: physical lines are split the way ``str.splitlines`` splits them, a trailing backslash
joins the next line, ``#`` comments are stripped when they start a line or follow whitespace,
and the requirement is the run of tokens before the first ``-``-prefixed option.

Security-relevant differences from pip, all deliberate:

* ``-r`` / ``-c`` includes are resolved **only among the in-memory files provided**; nothing is
  read from disk and remote includes are never fetched. Include cycles are detected.
* Editable, URL, VCS and local-path requirements are recorded as *unresolved* with a warning;
  they are never fetched or built.
* ``${VAR}`` references are not expanded (Warden never reads its own environment into a scan).
* Index URLs are credential-redacted before being recorded.
* Line numbers are editor line numbers (``\\n``/``\\r\\n``/``\\r``). pip additionally treats
  form feeds, U+2028 and similar characters as line breaks; their presence is warned about
  because they can hide a requirement from a human reviewer.
* Comments are stripped with a linear scan equivalent to pip's ``(^|\\s+)#.*$`` substitution;
  that regex backtracks quadratically on long whitespace runs, which a hostile file can exploit.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

from app.core.config import settings
from app.sbom.models import ManifestDependency
from app.sbom.parsers import (
    CONSTRAINTS,
    MAX_LINE_CHARS,
    MAX_NAME_LEN,
    REQUIREMENTS,
    ManifestParseResult,
    dependency_from_pep508,
    display,
    index_source,
    load_manifest,
    normalize_path,
    parse_hash_token,
    redact_url,
    valid_project_name,
    warn,
)

_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_EGG_RE = re.compile(r"(?:^|[#&])egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar")
_UNUSUAL_SEPARATORS = frozenset("\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")
_MAX_INCLUDE_DEPTH = 16
_DEV_TOKENS = frozenset({"dev", "develop", "development", "test", "tests", "testing", "lint", "docs", "doc", "ci",
                         "typing"})

# option -> (canonical name, takes a value)
_OPTIONS: dict[str, tuple[str, bool]] = {
    "-r": ("requirement", True), "--requirement": ("requirement", True),
    "-c": ("constraint", True), "--constraint": ("constraint", True),
    "-e": ("editable", True), "--editable": ("editable", True),
    "-i": ("index-url", True), "--index-url": ("index-url", True),
    "--extra-index-url": ("extra-index-url", True),
    "--no-index": ("no-index", False),
    "-f": ("find-links", True), "--find-links": ("find-links", True),
    "--trusted-host": ("trusted-host", True),
    "--hash": ("hash", True),
    "--pre": ("pre", False),
    "--prefer-binary": ("prefer-binary", False),
    "--require-hashes": ("require-hashes", False),
    "--only-binary": ("only-binary", True),
    "--no-binary": ("no-binary", True),
    "--use-feature": ("use-feature", True),
    "--global-option": ("global-option", True),
    "--config-settings": ("config-settings", True), "-C": ("config-settings", True),
}
_SHORT_WITH_VALUE = {k for k, (_, takes) in _OPTIONS.items() if takes and len(k) == 2}
_PER_REQUIREMENT_OPTIONS = frozenset({"hash", "global-option", "config-settings"})


@dataclass
class _State:
    sources: Mapping[str, object]
    result: ManifestParseResult
    limit: int
    visited: set[tuple[str, str]] = field(default_factory=set)
    stack: list[str] = field(default_factory=list)
    count: int = 0
    limit_hit: bool = False


def scope_for_file(path: str) -> str:
    """``dev`` for files whose name or parent directory marks them as development-only.

    A naming heuristic (``requirements-dev.txt``, ``requirements/test.txt``, ``docs/requirements.txt``);
    everything else is ``required``.
    """
    stem = posixpath.basename(path).rsplit(".", 1)[0].lower()
    parent = posixpath.basename(posixpath.dirname(path)).lower()
    tokens = set(re.split(r"[-_.\s]+", stem)) | set(re.split(r"[-_.\s]+", parent))
    return "dev" if tokens & _DEV_TOKENS else "required"


def parse_requirements(
    path: str,
    files: Mapping[str, object],
    *,
    constraints: bool = False,
    max_dependencies: int | None = None,
) -> ManifestParseResult:
    """Parse ``path`` (and any ``-r``/``-c`` includes present in ``files``).

    ``files`` maps relative paths to raw content; keys are normalised the same way include
    targets are. ``constraints=True`` parses the file as a pip constraints file (entries do not
    add dependencies).
    """
    sources = {normalize_path(k): v for k, v in files.items() if isinstance(k, str)}
    root = normalize_path(path)
    result = ManifestParseResult(file=root, type=CONSTRAINTS if constraints else REQUIREMENTS)
    limit = settings.MAX_PROJECT_COMPONENTS if max_dependencies is None else max(0, max_dependencies)
    state = _State(sources=sources, result=result, limit=limit)
    _parse_file(state, root, "constraint" if constraints else "requirement", 0)
    return result


# --------------------------------------------------------------------------------------
def _is_comment_line(line: str) -> bool:
    """pip's ``COMMENT_RE.match(line)``: optional leading whitespace, then ``#``."""
    return line.lstrip()[:1] == "#"


def _strip_comment(line: str) -> str:
    """Linear equivalent of pip's ``re.sub(r"(^|\\s+)#.*$", "", line)`` for a single logical line.

    The comment starts at the first ``#`` that begins the line or follows whitespace; that
    whitespace run is removed with it.
    """
    pos = line.find("#")
    while pos >= 0:
        if pos == 0 or line[pos - 1].isspace():
            start = pos
            while start > 0 and line[start - 1].isspace():
                start -= 1
            return line[:start]
        pos = line.find("#", pos + 1)
    return line


def _parse_file(state: _State, path: str, kind: str, depth: int) -> None:
    warnings = state.result.warnings
    if path in state.stack:
        chain = " -> ".join(display(p) for p in [*state.stack, path])
        warn(warnings, f"include cycle detected: {chain}")
        return
    if (path, kind) in state.visited:
        return
    if depth > _MAX_INCLUDE_DEPTH:
        warn(warnings, f"{display(path)}: include depth exceeds {_MAX_INCLUDE_DEPTH}; not parsed")
        return
    raw = state.sources.get(path)
    if raw is None:
        warn(warnings, f"included file {display(path)} was not provided (includes are never read from disk)")
        return
    state.visited.add((path, kind))
    text, digest, status = load_manifest(path, raw, warnings)
    if not any(m["file"] == path for m in state.result.manifests):
        mtype = CONSTRAINTS if kind == "constraint" else REQUIREMENTS
        state.result.manifests.append({"file": path, "type": mtype, "sha256": digest, "status": status})
    if text is None:
        return
    state.stack.append(path)
    try:
        for line_no, line in _logical_lines(text, path, warnings):
            if state.limit_hit:
                break
            _parse_line(state, path, kind, line_no, line, depth)
    finally:
        state.stack.pop()


def _logical_lines(text: str, path: str, warnings: list[str]):
    """Yield ``(editor_line_number, logical_line)`` with continuations joined and comments removed."""
    physical: list[tuple[int, str]] = []
    editor_line = 1
    unusual = False
    for segment in text.splitlines(keepends=True):
        if segment.endswith("\r\n"):
            body, newline = segment[:-2], True
        elif segment[-1:] in ("\n", "\r"):
            body, newline = segment[:-1], True
        elif segment and segment[-1] in _UNUSUAL_SEPARATORS:
            body, newline, unusual = segment[:-1], False, True
        else:
            body, newline = segment, False
        physical.append((editor_line, body))
        if newline:
            editor_line += 1
    if unusual:
        warn(warnings, f"{display(path)}: contains unusual line separators (form feed, U+2028, ...) that pip treats "
             "as line breaks; line numbers follow editor lines")

    buffer: list[str] = []
    buffer_len = 0
    primary = 0
    for line_no, line in physical:
        is_comment = _is_comment_line(line)
        if not line.endswith("\\") or is_comment:
            if is_comment:
                line = " " + line
            if buffer:
                buffer.append(line)
                buffer_len += len(line)
                start, joined = primary, ("".join(buffer) if buffer_len <= MAX_LINE_CHARS else None)
                buffer, buffer_len = [], 0
            else:
                start, joined = line_no, (line if len(line) <= MAX_LINE_CHARS else None)
            if joined is None:
                warn(warnings, f"{display(path)}:{start}: line longer than {MAX_LINE_CHARS} characters; skipped")
                continue
            cleaned = _strip_comment(joined).strip()
            if cleaned:
                yield start, cleaned
        else:
            if not buffer:
                primary = line_no
            if buffer_len <= MAX_LINE_CHARS:
                piece = line.strip("\\")
                buffer.append(piece)
            buffer_len += len(line)
    if buffer:
        if buffer_len > MAX_LINE_CHARS:
            warn(warnings, f"{display(path)}:{primary}: line longer than {MAX_LINE_CHARS} characters; skipped")
        else:
            cleaned = _strip_comment("".join(buffer)).strip()
            if cleaned:
                yield primary, cleaned


def _break_args_options(line: str) -> tuple[str, str]:
    """pip's split: requirement tokens up to the first token that starts with ``-``.

    Same result as pip's ``break_args_options`` (split on single spaces, re-join both halves) but
    computed with one ``str.find``: pip pops from the front of the token list, which is quadratic for
    a hostile line made of tens of thousands of spaces. A token starts with ``-`` exactly when it
    begins the line or follows a space.
    """
    if line.startswith("-"):
        return "", line
    index = line.find(" -")
    if index < 0:
        return line, ""
    return line[:index], line[index + 1 :]


def _parse_options(tokens: list[str], warnings: list[str], where: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        name, value = token, None
        if token.startswith("--") and "=" in token:
            name, value = token.split("=", 1)
        elif token[:2] in _SHORT_WITH_VALUE and len(token) > 2 and not token.startswith("--"):
            name, value = token[:2], token[2:]
        spec = _OPTIONS.get(name)
        if spec is None:
            warn(warnings, f"{where}: unsupported option {display(token)} ignored")
            continue
        canonical, takes_value = spec
        if takes_value and value is None:
            if i >= len(tokens):
                warn(warnings, f"{where}: option {name} is missing its value")
                continue
            value = tokens[i]
            i += 1
        out.append((canonical, value))
    return out


def _parse_line(state: _State, path: str, kind: str, line_no: int, line: str, depth: int) -> None:
    warnings = state.result.warnings
    where = f"{display(path)}:{line_no}"
    if "${" in line:
        warn(warnings, f"{where}: environment variable references are not expanded")
    args, options = _break_args_options(line)
    try:
        tokens = shlex.split(options) if options else []
    except ValueError:
        warn(warnings, f"{where}: could not tokenise options (unbalanced quotes); line skipped")
        return
    parsed = _parse_options(tokens, warnings, where)

    if not args:
        for name, value in parsed:
            if name in ("requirement", "constraint") and value is not None:
                _include(state, path, kind, name, value, line_no, depth)
            elif name == "editable" and value is not None:
                if kind == "constraint":
                    warn(warnings, f"{where}: editable requirements are not allowed in constraints files")
                    continue
                _add_reference(state, path, kind, line_no, value, [], editable=True)
            elif name in ("index-url", "extra-index-url", "find-links") and value is not None:
                state.result.index_sources.append(index_source(name, value, path, line_no))
            elif name == "no-index":
                state.result.index_sources.append({"kind": "no-index", "url": "", "host": None, "file": path,
                                                   "line": line_no})
            elif name == "hash":
                warn(warnings, f"{where}: --hash without a requirement ignored")
        return

    hashes: list[str] = []
    for name, value in parsed:
        if name == "hash":
            token = parse_hash_token(value or "")
            if token is None:
                warn(warnings, f"{where}: invalid --hash value ignored (expected sha256/sha384/sha512:<hex>)")
            else:
                hashes.append(token)
        elif name not in _PER_REQUIREMENT_OPTIONS:
            warn(warnings, f"{where}: option --{name} is not valid after a requirement; ignored")
    if _looks_like_reference(args):
        _add_reference(state, path, kind, line_no, args, hashes, editable=False)
        return
    dep = dependency_from_pep508(
        args, source_file=path, line=line_no, warnings=warnings,
        scope=scope_for_file(path), kind=kind, direct=kind == "requirement", hashes=hashes,
    )
    if dep is not None:
        _append(state, dep)


def _path_like(text: str) -> bool:
    return bool(text.startswith((".", "/", "~", "\\")) or "/" in text or "\\" in text or _WINDOWS_DRIVE_RE.match(text))


def _looks_like_reference(text: str) -> bool:
    """True for a bare URL / VCS / path / archive reference; False for PEP 508 requirement text.

    Mirrors pip: ``name @ url`` is a PEP 508 direct reference when the part before ``@`` does not
    look like a path, even if the URL ends in an archive suffix.
    """
    candidate = text.split(";", 1)[0].strip()
    if _URL_SCHEME_RE.match(candidate):
        return True
    head, at, _rest = candidate.partition("@")
    if at and not _path_like(head.strip()):
        return False
    return _path_like(candidate) or candidate.lower().endswith(_ARCHIVE_SUFFIXES)


def _add_reference(state: _State, path: str, kind: str, line_no: int, target: str, hashes: list[str], *,
                   editable: bool) -> None:
    """Record an editable / URL / VCS / path requirement as unresolved. Never fetched."""
    warnings = state.result.warnings
    where = f"{display(path)}:{line_no}"
    target = target.strip()
    if not _looks_like_reference(target):
        # "-e name @ url" or a plain requirement passed to -e: fall back to PEP 508.
        dep = dependency_from_pep508(target, source_file=path, line=line_no, warnings=warnings,
                                     scope=scope_for_file(path), kind=kind, direct=kind == "requirement",
                                     hashes=hashes)
        if dep is not None:
            warn(warnings, f"{where}: editable requirement for '{dep.name}' recorded as unresolved (never built)")
            dep.pinned_version = None
            _append(state, dep)
        return
    location = target.split(";", 1)[0].strip()
    name = None
    egg = _EGG_RE.search(location)
    if egg:
        name = egg.group(1)
    else:
        filename = posixpath.basename(location.split("#", 1)[0].split("?", 1)[0].replace("\\", "/"))
        lowered = filename.lower()
        try:
            if lowered.endswith(".whl"):
                name = str(parse_wheel_filename(filename)[0])
            elif lowered.endswith((".tar.gz", ".zip")):
                name = str(parse_sdist_filename(filename)[0])
        except (InvalidWheelFilename, InvalidSdistFilename):
            name = None
    label = "editable" if editable else "direct URL/path"
    if not name or not valid_project_name(name) or len(name) > MAX_NAME_LEN:
        warn(warnings, f"{where}: {label} requirement {redact_url(location)} has no determinable package name; "
             "not recorded (never fetched)")
        return
    warn(warnings, f"{where}: {label} requirement for '{name}' recorded as unresolved (never fetched)")
    _append(state, ManifestDependency(
        name=name, normalized_name=canonicalize_name(name), specifier="", pinned_version=None,
        source_file=path, line=line_no, hashes=sorted(set(hashes)), direct=kind == "requirement",
        scope=scope_for_file(path), url=redact_url(location), kind=kind,
    ))


def _append(state: _State, dep: ManifestDependency) -> None:
    if state.count >= state.limit:
        if not state.limit_hit:
            warn(state.result.warnings, f"more than {state.limit} requirements; remaining entries not parsed")
        state.limit_hit = True
        return
    state.count += 1
    state.result.dependencies.append(dep)


def _include(state: _State, path: str, kind: str, option: str, target: str, line_no: int, depth: int) -> None:
    warnings = state.result.warnings
    target = target.strip()
    if _URL_SCHEME_RE.match(target):
        warn(warnings, f"{display(path)}:{line_no}: remote include {redact_url(target)} not fetched")
        return
    resolved = normalize_path(posixpath.join(posixpath.dirname(path), target.replace("\\", "/")))
    new_kind = "constraint" if option == "constraint" or kind == "constraint" else "requirement"
    _parse_file(state, resolved, new_kind, depth + 1)
