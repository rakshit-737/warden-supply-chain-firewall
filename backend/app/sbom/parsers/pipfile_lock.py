"""Pipenv manifests: ``Pipfile`` (declared dependencies) and ``Pipfile.lock`` (locked versions).

``Pipfile.lock`` records versions (``"==1.2.3"``), distribution hashes and markers per package,
split into ``default`` (required) and ``develop`` (dev) sections - but **no dependency
relationships**. Pairing it with the ``Pipfile`` in the same directory is what lets
``parse_project`` tell direct dependencies from transitive ones; without a ``Pipfile`` every
locked package is treated as direct and a warning says so.

JSON has no position API, so ``Pipfile.lock`` line numbers are only recorded when a package key
appears exactly once inside its section's line range; otherwise the line is left unknown.
"""

from __future__ import annotations

import bisect
import json
import re
import tomllib

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from app.core.config import settings
from app.sbom.models import ManifestDependency
from app.sbom.parsers import (
    MAX_NAME_LEN,
    PIPFILE,
    PIPFILE_LOCK,
    LockedPackage,
    ManifestParseResult,
    bound_specifier,
    clean_version,
    credential_like,
    display,
    index_source,
    load_manifest,
    parse_hash_token,
    pinned_version,
    redact_url,
    safe_marker,
    scan_toml_positions,
    valid_project_name,
    warn,
)

_NON_PACKAGE_TABLES = frozenset({"source", "requires", "pipenv", "scripts"})
_REFERENCE_KEYS = ("git", "path", "file", "url")
_JSON_OBJECT_KEY_RE = re.compile(r'^\s*"([^"\\]{1,214})"\s*:\s*\{')


def _section_scope(section: str) -> tuple[str, str | None]:
    if section in ("packages", "default"):
        return "required", None
    if section in ("dev-packages", "develop"):
        return "dev", None
    return "optional", display(section)  # custom Pipenv package categories


def _specifier(value: object, warnings: list[str], where: str, name: str) -> tuple[str, str | None]:
    if not isinstance(value, str) or value.strip() in ("", "*"):
        return "", None
    raw = value.strip()
    try:
        spec = SpecifierSet(raw)
    except InvalidSpecifier:
        warn(warnings, f"{where}: invalid version specifier {display(raw)!s} for '{display(name)}'; kept verbatim")
        return bound_specifier(raw, warnings, where), None
    pinned = pinned_version(spec)
    return bound_specifier(str(spec), warnings, where), clean_version(pinned, warnings, where) if pinned else None


def _reference(entry: dict) -> tuple[str, str] | None:
    for key in _REFERENCE_KEYS:
        if isinstance(entry.get(key), str):
            return key, entry[key]
    return None


# ======================================================================================
# Pipfile
# ======================================================================================
def parse_pipfile(path: str, content: object) -> ManifestParseResult:
    result = ManifestParseResult(file=path, type=PIPFILE)
    text, digest, status = load_manifest(path, content, result.warnings)
    result.manifests.append({"file": path, "type": PIPFILE, "sha256": digest, "status": status})
    if text is None:
        return result
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        warn(result.warnings, f"{display(path)}: invalid TOML ({type(exc).__name__}); not parsed")
        result.manifests[-1]["status"] = "error"
        return result
    positions = scan_toml_positions(text)
    sources = data.get("source")
    source_urls: dict[str, str] = {}
    if isinstance(sources, list):
        for i, source in enumerate(sources):
            if isinstance(source, dict) and isinstance(source.get("url"), str):
                result.index_sources.append(index_source(
                    "pipenv-source", source["url"], path, positions.line_of("source", f"[{i}]", "url"),
                    name=source.get("name") if isinstance(source.get("name"), str) else None,
                ))
                if isinstance(source.get("name"), str):
                    source_urls.setdefault(source["name"], redact_url(source["url"]))
    limit = settings.MAX_PROJECT_COMPONENTS
    for section in sorted(k for k in data if isinstance(k, str) and k not in _NON_PACKAGE_TABLES):
        table = data[section]
        if not isinstance(table, dict):
            continue
        scope, group = _section_scope(section)
        for name in table:
            if len(result.dependencies) >= limit:
                warn(result.warnings, f"{display(path)}: more than {limit} dependencies; truncated")
                return result
            line = positions.line_of(section, name) if isinstance(name, str) else None
            dep = _pipfile_entry(path, line, name, table[name], scope, group, result.warnings)
            if dep is not None:
                dep.index_url = _index_for(table[name], source_urls, result.warnings, path, line)
                result.dependencies.append(dep)
    return result


def _index_for(entry: object, source_urls: dict[str, str], warnings: list[str], path: str,
               line: int | None) -> str | None:
    """Redacted URL of the named ``index`` an entry is pinned to (``None`` when not named)."""
    index = entry.get("index") if isinstance(entry, dict) else None
    if not isinstance(index, str):
        return None
    url = source_urls.get(index)
    if url is None:
        warn(warnings, f"{display(path)}{f':{line}' if line else ''}: package index {display(index)!s} "
             "is not declared in the sources")
    return url


def _pipfile_entry(path: str, line: int | None, name: object, value: object, scope: str, group: str | None,
                   warnings: list[str]) -> ManifestDependency | None:
    where = f"{display(path)}{f':{line}' if line else ''}"
    if not isinstance(name, str) or not valid_project_name(name) or len(name) > MAX_NAME_LEN:
        warn(warnings, f"{where}: invalid package name {display(name)!s}; skipped")
        return None
    entry = {"version": value} if isinstance(value, str) else value
    if not isinstance(entry, dict):
        warn(warnings, f"{where}: unsupported value for '{display(name)}'; skipped")
        return None
    extras = sorted(e for e in entry.get("extras", []) if isinstance(e, str) and not credential_like(e)) \
        if isinstance(entry.get("extras"), list) else []
    markers = safe_marker(entry.get("markers"), warnings, where)
    reference = _reference(entry)
    if reference is not None:
        warn(warnings, f"{where}: '{display(name)}' comes from a {reference[0]} source; recorded as unresolved "
             "(never fetched)")
        return ManifestDependency(name=name, normalized_name=canonicalize_name(name), extras=extras, markers=markers,
                                  source_file=path, line=line, scope=scope, group=group,
                                  url=redact_url(reference[1]))
    specifier, pinned = _specifier(entry.get("version"), warnings, where, name)
    return ManifestDependency(name=name, normalized_name=canonicalize_name(name), specifier=specifier,
                              pinned_version=pinned, extras=extras, markers=markers, source_file=path, line=line,
                              scope=scope, group=group)


# ======================================================================================
# Pipfile.lock
# ======================================================================================
def parse_pipfile_lock(path: str, content: object) -> ManifestParseResult:
    result = ManifestParseResult(file=path, type=PIPFILE_LOCK)
    text, digest, status = load_manifest(path, content, result.warnings)
    result.manifests.append({"file": path, "type": PIPFILE_LOCK, "sha256": digest, "status": status})
    if text is None:
        return result
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        warn(result.warnings, f"{display(path)}: invalid JSON ({type(exc).__name__}); not parsed")
        result.manifests[-1]["status"] = "error"
        return result
    if not isinstance(data, dict):
        warn(result.warnings, f"{display(path)}: top-level JSON value must be an object")
        return result
    meta = data.get("_meta")
    sources = meta.get("sources") if isinstance(meta, dict) else None
    source_urls: dict[str, str] = {}
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict) and isinstance(source.get("url"), str):
                result.index_sources.append(index_source(
                    "pipenv-source", source["url"], path, None,
                    name=source.get("name") if isinstance(source.get("name"), str) else None,
                ))
                if isinstance(source.get("name"), str):
                    source_urls.setdefault(source["name"], redact_url(source["url"]))
    sections = sorted(k for k in data if isinstance(k, str) and not k.startswith("_") and isinstance(data[k], dict))
    lines = _json_package_lines(text, sections, [k for k in data if isinstance(k, str)])
    limit = settings.MAX_PROJECT_COMPONENTS
    for section in sections:
        scope, _group = _section_scope(section)
        for name in sorted(k for k in data[section] if isinstance(k, str)):
            if len(result.packages) >= limit:
                warn(result.warnings, f"{display(path)}: more than {limit} locked packages; truncated")
                return result
            line = lines.get((section, name))
            locked = _lock_entry(path, line, name, data[section][name], scope, section, result.warnings)
            if locked is not None:
                locked.index_url = _index_for(data[section][name], source_urls, result.warnings, path, line)
                result.packages.append(locked)
    return result


def _lock_entry(path: str, line: int | None, name: str, entry: object, scope: str, section: str,
                warnings: list[str]) -> LockedPackage | None:
    where = f"{display(path)}{f':{line}' if line else ''}"
    if not valid_project_name(name):
        warn(warnings, f"{where}: invalid package name {display(name)!s}; skipped")
        return None
    if not isinstance(entry, dict):
        warn(warnings, f"{where}: entry for '{display(name)}' must be an object; skipped")
        return None
    locked = LockedPackage(name=name, normalized_name=canonicalize_name(name), version=None, source_file=path,
                           line=line, scope=scope, groups=[display(section)])
    reference = _reference(entry)
    if reference is not None:
        locked.source_type = reference[0]
        locked.source_url = redact_url(reference[1])
        warn(warnings, f"{where}: '{display(name)}' is locked from a {reference[0]} source; no registry purl "
             "assigned (never fetched)")
    _spec, pinned = _specifier(entry.get("version"), warnings, where, name)
    locked.version = pinned
    if pinned is None and reference is None:
        warn(warnings, f"{where}: '{display(name)}' has no exact locked version")
    hashes = entry.get("hashes")
    if isinstance(hashes, list):
        valid = {token for token in (parse_hash_token(h) for h in hashes if isinstance(h, str)) if token}
        if len(valid) != len(hashes):
            warn(warnings, f"{where}: {len(hashes) - len(valid)} malformed hash entr(ies) ignored for "
                 f"'{display(name)}'")
        locked.hashes = sorted(valid)
    return locked


def _json_package_lines(text: str, sections: list[str], top_keys: list[str]) -> dict[tuple[str, str], int]:
    """Map ``(section, package)`` to a line number when the key is unambiguous within its section."""
    occurrences: list[tuple[str, int]] = []
    for index, line in enumerate(text.split("\n")):
        m = _JSON_OBJECT_KEY_RE.match(line)
        if m:
            occurrences.append((m.group(1), index + 1))
    starts: dict[str, int] = {}
    for key in set(top_keys):
        found = [ln for k, ln in occurrences if k == key]
        if len(found) == 1:
            starts[key] = found[0]
    if any(section not in starts for section in sections):
        return {}
    boundaries = sorted((ln, key) for key, ln in starts.items())
    boundary_lines = [ln for ln, _ in boundaries]
    candidates: dict[tuple[str, str], list[int]] = {}
    for key, ln in occurrences:
        pos = bisect.bisect_left(boundary_lines, ln) - 1
        if pos < 0 or boundary_lines[pos] == ln:
            continue
        section = boundaries[pos][1]
        if section in sections:
            candidates.setdefault((section, key), []).append(ln)
    return {k: v[0] for k, v in candidates.items() if len(v) == 1}
