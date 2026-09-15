"""``poetry.lock`` parser: locked packages, their dependency edges and distribution hashes.

Supports lock-version 1.x (hashes under ``[metadata.files]``) and 2.x (per-package ``files``).
Scope comes from ``groups`` (Poetry >= 1.5: ``main`` -> required, others -> dev), the legacy
``category`` key, or ``optional = true`` (installed only via an extra).

Edges follow the dependency metadata the lock records for each package; a dependency that is
not itself present in the lock (e.g. an unrequested optional extra) produces no edge. Packages
locked from git/url/file/directory sources are kept but get no PyPI purl, because their
artifact does not come from the registry.
"""

from __future__ import annotations

import tomllib

from packaging.utils import canonicalize_name

from app.core.config import settings
from app.sbom.parsers import (
    POETRY_LOCK,
    LockedPackage,
    ManifestParseResult,
    bound_specifier,
    clean_version,
    display,
    index_source,
    load_manifest,
    parse_hash_token,
    redact_url,
    scan_toml_positions,
    valid_project_name,
    warn,
)
from app.sbom.parsers.pyproject import poetry_constraint_to_pep440, poetry_dependency_specs


def parse_poetry_lock(path: str, content: object) -> ManifestParseResult:
    result = ManifestParseResult(file=path, type=POETRY_LOCK)
    text, digest, status = load_manifest(path, content, result.warnings)
    result.manifests.append({"file": path, "type": POETRY_LOCK, "sha256": digest, "status": status})
    if text is None:
        return result
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        warn(result.warnings, f"{display(path)}: invalid TOML ({type(exc).__name__}); not parsed")
        result.manifests[-1]["status"] = "error"
        return result
    packages = data.get("package")
    if not isinstance(packages, list):
        warn(result.warnings, f"{display(path)}: no [[package]] entries found")
        return result
    positions = scan_toml_positions(text)
    metadata = data.get("metadata")
    legacy_files = metadata.get("files") if isinstance(metadata, dict) else None
    legacy_files = legacy_files if isinstance(legacy_files, dict) else {}
    legacy_by_name = {canonicalize_name(k): v for k, v in legacy_files.items() if isinstance(k, str)}

    limit = settings.MAX_PROJECT_COMPONENTS
    if len(packages) > limit:
        warn(result.warnings, f"{display(path)}: {len(packages)} packages exceed MAX_PROJECT_COMPONENTS; truncated")
    for index, pkg in enumerate(packages[:limit]):
        line = positions.line_of("package", f"[{index}]", "name")
        where = f"{display(path)}{f':{line}' if line else ''}"
        if not isinstance(pkg, dict) or not valid_project_name(pkg.get("name")):
            warn(result.warnings, f"{where}: package entry {index} has no valid name; skipped")
            continue
        name = pkg["name"]
        normalized = canonicalize_name(name)
        version = clean_version(pkg.get("version"), result.warnings, where)
        if version is None:
            warn(result.warnings, f"{where}: '{name}' has no usable version")
        locked = LockedPackage(name=name, normalized_name=normalized, version=version, source_file=path, line=line,
                               dependencies_known=True)
        locked.hashes = _hashes(pkg.get("files"), result.warnings, where) or \
            _hashes(legacy_by_name.get(normalized), result.warnings, where)
        locked.groups = sorted(g for g in pkg.get("groups", []) if isinstance(g, str)) \
            if isinstance(pkg.get("groups"), list) else []
        locked.scope = _scope(pkg, locked.groups)
        locked.dependencies = _dependencies(pkg.get("dependencies"), result.warnings, where)
        source = pkg.get("source")
        if isinstance(source, dict) and isinstance(source.get("type"), str):
            source_type = source["type"].lower()
            url = source.get("url") if isinstance(source.get("url"), str) else None
            locked.source_type = source_type
            locked.source_url = redact_url(url) if url else None
            if source_type == "legacy" and url:
                source_line = positions.line_of("package", f"[{index}]", "source", "url")
                result.index_sources.append(index_source("poetry-lock-source", url, path, source_line,
                                                         name=source.get("reference")
                                                         if isinstance(source.get("reference"), str) else None))
            elif source_type != "legacy":
                warn(result.warnings, f"{where}: '{name}' is locked from a {display(source_type)} source; "
                     "no registry purl assigned (never fetched)")
        result.packages.append(locked)
    return result


def _scope(pkg: dict, groups: list[str]) -> str:
    if groups:
        if "main" in groups:
            return "optional" if pkg.get("optional") is True else "required"
        return "dev"
    if pkg.get("category") == "dev":
        return "dev"
    if pkg.get("optional") is True:
        return "optional"
    return "required"


def _hashes(files: object, warnings: list[str], where: str) -> list[str]:
    if not isinstance(files, list):
        return []
    out: set[str] = set()
    invalid = 0
    for entry in files:
        value = entry.get("hash") if isinstance(entry, dict) else None
        token = parse_hash_token(value) if isinstance(value, str) else None
        if token is None:
            invalid += 1
        else:
            out.add(token)
    if invalid:
        warn(warnings, f"{where}: {invalid} file hash entr{'y' if invalid == 1 else 'ies'} ignored (malformed)")
    return sorted(out)


def _dependencies(deps: object, warnings: list[str], where: str) -> list[tuple[str, str]]:
    if deps is None:
        return []
    if not isinstance(deps, dict):
        warn(warnings, f"{where}: package dependencies must be a table")
        return []
    out: list[tuple[str, str]] = []
    for name in sorted(k for k in deps if isinstance(k, str)):
        if not valid_project_name(name):
            warn(warnings, f"{where}: invalid dependency name {display(name)!s} ignored")
            continue
        specs = poetry_dependency_specs(deps[name]) or [{}]
        for spec in specs:
            raw = spec.get("version", "") if isinstance(spec.get("version", ""), str) else ""
            specifier, converted = poetry_constraint_to_pep440(raw)
            if not converted:
                specifier = raw
            out.append((canonicalize_name(name), bound_specifier(specifier, warnings, where)))
    return sorted(set(out))
