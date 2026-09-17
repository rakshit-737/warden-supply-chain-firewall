"""npm manifests: ``package.json``, ``package-lock.json`` and ``npm-shrinkwrap.json``.

Same rules as the Python parsers: contents only, never fetched or executed, bounded, fail soft.

* ``package.json`` declares the direct dependencies of its directory (``dependencies`` required,
  ``optionalDependencies`` optional, ``devDependencies`` dev; ``peerDependencies`` are not installed
  by this package and are not listed). A declaration's line is recorded only when its key can be
  located exactly in the text.
* A lock file (lockfileVersion 2 or 3, the ``packages`` map) pins every installed package, with
  its integrity hash, and gives the dependency edges. Node's resolution is followed: a dependency of
  ``node_modules/a`` is looked up in ``node_modules/a/node_modules`` first, then in each ancestor
  directory. lockfileVersion 1 (nested ``dependencies``) is read for versions and edges too.
* When a directory has a lock file, its components are ``locked`` and the lock's root entry decides
  which are direct; without one, declared ranges stay ``unresolved`` unless they are exact versions.
* Dependencies from git, URLs, local paths or tarballs are recorded with a credential-redacted
  ``url`` and no version, because nothing about them is fixed by a registry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import quote

from app.core.config import settings
from app.sbom.models import Component, DependencyEdge, ManifestDependency

PACKAGE_JSON = "npm-package"
PACKAGE_LOCK = "npm-lock"
_SCOPES = ("required", "optional", "dev")
SECTIONS = (("dependencies", "required"), ("optionalDependencies", "optional"), ("devDependencies", "dev"))
REGISTRY_HOSTS = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
MAX_LOCK_PACKAGES = 20_000

_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_EXACT_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_NON_REGISTRY_RE = re.compile(
    r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|workspace:|[\w.-]+/[\w.-]+$)"
)
_USERINFO_RE = re.compile(r"(?<=://)[^/@\s]+@")


def is_npm_manifest(path: str) -> str | None:
    base = posixpath.basename(path.replace("\\", "/")).lower()
    if "node_modules" in path.replace("\\", "/").split("/"):
        return None
    if base == "package.json":
        return PACKAGE_JSON
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return PACKAGE_LOCK
    return None


def normalize_npm_name(name: str) -> str:
    return name.strip().lower()


def npm_purl(name: str, version: str | None) -> str | None:
    if not version:
        return None
    if name.startswith("@") and "/" in name:
        scope, _, bare = name.partition("/")
        return f"pkg:npm/{quote(scope, safe='')}/{quote(bare, safe='')}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name, safe='')}@{quote(version, safe='')}"


def bom_ref(name: str, version: str | None) -> str:
    return npm_purl(name, version) or f"pkg:npm/{quote(normalize_npm_name(name), safe='@/')}"


def _integrity_hex(value: object) -> str | None:
    """``sha512-<base64>`` (SRI) as ``sha512:<hex>``; other algorithms are ignored."""
    if not isinstance(value, str):
        return None
    for token in value.split():
        algo, _, digest = token.partition("-")
        if algo not in ("sha512", "sha384", "sha256"):
            continue
        try:
            raw = base64.b64decode(digest, validate=True)
        except (binascii.Error, ValueError):
            continue
        return f"{algo}:{raw.hex()}"
    return None


def _redact(url: str) -> str:
    return _USERINFO_RE.sub("", url)[:300]


def _line_of_key(text: str, section: str, key: str) -> int | None:
    """Exact line of ``"key":`` inside the object that follows ``"section":``; None when ambiguous."""
    start = text.find(f'"{section}"')
    if start < 0 or text.find(f'"{section}"', start + 1) >= 0:
        return None
    brace = text.find("{", start)
    end = text.find("}", brace)
    if brace < 0 or end < 0:
        return None
    body = text[brace:end]
    matches = [m.start() for m in re.finditer(re.escape(json.dumps(key)) + r"\s*:", body)]
    if len(matches) != 1:
        return None
    return text.count("\n", 0, brace + matches[0]) + 1


@dataclass
class NpmResult:
    components: list[Component] = field(default_factory=list)
    edges: list[DependencyEdge] = field(default_factory=list)
    declarations: list[ManifestDependency] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    explicit_scope: dict[str, str] = field(default_factory=dict)


def _load(path: str, content: object, warnings: list[str]) -> dict | None:
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(raw, (bytes, bytearray)):
        return None
    if len(raw) > settings.MAX_MANIFEST_BYTES:
        warnings.append(f"{path}: larger than MAX_MANIFEST_BYTES, skipped")
        return None
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        warnings.append(f"{path}: not valid JSON, skipped")
        return None
    return data if isinstance(data, dict) else None


def _package_name_from_path(key: str) -> str:
    parts = key.split("node_modules/")
    return parts[-1].rstrip("/")


def parse_npm(files: Mapping[str, bytes | str], root_ref: str) -> NpmResult:

    result = NpmResult()
    by_dir: dict[str, dict[str, tuple[str, object]]] = {}
    for path in sorted(files):
        kind = is_npm_manifest(path)
        if kind:
            by_dir.setdefault(posixpath.dirname(path.replace("\\", "/")), {})[kind] = (path, files[path])

    components: dict[str, Component] = {}

    def add_component(name: str, version: str | None, *, source_file: str, direct: bool, scope: str,
                      resolution: str, integrity: str | None = None, url: str | None = None,
                      line: int | None = None, specifier: str = "") -> Component | None:
        if not _NAME_RE.match(name.lower()):
            result.warnings.append(f"{source_file}: invalid npm package name skipped")
            return None
        ref = bom_ref(name, version)
        comp = components.get(ref)
        if comp is None:
            comp = Component(bom_ref=ref, name=name, normalized_name=normalize_npm_name(name), version=version,
                             purl=npm_purl(name, version), ecosystem="npm", direct=direct, scope=scope,
                             resolution=resolution, specifier=specifier)
            components[ref] = comp
        comp.direct = comp.direct or direct
        if source_file not in comp.source_files:
            comp.source_files.append(source_file)
        comp.declared_at.append({"file": source_file, "line": line})
        if integrity and integrity not in comp.file_hashes:
            comp.file_hashes.append(integrity)
            algo, _, digest = integrity.partition(":")
            comp.hashes.setdefault(algo, digest)
        current = result.explicit_scope.get(ref)
        if current is None or _SCOPES.index(scope) < _SCOPES.index(current):
            result.explicit_scope[ref] = scope
        del url  # recorded on the declaration; components carry no URL field
        return comp

    for _directory, manifests in sorted(by_dir.items()):
        declared: dict[str, tuple[str, str, int | None]] = {}
        if PACKAGE_JSON in manifests:
            path, content = manifests[PACKAGE_JSON]
            data = _load(path, content, result.warnings)
            if data is not None:
                text = content if isinstance(content, str) else content.decode("utf-8", "replace")
                result.manifests.append({"file": path, "type": PACKAGE_JSON,
                                         "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
                for section, scope in SECTIONS:
                    deps = data.get(section)
                    if not isinstance(deps, dict):
                        continue
                    for name, spec in sorted(deps.items())[:settings.MAX_PROJECT_COMPONENTS]:
                        if not isinstance(name, str) or not isinstance(spec, str):
                            continue
                        line = _line_of_key(text, section, name)
                        declared.setdefault(name, (spec, scope, line))
                        non_registry = bool(_NON_REGISTRY_RE.match(spec.strip()))
                        result.declarations.append(ManifestDependency(
                            name=name, normalized_name=normalize_npm_name(name), specifier=spec[:200],
                            pinned_version=spec.lstrip("v") if _EXACT_RE.match(spec) else None,
                            source_file=path, line=line, direct=True, scope=scope,
                            url=_redact(spec) if non_registry else None,
                        ))

        if PACKAGE_LOCK in manifests:
            path, content = manifests[PACKAGE_LOCK]
            data = _load(path, content, result.warnings)
            if data is None:
                continue
            text = content if isinstance(content, str) else content.decode("utf-8", "replace")
            result.manifests.append({"file": path, "type": PACKAGE_LOCK,
                                     "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()})
            packages = data.get("packages")
            if isinstance(packages, dict):
                _read_lock_v2(packages, path, root_ref, add_component, result, declared)
            elif isinstance(data.get("dependencies"), dict):
                _read_lock_v1(data["dependencies"], path, root_ref, add_component, result, declared)
            else:
                result.warnings.append(f"{path}: unsupported lock file layout")
            continue

        for name, (spec, scope, line) in sorted(declared.items()):
            exact = _EXACT_RE.match(spec)
            non_registry = _NON_REGISTRY_RE.match(spec.strip())
            version = spec.lstrip("v") if exact else None
            comp = add_component(name, version, source_file=manifests[PACKAGE_JSON][0], direct=True, scope=scope,
                                 resolution="pinned" if exact else "unresolved", line=line,
                                 specifier="" if exact else spec[:200],
                                 url=_redact(spec) if non_registry else None)
            if comp is not None:
                result.edges.append(DependencyEdge(parent=root_ref, child=comp.bom_ref, specifier=spec[:200]))
        if declared and PACKAGE_LOCK not in manifests:
            result.warnings.append(f"{manifests[PACKAGE_JSON][0]}: no package-lock.json next to it; "
                                   "versions are not locked")

    result.components = sorted(components.values(), key=lambda c: c.bom_ref)[:settings.MAX_PROJECT_COMPONENTS]
    kept = {c.bom_ref for c in result.components}
    result.edges = sorted({(e.parent, e.child): e for e in result.edges
                           if e.child in kept and (e.parent == root_ref or e.parent in kept)}.values(),
                          key=lambda e: (e.parent, e.child))
    return result


def _read_lock_v2(packages: dict, path: str, root_ref: str, add_component, result: NpmResult,
                  declared: Mapping[str, tuple[str, str, int | None]]) -> None:
    entries = {k: v for k, v in list(packages.items())[:MAX_LOCK_PACKAGES]
               if isinstance(k, str) and isinstance(v, dict)}
    if len(packages) > MAX_LOCK_PACKAGES:
        result.warnings.append(f"{path}: more than {MAX_LOCK_PACKAGES} lock entries; truncated")
    root = entries.get("", {})
    root_deps: dict[str, str] = {}
    for section, _scope in SECTIONS:
        if isinstance(root.get(section), dict):
            root_deps.update({k: v for k, v in root[section].items() if isinstance(v, str)})
    refs: dict[str, str] = {}
    for key, entry in sorted(entries.items()):
        if not key.startswith("node_modules/") and "/node_modules/" not in key:
            continue  # workspace sources and the root
        if entry.get("link"):
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else _package_name_from_path(key)
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else ""
        non_registry = bool(resolved) and not resolved.startswith(REGISTRY_HOSTS)
        if entry.get("dev"):
            scope = "dev"
        elif entry.get("optional") or entry.get("devOptional"):
            scope = "optional"
        else:
            scope = "required"
        top_level = key.count("node_modules/") == 1
        direct = top_level and name in (root_deps or declared)
        decl = declared.get(name)
        comp = add_component(name, None if non_registry else version, source_file=path, direct=direct,
                             scope=scope, resolution="locked", integrity=_integrity_hex(entry.get("integrity")),
                             url=_redact(resolved) if non_registry else None,
                             line=decl[2] if decl and direct else None)
        if comp is not None:
            refs[key] = comp.bom_ref
            if direct:
                result.edges.append(DependencyEdge(parent=root_ref, child=comp.bom_ref,
                                                   specifier=(root_deps.get(name) or (decl[0] if decl else ""))[:200]))
    for key, entry in entries.items():
        parent_ref = refs.get(key)
        if parent_ref is None:
            continue
        deps: dict[str, str] = {}
        for section in ("dependencies", "optionalDependencies"):
            if isinstance(entry.get(section), dict):
                deps.update({k: v for k, v in entry[section].items() if isinstance(v, str)})
        for dep_name, spec in deps.items():
            child = _resolve(key, dep_name, refs)
            if child:
                result.edges.append(DependencyEdge(parent=parent_ref, child=child, specifier=spec[:200]))


def _resolve(from_key: str, name: str, refs: Mapping[str, str]) -> str | None:
    """Node's lookup: nested node_modules first, then each ancestor, then the top level."""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in refs:
            return refs[candidate]
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def _read_lock_v1(deps: dict, path: str, root_ref: str, add_component, result: NpmResult,
                  declared: Mapping[str, tuple[str, str, int | None]], parent: str | None = None,
                  depth: int = 0) -> None:
    if depth > 64:
        result.warnings.append(f"{path}: dependency tree deeper than 64 levels; truncated")
        return
    for name, entry in sorted(deps.items()):
        if not isinstance(entry, dict):
            continue
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        non_registry = bool(version) and bool(_NON_REGISTRY_RE.match(version))
        scope = "dev" if entry.get("dev") else "optional" if entry.get("optional") else "required"
        direct = parent is None and (not declared or name in declared)
        comp = add_component(name, None if non_registry else version, source_file=path, direct=direct,
                             scope=scope, resolution="locked", integrity=_integrity_hex(entry.get("integrity")),
                             url=_redact(version) if non_registry else None)
        if comp is None:
            continue
        if direct or parent:
            result.edges.append(DependencyEdge(parent=parent or root_ref, child=comp.bom_ref))
        if isinstance(entry.get("dependencies"), dict):
            _read_lock_v1(entry["dependencies"], path, root_ref, add_component, result, declared,
                          parent=comp.bom_ref, depth=depth + 1)
