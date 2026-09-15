"""``pyproject.toml`` dependency parser: PEP 621, PEP 735 dependency groups and Poetry tables.

Only *static* declarations are read. When ``[project].dynamic`` lists ``dependencies`` the real
dependency set is produced by the build backend at build time; Warden never runs a build
backend, so it records a warning instead of guessing.

Scopes:

* ``[project].dependencies`` and ``[tool.poetry.dependencies]`` -> ``required``
* ``[project.optional-dependencies]`` (and Poetry ``optional = true``) -> ``optional``, ``group`` = extra
* ``[dependency-groups]`` (PEP 735), ``[tool.poetry.dev-dependencies]`` and non-``main`` Poetry groups -> ``dev``

Poetry constraints (``^1.2``, ``~1.2``, bare versions) are converted to PEP 440 where there is an
exact equivalent; anything else (``||`` unions, malformed) is kept verbatim with a warning.
"""

from __future__ import annotations

import re
import tomllib

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app.core.config import settings
from app.sbom.models import ManifestDependency
from app.sbom.parsers import (
    MAX_NAME_LEN,
    PYPROJECT,
    ManifestParseResult,
    bound_specifier,
    clean_version,
    credential_like,
    dependency_from_pep508,
    display,
    index_source,
    load_manifest,
    pinned_version,
    redact_url,
    safe_marker,
    scan_toml_positions,
    valid_project_name,
    warn,
)

_OPERATOR_RE = re.compile(r"^(===|==|!=|<=|>=|~=|<|>)(.+)$")
_SPLIT_RE = re.compile(r"\s*,\s*|\s+(?=[<>=!~^])")
_BARE_VERSION_RE = re.compile(r"^v?\d[\w.+!-]*(?:\.\*)?$")
_REFERENCE_KEYS = ("git", "path", "url", "file")


# ======================================================================================
# Poetry constraint conversion
# ======================================================================================
def _release_bound(version: str, caret: bool) -> str | None:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return None
    if parsed.epoch or parsed.local:
        return None
    release = list(parsed.release)
    precision = len(release)
    major = release[0]
    minor = release[1] if precision > 1 else 0
    patch = release[2] if precision > 2 else 0
    if caret:
        if major != 0 or precision == 1:
            upper = (major + 1, 0, 0)
        elif minor != 0 or precision == 2:
            upper = (0, minor + 1, 0)
        else:
            upper = (0, 0, patch + 1)
    elif precision == 1:
        upper = (major + 1, 0, 0)
    else:
        upper = (major, minor + 1, 0)
    return ".".join(str(p) for p in upper)


def poetry_constraint_to_pep440(constraint: str) -> tuple[str, bool]:
    """Convert a Poetry version constraint to a PEP 440 specifier set.

    Returns ``(specifier, converted)``. ``converted`` is ``False`` when no exact PEP 440
    equivalent exists; the raw constraint is then returned unchanged.
    """
    raw = constraint.strip() if isinstance(constraint, str) else ""
    if raw in ("", "*"):
        return "", True
    if "|" in raw:
        return raw, False
    converted: list[str] = []
    for part in _SPLIT_RE.split(raw):
        part = re.sub(r"\s+", "", part)
        if not part or part == "*":
            continue
        if part.startswith("^") or (part.startswith("~") and not part.startswith("~=")):
            version = part[1:]
            upper = _release_bound(version, caret=part.startswith("^"))
            if upper is None:
                return raw, False
            converted.append(f">={version}")
            converted.append(f"<{upper}")
            continue
        m = _OPERATOR_RE.match(part)
        if m:
            converted.append(part)
        elif part.startswith("=") and not part.startswith("=="):
            converted.append("==" + part[1:])
        elif _BARE_VERSION_RE.match(part):
            converted.append("==" + part)
        else:
            return raw, False
    spec = ",".join(converted)
    try:
        SpecifierSet(spec)
    except InvalidSpecifier:
        return raw, False
    return spec, True


def poetry_dependency_specs(value: object) -> list[dict] | None:
    """Normalise a Poetry dependency value (string, table or list of tables) to a list of tables."""
    if isinstance(value, str):
        return [{"version": value}]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(v, dict) for v in value):
        return list(value)
    return None


# ======================================================================================
# Parser
# ======================================================================================
def parse_pyproject(path: str, content: object) -> ManifestParseResult:
    result = ManifestParseResult(file=path, type=PYPROJECT)
    text, digest, status = load_manifest(path, content, result.warnings)
    result.manifests.append({"file": path, "type": PYPROJECT, "sha256": digest, "status": status})
    if text is None:
        return result
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        warn(result.warnings, f"{display(path)}: invalid TOML ({type(exc).__name__}); not parsed")
        result.manifests[-1]["status"] = "error"
        return result
    positions = scan_toml_positions(text)
    ctx = _Context(path, result, positions)

    project = data.get("project")
    if isinstance(project, dict):
        _pep621(ctx, project)
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        _dependency_groups(ctx, groups)
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        _poetry(ctx, poetry)
    return result


class _Context:
    def __init__(self, path: str, result: ManifestParseResult, positions) -> None:
        self.path = path
        self.result = result
        self.positions = positions
        self.limit = settings.MAX_PROJECT_COMPONENTS
        self.limit_hit = False
        self.source_urls: dict[str, str] = {}  # lower-cased Poetry source name -> redacted URL
        self.extras_of: dict[str, set[str]] = {}  # normalized package name -> [tool.poetry.extras] names

    def where(self, line: int | None) -> str:
        return f"{display(self.path)}{f':{line}' if line else ''}"

    def add(self, dep: ManifestDependency | None) -> None:
        if dep is None:
            return
        if len(self.result.dependencies) >= self.limit:
            if not self.limit_hit:
                warn(self.result.warnings, f"{display(self.path)}: more than {self.limit} dependencies; truncated")
            self.limit_hit = True
            return
        self.result.dependencies.append(dep)


def _pep621(ctx: _Context, project: dict) -> None:
    if isinstance(project.get("name"), str):
        ctx.result.project_name = display(project["name"])
    ctx.result.project_version = clean_version(project.get("version"), ctx.result.warnings, ctx.where(None))
    dynamic = project.get("dynamic")
    if isinstance(dynamic, list):
        for key in ("dependencies", "optional-dependencies"):
            if key in dynamic:
                warn(ctx.result.warnings, f"{display(ctx.path)}: [project].{key} is dynamic (computed by the build "
                     "backend, which Warden never runs); those dependencies are not included")
    deps = project.get("dependencies")
    if deps is not None:
        _string_list(ctx, ("project", "dependencies"), deps, scope="required", group=None)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra in sorted(optional):
            _string_list(ctx, ("project", "optional-dependencies", extra), optional[extra], scope="optional",
                         group=display(extra))
    elif optional is not None:
        warn(ctx.result.warnings, f"{display(ctx.path)}: [project].optional-dependencies must be a table")


def _string_list(ctx: _Context, path: tuple[str, ...], values: object, *, scope: str, group: str | None) -> None:
    if not isinstance(values, list):
        warn(ctx.result.warnings, f"{display(ctx.path)}: {'.'.join(display(p) for p in path)} must be an array")
        return
    lines = ctx.positions.item_lines(path, values)
    for value, line in zip(values, lines):
        if isinstance(value, str):
            ctx.add(dependency_from_pep508(value, source_file=ctx.path, line=line, warnings=ctx.result.warnings,
                                           scope=scope, group=group))
        elif not (isinstance(value, dict) and "include-group" in value):
            warn(ctx.result.warnings, f"{ctx.where(line)}: non-string dependency entry ignored")


def _dependency_groups(ctx: _Context, groups: dict) -> None:
    """PEP 735 groups. ``include-group`` entries are validated (existence, cycles) but not
    expanded: the included group's own entries are already recorded at their real lines."""
    normalized = {canonicalize_name(g): g for g in groups if isinstance(g, str)}
    for group in sorted(g for g in groups if isinstance(g, str)):
        _string_list(ctx, ("dependency-groups", group), groups[group], scope="dev", group=display(group))

    def includes(name: str) -> list[str]:
        entries = groups.get(name)
        out = []
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and isinstance(entry.get("include-group"), str):
                out.append(entry["include-group"])
        return out

    for group in sorted(normalized.values()):
        stack = [(group, [group])]
        seen: set[str] = set()
        while stack:
            current, chain = stack.pop()
            for target in includes(current):
                key = canonicalize_name(target)
                if key not in normalized:
                    warn(ctx.result.warnings, f"{display(ctx.path)}: dependency group '{display(current)}' includes "
                         f"unknown group '{display(target)}'")
                    continue
                if key in {canonicalize_name(c) for c in chain}:
                    warn(ctx.result.warnings, f"{display(ctx.path)}: dependency-group include cycle: "
                         f"{' -> '.join(display(c) for c in [*chain, target])}")
                    continue
                if key not in seen:
                    seen.add(key)
                    stack.append((normalized[key], [*chain, normalized[key]]))


def _poetry(ctx: _Context, poetry: dict) -> None:
    if ctx.result.project_name is None and isinstance(poetry.get("name"), str):
        ctx.result.project_name = display(poetry["name"])
    if ctx.result.project_version is None:
        ctx.result.project_version = clean_version(poetry.get("version"), ctx.result.warnings, ctx.where(None))
    sources = poetry.get("source")
    if isinstance(sources, list):
        for i, source in enumerate(sources):
            if isinstance(source, dict) and isinstance(source.get("url"), str):
                line = ctx.positions.line_of("tool", "poetry", "source", f"[{i}]", "url")
                ctx.result.index_sources.append(index_source(
                    "poetry-source", source["url"], ctx.path, line,
                    name=source.get("name") if isinstance(source.get("name"), str) else None,
                    priority=source.get("priority") if isinstance(source.get("priority"), str) else None,
                ))
                if isinstance(source.get("name"), str):
                    ctx.source_urls.setdefault(source["name"].lower(), redact_url(source["url"]))
    extras = poetry.get("extras")
    if isinstance(extras, dict):
        for extra in sorted(k for k in extras if isinstance(k, str)):
            members = extras[extra] if isinstance(extras[extra], list) else []
            for member in members:
                if isinstance(member, str):
                    ctx.extras_of.setdefault(canonicalize_name(member), set()).add(display(extra))
    tables: list[tuple[tuple[str, ...], object, str, str | None]] = [
        (("tool", "poetry", "dependencies"), poetry.get("dependencies"), "required", None),
        (("tool", "poetry", "dev-dependencies"), poetry.get("dev-dependencies"), "dev", "dev"),
    ]
    groups = poetry.get("group")
    if isinstance(groups, dict):
        for name in sorted(g for g in groups if isinstance(g, str)):
            body = groups[name]
            if isinstance(body, dict):
                scope = "required" if name == "main" else "dev"
                tables.append((("tool", "poetry", "group", name, "dependencies"), body.get("dependencies"), scope,
                               display(name)))
    for path, table, scope, group in tables:
        if table is None:
            continue
        if not isinstance(table, dict):
            warn(ctx.result.warnings, f"{display(ctx.path)}: {'.'.join(display(p) for p in path)} must be a table")
            continue
        for name in table:
            if not isinstance(name, str) or name.lower() == "python":
                continue
            _poetry_entry(ctx, path, name, table[name], scope, group)


def _poetry_entry(ctx: _Context, table_path: tuple[str, ...], name: str, value: object, scope: str,
                  group: str | None) -> None:
    line = ctx.positions.line_of(*table_path, name)
    where = ctx.where(line)
    warnings = ctx.result.warnings
    if not valid_project_name(name) or len(name) > MAX_NAME_LEN:
        warn(warnings, f"{where}: invalid package name {display(name)!s}; skipped")
        return
    specs = poetry_dependency_specs(value)
    if specs is None:
        warn(warnings, f"{where}: unsupported dependency value for '{display(name)}'; skipped")
        return
    for spec in specs:
        entry_scope = "optional" if spec.get("optional") is True and scope == "required" else scope
        entry_group = group
        if entry_scope == "optional" and group is None:
            entry_group = ",".join(sorted(ctx.extras_of.get(canonicalize_name(name), ()))) or None
        extras = sorted(e for e in spec.get("extras", []) if isinstance(e, str) and not credential_like(e)) \
            if isinstance(spec.get("extras"), list) else []
        markers = safe_marker(spec.get("markers"), warnings, where)
        index_url = None
        if isinstance(spec.get("source"), str):
            index_url = ctx.source_urls.get(spec["source"].lower())
            if index_url is None:
                warn(warnings, f"{where}: '{display(name)}' names an undeclared Poetry source "
                     f"{display(spec['source'])!s}")
        reference = next((k for k in _REFERENCE_KEYS if isinstance(spec.get(k), str)), None)
        if reference is not None:
            warn(warnings, f"{where}: '{display(name)}' comes from a {reference} source; recorded as unresolved "
                 "(never fetched)")
            ctx.add(ManifestDependency(
                name=name, normalized_name=canonicalize_name(name), source_file=ctx.path, line=line,
                extras=extras, markers=markers, scope=entry_scope, group=entry_group,
                url=redact_url(spec[reference]),
            ))
            continue
        raw = spec.get("version", "")
        if not isinstance(raw, str):
            warn(warnings, f"{where}: non-string version constraint for '{display(name)}'; treated as unconstrained")
            raw = ""
        specifier, converted = poetry_constraint_to_pep440(raw)
        pinned = None
        if converted:
            pinned = pinned_version(SpecifierSet(specifier)) if specifier else None
            pinned = clean_version(pinned, warnings, where) if pinned else None
        else:
            warn(warnings, f"{where}: Poetry constraint {display(raw)!s} for '{display(name)}' has no exact PEP 440 "
                 "equivalent; kept verbatim")
        ctx.add(ManifestDependency(
            name=name, normalized_name=canonicalize_name(name),
            specifier=bound_specifier(specifier, warnings, where), pinned_version=pinned,
            extras=extras, markers=markers, source_file=ctx.path, line=line, scope=entry_scope, group=entry_group,
            index_url=index_url,
        ))
