"""SBOM engine: manifest parsers, project merging, manifest discovery and the optional resolver.

Everything here is offline. Manifests come from the synthetic fixtures in ``tests/data/sbom``
(see its README) or are built inline, and registry HTTP is mocked with respx. Adversarial cases
cover include cycles, forbidden includes, hostile whitespace, huge lines, oversized manifests,
malformed TOML/JSON, credential-bearing URLs, symlinks/junctions and hostile registry metadata.
"""

from __future__ import annotations

import builtins
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx
import pytest
import respx
from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

import app.sbom.parsers.pipfile_lock  # noqa: F401  (imported up front: tests below forbid file access)
import app.sbom.parsers.poetry_lock  # noqa: F401
from app.core.config import settings
from app.core.http import SafeHttpClient
from app.sbom import parse_project
from app.sbom.discover import discover_manifests
from app.sbom.models import Component, DependencyEdge, ProjectInventory, make_bom_ref, make_purl
from app.sbom.parsers import (
    compute_graph_metadata,
    manifest_type,
    propagate_scope,
    redact_url,
    scan_toml_positions,
)
from app.sbom.parsers.pyproject import poetry_constraint_to_pep440
from app.sbom.parsers.requirements import _break_args_options, _strip_comment
from app.sbom.resolver import resolve_transitive

DATA = Path(__file__).parent / "data" / "sbom"


# ------------------------------------------------------------------------------------ helpers
def fixture_files(directory: str, *, rename: dict[str, str] | None = None,
                  only: set[str] | None = None) -> dict[str, bytes]:
    """Load ``<directory>/*.fixture`` as an in-memory manifest mapping (suffix stripped)."""
    out: dict[str, bytes] = {}
    for path in sorted((DATA / directory).glob("*.fixture")):
        name = path.name.removesuffix(".fixture")
        if only is not None and name not in only:
            continue
        out[(rename or {}).get(name, name)] = path.read_bytes()
    return out


def lines_of(content: bytes | str, needle: str) -> list[int]:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return [i for i, line in enumerate(text.splitlines(), start=1) if needle in line]


def line_of(content: bytes | str, needle: str) -> int:
    hits = lines_of(content, needle)
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def comp(inventory: ProjectInventory, ref: str) -> Component:
    found = inventory.component(ref)
    assert found is not None, (ref, [c.bom_ref for c in inventory.components])
    return found


def decl(inventory: ProjectInventory, name: str, file: str | None = None):
    matches = [d for d in inventory.dependencies
               if d.normalized_name == name and (file is None or d.source_file == file)]
    assert len(matches) == 1, (name, matches)
    return matches[0]


def edge_set(inventory: ProjectInventory) -> set[tuple[str, str]]:
    return {(e.parent, e.child) for e in inventory.edges}


def assert_graph_consistent(inventory: ProjectInventory) -> None:
    refs = {c.bom_ref for c in inventory.components}
    assert len(refs) == len(inventory.components), "bom-refs must be unique"
    for e in inventory.edges:
        assert e.parent == inventory.root_ref or e.parent in refs
        assert e.child in refs
    for c in inventory.components:
        assert c.depth is None or c.depth >= 1
        assert set(c.introduced_by) <= refs


# ==================================================================================== requirements
def test_requirements_fixture_components_lines_and_hashes():
    files = fixture_files("requirements")
    inv = parse_project(files, "fixture")
    req = files["requirements.txt"]
    assert_graph_consistent(inv)

    requests = comp(inv, "pkg:pypi/requests@2.31.0")
    assert requests.declared_at == [{"file": "requirements.txt", "line": line_of(req, "requests[socks,security]")}]
    assert (requests.resolution, requests.direct, requests.depth, requests.scope) == ("pinned", True, 1, "required")
    assert requests.purl == "pkg:pypi/requests@2.31.0"
    # Two distribution digests recorded -> no single per-algorithm value is claimed.
    assert requests.file_hashes == ["sha256:" + "ab" * 32, "sha256:" + "cd" * 32]
    assert requests.hashes == {}
    assert decl(inv, "requests").extras == ["security", "socks"]

    flask = comp(inv, "pkg:pypi/flask")
    assert (flask.resolution, flask.version, flask.purl) == ("unresolved", None, None)
    flask_decl = decl(inv, "flask")
    assert flask_decl.line == line_of(req, "flask>=2.0")
    assert flask_decl.markers == 'python_version >= "3.8"'
    assert flask_decl.specifier == "<3,>=2.0"

    certifi = comp(inv, "pkg:pypi/certifi@2024.2.2")
    assert certifi.declared_at == [{"file": "base.txt", "line": line_of(files["base.txt"], "certifi==")}]
    assert certifi.hashes == {"sha256": "ef" * 32}

    assert comp(inv, "pkg:pypi/django").resolution == "unresolved"  # ==4.2.* is not an exact pin
    assert comp(inv, "pkg:pypi/urllib3@1.26.18").resolution == "pinned"  # === arbitrary equality
    assert {m["file"]: m["type"] for m in inv.manifests} == {
        "requirements.txt": "requirements", "base.txt": "requirements", "constraints.txt": "constraints",
    }
    for manifest in inv.manifests:
        assert re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])


def test_requirements_constraints_pin_but_never_add_packages():
    files = fixture_files("requirements")
    inv = parse_project(files, "fixture")
    idna = comp(inv, "pkg:pypi/idna@3.7")
    assert idna.resolution == "pinned" and idna.direct
    assert {"file": "constraints.txt", "line": 2} in idna.declared_at
    assert {"file": "requirements.txt", "line": line_of(files["requirements.txt"], "idna   #")} in idna.declared_at
    assert not any(c.normalized_name == "never-requested-package" for c in inv.components)
    assert not any("not reachable" in w for w in inv.warnings)


def test_requirements_references_are_unresolved_never_fetched_and_redacted():
    files = fixture_files("requirements")
    inv = parse_project(files, "fixture")
    req = files["requirements.txt"]
    thing = decl(inv, "acme-thing")
    assert thing.url == "git+https://[REDACTED]@git.internal.example/acme/thing.git#egg=acme-thing"
    assert thing.line == line_of(req, "-e git+https")
    legacy = decl(inv, "legacy-pkg")  # name recovered from the sdist filename
    assert legacy.url == "https://downloads.example.com/archive/legacy_pkg-1.0.tar.gz"
    wheel = decl(inv, "wheelpkg")  # PEP 508 "name @ url" ending in an archive suffix
    assert wheel.url.endswith("wheelpkg-2.0-py3-none-any.whl") and wheel.line == line_of(req, "wheelpkg @")
    for name in ("acme-thing", "legacy-pkg", "wheelpkg"):
        component = comp(inv, f"pkg:pypi/{name}")
        assert (component.resolution, component.purl, component.version) == ("unresolved", None, None)
    assert sum("never fetched" in w for w in inv.warnings) >= 3
    dumped = json.dumps(inv.to_dict())
    for secret in ("fixture-secret", "fixture-token-123", "deploy-user", "ci-user"):
        assert secret not in dumped


def test_requirements_index_urls_are_recorded_with_lines_and_redacted():
    files = fixture_files("requirements")
    inv = parse_project(files, "fixture")
    req = files["requirements.txt"]
    by_kind = {s["kind"]: s for s in inv.index_sources}
    assert by_kind["index-url"]["line"] == line_of(req, "--index-url")
    assert by_kind["index-url"]["url"] == "https://[REDACTED]@packages.internal.example/simple"
    assert by_kind["index-url"]["host"] == "packages.internal.example"
    assert by_kind["extra-index-url"]["line"] == line_of(req, "--extra-index-url")
    assert inv.index_urls == ["https://[REDACTED]@packages.internal.example/simple"]
    assert inv.extra_index_urls == ["https://pypi.org/simple"]
    assert inv.private_index_hints == ["https://[REDACTED]@packages.internal.example/simple"]


def test_requirements_comment_and_environment_variable_semantics():
    files = fixture_files("requirements")
    inv = parse_project(files, "fixture")
    req = files["requirements.txt"]
    env_line = line_of(req, "${PRIVATE_PKG}")
    assert f"requirements.txt:{env_line}: environment variable references are not expanded" in inv.warnings
    # Like pip, '#' only starts a comment at line start or after whitespace.
    bad_line = line_of(req, "certifi#not-a-comment")
    assert any(w.startswith(f"requirements.txt:{bad_line}: invalid requirement") for w in inv.warnings)
    assert [d.source_file for d in inv.dependencies if d.normalized_name == "certifi"] == ["base.txt"]


def test_line_continuations_crlf_and_comment_lines_keep_real_line_numbers():
    text = (
        "a==1 \\\r\n"
        "  --hash=sha256:" + "1" * 64 + "\r\n"
        "\r\n"
        "# a comment ending in a backslash \\\r\n"
        "b==2\r\n"
        "c==3 \\\n"
        "# a comment line terminates the continuation\n"
        "d==4\n"
    )
    inv = parse_project({"requirements.txt": text}, "p")
    lines = {d.normalized_name: d.line for d in inv.dependencies}
    assert lines == {"a": 1, "b": 5, "c": 6, "d": 8}
    assert decl(inv, "a").hashes == ["sha256:" + "1" * 64]


@hypothesis_settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab#= \t  x\\")), max_size=40))
def test_linear_comment_stripping_matches_pips_regex(line):
    assert _strip_comment(line) == re.sub(r"(^|\s+)#.*$", "", line)


def _pip_break_args_options(line: str) -> tuple[str, str]:
    """Reference copy of pip's ``req_file.break_args_options`` (quadratic; used only for comparison)."""
    tokens = line.split(" ")
    args = []
    options = tokens[:]
    for token in tokens:
        if token.startswith("-") or token.startswith("--"):
            break
        args.append(token)
        options.pop(0)
    return " ".join(args), " ".join(options)


@hypothesis_settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.sampled_from(list("ab=-  \t#\\")), max_size=40))
def test_linear_args_options_split_matches_pip(line):
    assert _break_args_options(line) == _pip_break_args_options(line)


def test_requirement_line_handling_is_linear_on_hostile_whitespace():
    # With pip's comment regex (~8s/line) or its pop(0) option split (~2s/line) twenty such lines
    # take 40s to minutes; the linear implementation needs well under a second. The bound is loose
    # so that a busy CI machine cannot make it flaky.
    hostile_line = "pkg==1.0" + " " * 32_000 + "tail"
    text = "\n".join([hostile_line] * 20 + ["ok==1.0"])
    started = time.perf_counter()
    inv = parse_project({"requirements.txt": text}, "p")
    assert time.perf_counter() - started < 10.0
    assert comp(inv, "pkg:pypi/ok@1.0").declared_at == [{"file": "requirements.txt", "line": 21}]


def test_huge_lines_and_continuations_are_skipped_with_warnings():
    huge = "x" * 100_000
    continued = "\n".join(["segment" * 20 + " \\"] * 2_000)
    text = f"{huge}\nfirst==1.0\n{continued}\nlast==2.0\n"
    inv = parse_project({"requirements.txt": text}, "p")
    assert decl(inv, "first").line == 2
    assert sum("line longer than" in w for w in inv.warnings) >= 2
    assert all(len(w) <= 300 for w in inv.warnings)


def test_oversized_manifest_is_reported_not_truncated(monkeypatch):
    monkeypatch.setattr(settings, "MAX_MANIFEST_BYTES", 1024)
    inv = parse_project({"requirements.txt": "requests==2.31.0\n" + "#" * 2048}, "p")
    assert inv.components == []
    assert inv.manifests == [
        {"file": "requirements.txt", "type": "requirements", "sha256": None, "status": "too_large"},
    ]
    assert any("MAX_MANIFEST_BYTES" in w for w in inv.warnings)


def test_component_count_is_bounded(monkeypatch):
    monkeypatch.setattr(settings, "MAX_PROJECT_COMPONENTS", 50)
    text = "\n".join(f"package-{i}=={i}.0" for i in range(400))
    inv = parse_project({"requirements.txt": text}, "p")
    assert len(inv.components) <= 50
    assert any("more than 50 requirements" in w for w in inv.warnings)
    assert_graph_consistent(inv)


def test_include_cycles_and_forbidden_includes_never_touch_the_filesystem(monkeypatch):
    files = fixture_files("adversarial", rename={"cycle-a.txt": "requirements.txt"},
                          only={"cycle-a.txt", "cycle-b.txt", "cycle-c.txt"})

    def forbidden(*_args, **_kwargs):
        raise AssertionError("manifest parsing must not access the filesystem")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    inv = parse_project(files, "cycle")
    monkeypatch.undo()

    assert sorted(c.bom_ref for c in inv.components) == ["pkg:pypi/alpha@1.0", "pkg:pypi/beta@1.0",
                                                         "pkg:pypi/gamma@1.0"]
    warnings = "\n".join(inv.warnings)
    assert "include cycle detected: requirements.txt -> cycle-b.txt -> cycle-c.txt -> requirements.txt" in warnings
    assert "include cycle detected: requirements.txt -> cycle-b.txt -> cycle-b.txt" in warnings
    assert "included file missing.txt was not provided" in warnings
    assert "remote include https://evil.example/remote-requirements.txt not fetched" in warnings
    assert "included file ../../../../etc/passwd was not provided" in warnings


def test_includes_resolve_relative_to_the_including_file():
    files = {
        "svc/requirements.txt": "-r ../common/base.txt\nlocal==1.0\n",
        "common/base.txt": "shared==2.0\n",
    }
    inv = parse_project(files, "p")
    assert comp(inv, "pkg:pypi/shared@2.0").declared_at == [{"file": "common/base.txt", "line": 1}]
    # Like pip (options are tokenised with POSIX shlex), unquoted backslashes are escapes, so this
    # include names "svc/..commonbase.txt", which was not provided.
    files["svc/requirements.txt"] = "-r ..\\common\\base.txt\n"
    inv = parse_project(files, "p")
    assert inv.component("pkg:pypi/shared@2.0") is None
    assert any("svc/..commonbase.txt was not provided" in w for w in inv.warnings)


def test_utf16_requirements_from_windows_powershell_are_decoded():
    content = "requests==2.31.0\r\nflask==3.0.0\r\n".encode("utf-16")
    inv = parse_project({"requirements.txt": content}, "p")
    assert {c.bom_ref: c.declared_at[0]["line"] for c in inv.components} == {
        "pkg:pypi/flask@3.0.0": 2, "pkg:pypi/requests@2.31.0": 1,
    }


def test_unusual_line_separators_are_warned_about():
    inv = parse_project({"requirements.txt": "visible==1.0\x0chidden==2.0\n"}, "p")
    assert {c.normalized_name for c in inv.components} == {"visible", "hidden"}
    assert any("unusual line separators" in w for w in inv.warnings)


def test_duplicate_and_conflicting_declarations_are_warned_and_kept_honest():
    files = {"requirements.txt": (DATA / "adversarial" / "duplicates.txt.fixture").read_bytes()}
    inv = parse_project(files, "p")
    refs = sorted(c.bom_ref for c in inv.components)
    assert refs == ["pkg:pypi/python-dateutil@2.9.0", "pkg:pypi/requests@2.30.0", "pkg:pypi/requests@2.31.0"]
    assert "requirements.txt: 'requests' is declared 3 times (lines 2, 3, 4)" in inv.warnings
    assert any(w.startswith("'requests' is pinned to conflicting versions: 2.30.0") for w in inv.warnings)
    assert len(comp(inv, "pkg:pypi/python-dateutil@2.9.0").declared_at) == 2


def test_weird_and_invalid_environment_markers():
    files = {"requirements.txt": (DATA / "adversarial" / "weird-markers.txt.fixture").read_bytes()}
    inv = parse_project(files, "p")
    assert decl(inv, "pkg-one").markers == \
        'python_version > "3.6" and (sys_platform == "linux" or sys_platform == "win32")'
    assert decl(inv, "pkg-four").extras == ["extra1", "extra2"]
    assert {c.normalized_name for c in inv.components} == {"pkg-one", "pkg-two", "pkg-three", "pkg-four"}
    invalid = [w for w in inv.warnings if "invalid requirement" in w]
    assert len(invalid) == 4
    # The bidi override in a package name is escaped, never emitted raw.
    assert any("\\u202e" in w for w in invalid)
    assert not any("‮" in w for w in inv.warnings)


# ==================================================================================== pyproject
def test_pep621_optional_dependencies_and_dependency_groups():
    files = fixture_files("pep621")
    text = files["pyproject.toml"]
    inv = parse_project(files, "fixture")
    assert inv.project_version == "1.4.0"
    rich = decl(inv, "rich")
    assert rich.line == line_of(text, "rich[jupyter]")  # escaped quotes inside the string
    assert rich.markers == 'python_version >= "3.10"' and rich.extras == ["jupyter"]
    socks = decl(inv, "pysocks")
    assert (socks.scope, socks.group, socks.line) == ("optional", "socks", line_of(text, "socks = ["))
    assert (decl(inv, "mkdocs").scope, decl(inv, "mkdocs").group) == ("optional", "docs")
    pytest_decl = decl(inv, "pytest")
    assert (pytest_decl.scope, pytest_decl.group, pytest_decl.line) == ("dev", "test", line_of(text, "test = ["))
    assert comp(inv, "pkg:pypi/ruff@0.4.0").scope == "dev"
    assert comp(inv, "pkg:pypi/pydantic@2.7.0").resolution == "pinned"
    assert "pyproject.toml: dependency-group include cycle: lint -> test -> lint" in inv.warnings
    assert "pyproject.toml: dependency group 'typing' includes unknown group 'missing-group'" in inv.warnings


def test_dynamic_pep621_dependencies_are_not_guessed():
    text = '[project]\nname = "x"\ndynamic = ["dependencies"]\n'
    inv = parse_project({"pyproject.toml": text}, "p")
    assert inv.components == []
    assert any("dynamic" in w and "never runs" in w for w in inv.warnings)


def test_poetry_project_with_lock_file():
    files = fixture_files("poetry")
    pyproject, lock = files["pyproject.toml"], files["poetry.lock"]
    inv = parse_project(files, "fixture")
    assert_graph_consistent(inv)
    assert inv.project_version == "0.3.0"
    assert not any(c.normalized_name == "python" for c in inv.components)

    assert decl(inv, "httpx", "pyproject.toml").specifier == ">=0.27,<0.28.0"
    assert decl(inv, "anyio", "pyproject.toml").specifier == ">=4.3,<4.4.0"
    click = decl(inv, "click", "pyproject.toml")
    assert (click.specifier, click.pinned_version) == ("==8.1.7", "8.1.7")
    assert decl(inv, "legacy", "pyproject.toml").specifier == ">=1.0 || <0.5"
    assert any("'legacy' has no exact PEP 440 equivalent" in w for w in inv.warnings)
    tomli = decl(inv, "tomli", "pyproject.toml")
    assert tomli.line == line_of(pyproject, "[tool.poetry.dependencies.tomli]")
    assert tomli.markers == 'python_version < "3.11"'
    private = decl(inv, "private-lib", "pyproject.toml")
    assert private.index_url == "https://packages.internal.example/simple/"
    pysocks = decl(inv, "pysocks", "pyproject.toml")
    assert (pysocks.scope, pysocks.group) == ("optional", "socks")
    assert decl(inv, "pytest", "pyproject.toml").scope == "dev"

    httpx_c = comp(inv, "pkg:pypi/httpx@0.27.0")
    assert (httpx_c.resolution, httpx_c.direct, httpx_c.depth, httpx_c.dependencies_known) == ("locked", True, 1, True)
    assert httpx_c.file_hashes == ["sha256:" + "12" * 32, "sha256:" + "34" * 32]
    assert {"file": "poetry.lock", "line": line_of(lock, 'name = "httpx"')} in httpx_c.declared_at
    assert {"file": "pyproject.toml", "line": line_of(pyproject, 'httpx = "^0.27"')} in httpx_c.declared_at

    acme = comp(inv, "pkg:pypi/acme-git@1.0.0")
    assert acme.purl is None  # locked from git: not a registry artifact

    certifi = comp(inv, "pkg:pypi/certifi@2024.2.2")
    assert (certifi.direct, certifi.depth, certifi.introduced_by) == (False, 2, ["pkg:pypi/httpx@0.27.0"])
    idna = comp(inv, "pkg:pypi/idna@3.7")
    assert idna.introduced_by == ["pkg:pypi/anyio@4.3.0", "pkg:pypi/httpx@0.27.0"]
    assert comp(inv, "pkg:pypi/pluggy@1.5.0").scope == "dev"
    assert comp(inv, "pkg:pypi/pysocks@1.7.1").scope == "optional"
    assert ("pkg:pypi/sniffio@1.3.1", "pkg:pypi/anyio@4.3.0") in edge_set(inv)  # the fixture's cycle
    assert ("pkg:pypi/pytest@8.2.0", "pkg:pypi/pluggy@1.5.0") in edge_set(inv)
    assert not any(e.child.startswith("pkg:pypi/colorama") for e in inv.edges)  # not in the lock -> no edge

    lock_private = next(d for d in inv.dependencies if d.kind == "lock" and d.normalized_name == "private-lib")
    assert lock_private.index_url == "https://packages.internal.example/simple"
    assert "https://packages.internal.example/simple" in inv.private_index_hints


@pytest.mark.parametrize(
    ("constraint", "expected"),
    [
        ("^1.2.3", ">=1.2.3,<2.0.0"),
        ("^0.2.3", ">=0.2.3,<0.3.0"),
        ("^0.0.3", ">=0.0.3,<0.0.4"),
        ("^0.0", ">=0.0,<0.1.0"),
        ("^0", ">=0,<1.0.0"),
        ("~1.2.3", ">=1.2.3,<1.3.0"),
        ("~1.2", ">=1.2,<1.3.0"),
        ("~1", ">=1,<2.0.0"),
        ("1.2.3", "==1.2.3"),
        ("1.2.*", "==1.2.*"),
        ("=1.5", "==1.5"),
        ("~=1.4", "~=1.4"),
        ("*", ""),
        (">=1.0,<2.0", ">=1.0,<2.0"),
        (">= 1.0 < 2.0", ">=1.0,<2.0"),
    ],
)
def test_poetry_constraints_convert_to_pep440(constraint, expected):
    assert poetry_constraint_to_pep440(constraint) == (expected, True)


@pytest.mark.parametrize("constraint", ["^1.0 || ^2.0", "^not-a-version", "latest", ">=1.0 <<2"])
def test_unconvertible_poetry_constraints_are_kept_verbatim(constraint):
    assert poetry_constraint_to_pep440(constraint) == (constraint, False)


def test_poetry_legacy_lock_without_pyproject():
    files = fixture_files("poetry-legacy")
    lock = files["poetry.lock"]
    inv = parse_project(files, "legacy")
    assert comp(inv, "pkg:pypi/requests@2.31.0").hashes == {"sha256": "a1" * 32}
    black = comp(inv, "pkg:pypi/black@24.3.0")
    assert (black.direct, black.scope, black.file_hashes) == (True, "dev", [])
    urllib3 = comp(inv, "pkg:pypi/urllib3@2.2.1")
    assert (urllib3.direct, urllib3.depth, urllib3.introduced_by) == (False, 2, ["pkg:pypi/requests@2.31.0"])
    assert any("lock graph roots treated as direct" in w for w in inv.warnings)
    black_line = line_of(lock, 'name = "black"')
    assert f"poetry.lock:{black_line}: 1 file hash entry ignored (malformed)" in inv.warnings


def test_parse_project_output_is_deterministic_regardless_of_input_order():
    files = {**fixture_files("poetry"), **fixture_files("requirements")}
    forward = parse_project(files, "det").to_dict()
    backward = parse_project(dict(reversed(list(files.items()))), "det").to_dict()
    assert json.dumps(forward, sort_keys=True) == json.dumps(backward, sort_keys=True)


# ==================================================================================== pipenv
def test_pipfile_with_lock_file():
    files = fixture_files("pipenv")
    lock = files["Pipfile.lock"]
    inv = parse_project(files, "pipenv")
    requests = comp(inv, "pkg:pypi/requests@2.31.0")
    assert (requests.resolution, requests.direct, requests.scope) == ("locked", True, "required")
    assert [d for d in requests.declared_at if d["file"] == "Pipfile.lock"] == [
        {"file": "Pipfile.lock", "line": line} for line in lines_of(lock, '"requests": {')
    ]
    assert requests.file_hashes == ["sha256:" + "a5" * 32, "sha256:" + "f4" * 32]
    assert comp(inv, "pkg:pypi/pytest@8.2.0").scope == "dev"
    assert decl(inv, "private-lib", "Pipfile").index_url == "https://[REDACTED]@packages.internal.example/simple"
    assert decl(inv, "flask", "Pipfile").extras == ["async"]
    assert comp(inv, "pkg:pypi/urllib3@2.2.1").file_hashes == []
    assert any("2 malformed hash entr(ies) ignored for 'urllib3'" in w for w in inv.warnings)
    # Pipfile.lock records no relationships: transitive packages have unknown parents.
    assert comp(inv, "pkg:pypi/certifi@2024.2.2").depth is None
    assert "2 component(s) are not reachable from any declared dependency" in inv.warnings
    assert "https://[REDACTED]@packages.internal.example/simple" in inv.private_index_hints
    assert "fixture-pass" not in json.dumps(inv.to_dict())


def test_pipfile_lock_alone_treats_every_locked_package_as_direct():
    inv = parse_project(fixture_files("pipenv", only={"Pipfile.lock"}), "pipenv")
    assert all(c.direct and c.depth == 1 for c in inv.components)
    assert comp(inv, "pkg:pypi/pytest@8.2.0").scope == "dev"
    assert comp(inv, "pkg:pypi/requests@2.31.0").scope == "required"  # default wins over develop
    assert any("no dependency relationships" in w for w in inv.warnings)


# ==================================================================================== robustness
def test_hostile_and_malformed_lock_and_manifest_files_become_warnings():
    adversarial = DATA / "adversarial"
    files = {
        "poetry.lock": (adversarial / "hostile-poetry.lock.fixture").read_bytes(),
        "pyproject.toml": (adversarial / "malformed-pyproject.toml.fixture").read_bytes(),
        "Pipfile.lock": (adversarial / "malformed-Pipfile.lock.fixture").read_bytes(),
    }
    inv = parse_project(files, "hostile")
    status = {m["file"]: m["status"] for m in inv.manifests}
    assert status == {"poetry.lock": "parsed", "pyproject.toml": "error", "Pipfile.lock": "error"}
    assert "pyproject.toml: invalid TOML (TOMLDecodeError); not parsed" in inv.warnings
    assert "Pipfile.lock: invalid JSON (JSONDecodeError); not parsed" in inv.warnings
    assert not any("passwd" in c.name for c in inv.components)
    weird = comp(inv, "pkg:pypi/weird-version")
    assert weird.version is None and weird.resolution == "unresolved" and not weird.dependencies_known
    lock_text = files["poetry.lock"]
    assert weird.declared_at == [{"file": "poetry.lock", "line": line_of(lock_text, 'name = "weird-version"')}]
    assert comp(inv, "pkg:pypi/ok-package@1.0.0").file_hashes == []
    assert comp(inv, "pkg:pypi/git-sourced@0.1.0").purl is None
    dumped = json.dumps(inv.to_dict())
    assert "fixture-token" not in dumped and "private_token=fixture" not in dumped


def test_credential_like_values_never_enter_the_inventory():
    token = "ghp_" + "Q1w2E3r4T5" * 4
    files = {
        "requirements.txt": (
            f"{token}==1.0\n"
            f"pkg-a[{token}]==1.0\n"
            f"pkg-b==={token}\n"
            f'pkg-c==1.0; platform_version == "{token}"\n'
            "pkg-ok==1.0\n"
        ),
        "svc/pyproject.toml": f'[tool.poetry.dependencies]\n{token} = "^1.0"\n'
                              f'fine = {{version = "1.0", extras = ["{token}"]}}\n',
        "pipenv/Pipfile": f'[packages]\n{token} = "*"\n',
        "lock/poetry.lock": f'[[package]]\nname = "{token}"\nversion = "1.0"\n',
        "evil\x1b[2J/requirements.txt": "hidden==1.0\n",
    }
    inv = parse_project(files, "p")
    # Names are normalised (lower-case, "_" -> "-") on the way in, so compare the secret body.
    assert token[4:].lower() not in json.dumps(inv.to_dict()).lower()
    names = {c.normalized_name for c in inv.components}
    assert names == {"pkg-b", "pkg-ok", "fine"}
    assert comp(inv, "pkg:pypi/pkg-b").resolution == "unresolved"  # the credential-like pin is not a version
    assert decl(inv, "fine").extras == []
    assert sum("credential-like" in w for w in inv.warnings) >= 3
    assert any("contains control characters" in w for w in inv.warnings)


@pytest.mark.parametrize(
    "files",
    [
        None,
        [],
        {"requirements.txt": 12345},
        {123: "requests==1.0"},
        {"pyproject.toml": b"\xff\xfe\x00\x00garbage"},
        {"Pipfile.lock": "[]"},
        {"Pipfile.lock": '{"default": []}'},
        {"poetry.lock": "package = 5"},
        {"poetry.lock": "[[package]]\nname = 1\n"},
        {"pyproject.toml": "project = 3\n[tool]\npoetry = 'x'\n"},
        {"pyproject.toml": "[project]\ndependencies = 'requests'\noptional-dependencies = []\n"},
        {"pyproject.toml": "a = " + "[" * 5000 + "]" * 5000},
        {"Pipfile.lock": "[" * 100_000},
        {"requirements.txt": "-r\n--hash\n-e\n--index-url\n'unbalanced\n"},
        {".": "x", "": "y", "../requirements.txt": "escape==1.0"},
    ],
)
def test_parse_project_never_raises_on_garbage(files):
    inv = parse_project(files, "garbage")  # type: ignore[arg-type]
    assert isinstance(inv, ProjectInventory)
    assert_graph_consistent(inv)


_REQUIREMENT_FRAGMENTS = [
    "requests", "Flask", "==", ">=", "~=", "1.0", "2.*", " ", "\t", "\\", "\n", "\r\n", "#", "-r ", "-c ",
    "requirements.txt", "base.txt", "--hash=sha256:" + "a" * 64, ";", " python_version", '"3"', "[", "]", ",",
    "@", "https://x.example/p-1.0.tar.gz", "-e ", "${X}", "--extra-index-url https://u:p@h.example/s", "\x0c",
]


@hypothesis_settings(max_examples=75, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    requirements=st.lists(st.sampled_from(_REQUIREMENT_FRAGMENTS), max_size=60).map("".join),
    base=st.lists(st.sampled_from(_REQUIREMENT_FRAGMENTS), max_size=30).map("".join),
    other=st.dictionaries(
        st.sampled_from(["pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "sub/requirements-dev.txt"]),
        st.one_of(st.text(max_size=300), st.binary(max_size=300)),
        max_size=3,
    ),
)
def test_parse_project_never_raises_property(requirements, base, other):
    inv = parse_project({"requirements.txt": requirements, "base.txt": base, **other}, "fuzz")
    assert_graph_consistent(inv)
    assert all(len(w) <= 300 for w in inv.warnings)
    assert "u:p@" not in json.dumps(inv.to_dict())


# ==================================================================================== helpers
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("requirements.txt", "requirements"),
        ("svc/requirements-dev.txt", "requirements"),
        ("requirements/base.txt", "requirements"),
        ("requirements.in", "requirements"),
        ("constraints.txt", "constraints"),
        ("a\\b\\Pipfile.lock", "pipfile-lock"),
        ("Pipfile", "pipfile"),
        ("PYPROJECT.TOML", "pyproject"),
        ("poetry.lock", "poetry-lock"),
        ("setup.py", None),
        ("requirements.txt.bak", None),
        ("notes.txt", None),
    ],
)
def test_manifest_type(path, expected):
    assert manifest_type(path) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://user:pass@host.example/simple?token=abc#frag", "https://[REDACTED]@host.example/simple?[REDACTED]#frag"),
        ("https://TOKEN123@host.example/simple", "https://[REDACTED]@host.example/simple"),
        ("git+ssh://git@github.com/org/repo.git", "git+ssh://git@github.com/org/repo.git"),
        ("https://[::1]:8443/simple", "https://[::1]:8443/simple"),
        ("git+https://u:secret@host.example:org/repo.git", "git+https://[REDACTED]@host.example:org/repo.git"),
        ("./wheels", "./wheels"),
    ],
)
def test_redact_url(url, expected):
    assert redact_url(url) == expected


def test_toml_positions_cover_escapes_headers_inline_tables_and_array_tables():
    text = (
        '[tool.poetry.dependencies]\n'            # 1
        'a = "1"\n'                               # 2
        '"quoted.key" = { version = "2",\n'       # 3
        '  extras = ["x"] }\n'                    # 4
        '[tool.poetry.dependencies.b]\n'          # 5
        'version = "3"\n'                         # 6
        '[project]\n'                             # 7
        'dependencies = [\n'                      # 8
        '  "c ; python_version < \\"3.9\\"",\n'   # 9
        '  """multi\nline""",\n'                  # 10-11
        '  "d",\n'                                # 12
        ']\n'                                     # 13
        '[[package]]\n'                           # 14
        'name = "p0"\n'                           # 15
        '[[package]]\n'                           # 16
        'name = "p1"\n'                           # 17
    )
    pos = scan_toml_positions(text)
    assert pos.line_of("tool", "poetry", "dependencies", "a") == 2
    assert pos.line_of("tool", "poetry", "dependencies", "quoted.key") == 3
    assert pos.line_of("tool", "poetry", "dependencies", "quoted.key", "extras") == 4
    assert pos.line_of("tool", "poetry", "dependencies", "b") == 5
    assert pos.item_lines(("project", "dependencies"), ['c ; python_version < "3.9"', "multi\nline", "d"]) == \
        [9, None, 12]
    assert pos.line_of("package", "[1]", "name") == 17
    # Positions are verified against the parsed values: a mismatch yields "unknown", never a guess.
    assert pos.item_lines(("project", "dependencies"), ["other", "multi\nline", "d"]) == [None, None, 12]
    assert pos.item_lines(("project", "dependencies"), ["d"]) == [None]


def test_compute_graph_metadata_handles_cycles_unreachable_and_shared_parents():
    def c(name: str, direct: bool) -> Component:
        return Component(bom_ref=make_bom_ref(name, "1.0"), name=name, normalized_name=name, version="1.0",
                         purl=make_purl(name, "1.0"), direct=direct)

    root = "warden:project/g"
    comps = [c("a", True), c("e", True), c("b", False), c("c", False), c("f", False), c("g", False),
             c("d", False), c("x", False)]
    ref = {x.name: x.bom_ref for x in comps}
    edges = [
        DependencyEdge(root, ref["a"]), DependencyEdge(root, ref["e"]),
        DependencyEdge(ref["a"], ref["b"]), DependencyEdge(ref["b"], ref["c"]), DependencyEdge(ref["c"], ref["b"]),
        DependencyEdge(ref["e"], ref["c"]), DependencyEdge(ref["a"], ref["e"]),
        DependencyEdge(ref["a"], ref["f"]), DependencyEdge(ref["f"], ref["g"]),
        DependencyEdge(ref["d"], ref["x"]),  # disconnected island
        DependencyEdge(ref["a"], "pkg:pypi/missing@1.0"),  # dangling edge is ignored
    ]
    inv = ProjectInventory(project_name="g", root_ref=root, components=comps, edges=edges)
    compute_graph_metadata(inv)
    got = {x.name: (x.depth, x.introduced_by) for x in inv.components}
    assert got == {
        "a": (1, []), "e": (1, []),  # e is also reachable from a, but direct components list no introducers
        "b": (2, sorted([ref["a"], ref["e"]])),  # a -> b and e -> c -> b (inside the b/c cycle)
        "c": (2, sorted([ref["a"], ref["e"]])),
        "f": (2, [ref["a"]]), "g": (3, [ref["a"]]),
        "d": (None, []), "x": (None, []),
    }


# ==================================================================================== discovery
def _write(root: Path, rel: str, content: str = "pkg==1.0\n") -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode("utf-8"))  # write_text would turn "\n" into "\r\n" on Windows


def test_discover_returns_known_manifests_only_and_skips_tool_directories(tmp_path):
    for rel in [
        "requirements.txt", "pyproject.toml", "README.md", "src/app.py", "services/api/requirements-dev.txt",
        "requirements/base.txt", ".venv/requirements.txt", "venv/Pipfile", "node_modules/pkg/requirements.txt",
        "build/requirements.txt", "dist/poetry.lock", ".git/requirements.txt", "__pycache__/requirements.txt",
        "a/b/c/d/requirements.txt", "a/b/c/d/e/requirements.txt",
    ]:
        _write(tmp_path, rel)
    found = discover_manifests(tmp_path, max_depth=4)
    assert sorted(found) == [
        "a/b/c/d/requirements.txt", "pyproject.toml", "requirements.txt", "requirements/base.txt",
        "services/api/requirements-dev.txt",
    ]
    assert found["requirements.txt"] == b"pkg==1.0\n"
    assert sorted(discover_manifests(tmp_path, max_depth=0)) == ["pyproject.toml", "requirements.txt"]


def test_discover_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    _write(outside, "requirements.txt", "secret-internal-package==1.0\n")
    root = tmp_path / "repo"
    _write(root, "requirements.txt")
    try:
        os.symlink(outside, root / "linked-dir", target_is_directory=True)
        os.symlink(outside / "requirements.txt", root / "sub-requirements.txt")
    except (OSError, NotImplementedError) as exc:  # Windows without symlink privilege
        pytest.skip(f"symlinks unavailable: {exc}")
    assert sorted(discover_manifests(root)) == ["requirements.txt"]


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are a Windows feature")
def test_discover_does_not_follow_windows_junctions(tmp_path):
    import _winapi  # type: ignore[import-not-found]

    outside = tmp_path / "outside"
    _write(outside, "requirements.txt", "secret-internal-package==1.0\n")
    root = tmp_path / "repo"
    _write(root, "requirements.txt")
    _winapi.CreateJunction(str(outside), str(root / "junction"))
    assert (root / "junction" / "requirements.txt").exists()  # the junction really points outside
    assert sorted(discover_manifests(root)) == ["requirements.txt"]


def test_discover_bounds_file_size_and_count(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "MAX_MANIFEST_BYTES", 100)
    _write(tmp_path, "requirements.txt", "a" * 500)
    for i in range(5):
        _write(tmp_path, f"svc{i}/requirements.txt")
    notes: list[str] = []
    limited = discover_manifests(tmp_path, max_files=3, warnings=notes)
    assert len(limited) == 3 and "stopped after 3 manifest files" in notes
    found = discover_manifests(tmp_path)
    assert len(found["requirements.txt"]) == 101  # read stops just past the cap
    inv = parse_project(found, "p")
    assert {"file": "requirements.txt", "type": "requirements", "sha256": None, "status": "too_large"} in inv.manifests


def test_discover_rejects_missing_root(tmp_path):
    notes: list[str] = []
    assert discover_manifests(tmp_path / "nope", warnings=notes) == {}
    assert notes == ["discovery root is not a directory"]


# ==================================================================================== resolver
PYPI = "https://pypi.org/pypi"
LINUX_312 = {"sys_platform": "linux", "platform_system": "Linux", "python_version": "3.12",
             "python_full_version": "3.12.4", "implementation_name": "cpython", "os_name": "posix"}


def _client() -> SafeHttpClient:
    return SafeHttpClient(name="test-resolver", allowed_hosts=["pypi.org"], retries=0, sleep=lambda _s: None)


def _release_json(requires_dist, license_expression=None) -> httpx.Response:
    info = {"requires_dist": requires_dist, "license_expression": license_expression}
    return httpx.Response(200, json={"info": info})


def _project_json(releases: dict) -> httpx.Response:
    return httpx.Response(200, json={"info": {}, "releases": releases})


def test_resolver_is_disabled_by_default_and_makes_no_requests():
    inv = parse_project({"requirements.txt": "requests==2.31.0\n"}, "p")
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(500))
        report = resolve_transitive(inv)
    assert report.status == "disabled" and not catch_all.called
    assert inv.edges == [DependencyEdge(inv.root_ref, "pkg:pypi/requests@2.31.0", "==2.31.0")]


def test_resolver_fills_transitive_edges_with_markers_extras_and_version_selection():
    # Registry responses below are test fixtures, not real PyPI data.
    inv = parse_project({"requirements.txt": "requests[socks]==2.31.0\nclick==8.1.7\n"}, "p")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/requests/2.31.0/json").mock(return_value=_release_json([
            "charset-normalizer<4,>=2", "idna<4,>=2.5", "urllib3<3,>=1.21.1", "certifi>=2017.4.17",
            'PySocks!=1.5.7,>=1.5.6; extra == "socks"', 'chardet<6,>=3.0.2; extra == "use-chardet-on-py3"',
            'win-only>=1; sys_platform == "win32"',
        ], license_expression="Apache-2.0"))
        router.get(f"{PYPI}/click/8.1.7/json").mock(
            return_value=_release_json(['colorama; platform_system == "Windows"']))
        router.get(f"{PYPI}/charset-normalizer/json").mock(return_value=_project_json(
            {"3.3.2": [{}], "4.0.0": [{}], "3.4.0rc1": [{}], "not a version": [{}]}))
        router.get(f"{PYPI}/idna/json").mock(return_value=_project_json(
            {"3.7": [{"yanked": True}], "3.6": [{"yanked": False}]}))
        router.get(f"{PYPI}/urllib3/json").mock(return_value=_project_json(
            {"2.2.1": [{"requires_python": ">=3.13"}], "2.2.0": [{"requires_python": ">=3.8"}]}))
        router.get(f"{PYPI}/certifi/json").mock(return_value=_project_json({"2024.2.2": [{}]}))
        router.get(f"{PYPI}/pysocks/json").mock(return_value=_project_json({"1.7.1": [{}], "1.5.7": [{}]}))
        router.get(f"{PYPI}/charset-normalizer/3.3.2/json").mock(return_value=_release_json(None))
        router.get(f"{PYPI}/idna/3.6/json").mock(return_value=_release_json([]))
        router.get(f"{PYPI}/urllib3/2.2.0/json").mock(return_value=_release_json(['brotli>=1.0.9; extra == "brotli"']))
        router.get(f"{PYPI}/certifi/2024.2.2/json").mock(return_value=_release_json(None))
        router.get(f"{PYPI}/pysocks/1.7.1/json").mock(return_value=_release_json([]))
        report = resolve_transitive(inv, enabled=True, client=_client(), target_environment=LINUX_312)

    assert report.status == "ok", report.warnings
    requests_ref = "pkg:pypi/requests@2.31.0"
    expected_children = {"pkg:pypi/charset-normalizer@3.3.2", "pkg:pypi/idna@3.6", "pkg:pypi/urllib3@2.2.0",
                         "pkg:pypi/certifi@2024.2.2", "pkg:pypi/pysocks@1.7.1"}
    assert {child for parent, child in edge_set(inv) if parent == requests_ref} == expected_children
    assert not any(e.parent == "pkg:pypi/click@8.1.7" for e in inv.edges)  # Windows-only marker
    for ref in expected_children:
        child = comp(inv, ref)
        assert (child.resolution, child.direct, child.depth, child.introduced_by) == \
            ("resolved", False, 2, [requests_ref])
    requests = comp(inv, requests_ref)
    assert requests.dependencies_known and requests.licenses == ["Apache-2.0"]
    assert comp(inv, "pkg:pypi/idna@3.6").dependencies_known  # [] = known to have none
    assert not comp(inv, "pkg:pypi/certifi@2024.2.2").dependencies_known  # null = unknown
    assert report.added_components == 5 and report.fetched_nodes == 7
    requested = {str(call.request.url) for call in router.calls}
    assert not any("chardet" in url or "win-only" in url or "brotli" in url or "colorama" in url for url in requested)
    assert_graph_consistent(inv)


def test_resolver_never_re_resolves_locked_components():
    inv = parse_project(fixture_files("poetry"), "fixture")
    before = edge_set(inv)
    with respx.mock(assert_all_called=False) as router:
        catch_all = router.route().mock(return_value=httpx.Response(500))
        report = resolve_transitive(inv, enabled=True, client=_client())
    assert report.status == "ok" and not catch_all.called
    assert edge_set(inv) == before


def test_resolver_budget_404_and_disallowed_hosts_degrade_to_partial():
    text = "alpha==1.0\nbeta==1.0\n"
    inv = parse_project({"requirements.txt": text}, "p")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/alpha/1.0/json").mock(return_value=httpx.Response(404))
        beta = router.get(f"{PYPI}/beta/1.0/json").mock(return_value=_release_json([]))
        report = resolve_transitive(inv, enabled=True, client=_client(), max_nodes=1)
    assert report.status == "partial" and not beta.called
    assert "resolver node budget (1) reached; resolution is partial" in inv.warnings
    assert "pkg:pypi/alpha@1.0: release metadata not available" in inv.warnings

    inv = parse_project({"requirements.txt": text}, "p")
    with respx.mock(assert_all_called=False) as router:
        evil = router.route(host="evil.example").mock(return_value=_release_json(["x"]))
        report = resolve_transitive(inv, enabled=True, client=_client(), base_url="https://evil.example/pypi")
    assert report.status == "partial" and not evil.called
    assert any("host_not_allowed" in w for w in inv.warnings)

    inv = parse_project({"requirements.txt": text}, "p")
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(return_value=_release_json(["gamma>=1"]))
        report = resolve_transitive(inv, enabled=True, client=_client(), max_requests=2)
    assert report.status == "partial" and report.requests == 2
    assert "resolver request budget (2) reached; resolution is partial" in inv.warnings


def test_resolver_type_checks_hostile_registry_metadata():
    inv = parse_project({"requirements.txt": "alpha==1.0\nbeta==1.0\n"}, "p")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/alpha/1.0/json").mock(return_value=_release_json(
            [123, None, "bad requirement !!!", "x" * 5000, "gamma>=1", "delta @ https://evil.example/d.whl"],
            license_expression="MIT" * 500))
        router.get(f"{PYPI}/beta/1.0/json").mock(return_value=_release_json("no"))
        router.get(f"{PYPI}/gamma/json").mock(
            return_value=httpx.Response(200, json={"releases": ["not", "a", "dict"]}))
        report = resolve_transitive(inv, enabled=True, client=_client())
    assert report.status == "partial"
    alpha = comp(inv, "pkg:pypi/alpha@1.0")
    # Hostile entries and the failed gamma lookup left dependencies without edges: not "known".
    assert alpha.licenses == [] and not alpha.dependencies_known
    assert not comp(inv, "pkg:pypi/beta@1.0").dependencies_known
    assert [c.normalized_name for c in inv.components] == ["alpha", "beta"]
    assert any("direct URL" in w for w in inv.warnings)


def test_resolver_does_not_report_a_failed_child_lookup_as_a_complete_dependency_list():
    """Regression: dependencies_known was set before children resolved, so the CycloneDX BOM listed a
    component whose dependency lookup failed under aggregate 'complete' with an empty dependsOn."""
    from app.sbom.cyclonedx import build as build_cyclonedx

    inv = parse_project({"requirements.txt": "a==1.0\n"}, "p")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{PYPI}/a/1.0/json").mock(return_value=_release_json(["b>=1", 'c>=1; sys_platform == "win32"']))
        router.get(f"{PYPI}/b/json").mock(return_value=httpx.Response(503))
        report = resolve_transitive(inv, enabled=True, client=_client(), target_environment=LINUX_312)
    assert report.status == "partial"
    assert not comp(inv, "pkg:pypi/a@1.0").dependencies_known
    document = build_cyclonedx(inv, timestamp="2026-09-15T00:00:00Z")
    complete = [c for c in document["compositions"] if c["aggregate"] == "complete"]
    assert all("pkg:pypi/a@1.0" not in c["dependencies"] for c in complete)
    assert {"aggregate": "unknown", "dependencies": ["pkg:pypi/a@1.0"]} in document["compositions"]


def test_resolved_scopes_are_propagated_to_a_fixed_point():
    """Regression: single-pass BFS evaluated x before its parent y was widened to 'required', so a runtime
    dependency of a required package ended up 'dev' (CycloneDX scope 'excluded')."""
    def c(name: str) -> Component:
        return Component(bom_ref=make_bom_ref(name, "1.0"), name=name, normalized_name=name, version="1.0",
                         purl=make_purl(name, "1.0"), direct=name in ("a", "b"), resolution="resolved")

    root = "warden:project/scope"
    comps = {name: c(name) for name in ("a", "b", "x", "y")}
    comps["y"].scope = "dev"  # stale scope from creation under the dev parent
    edges = [DependencyEdge(root, comps["a"].bom_ref), DependencyEdge(root, comps["b"].bom_ref),
             DependencyEdge(comps["a"].bom_ref, comps["x"].bom_ref),
             DependencyEdge(comps["a"].bom_ref, comps["y"].bom_ref),
             DependencyEdge(comps["b"].bom_ref, comps["y"].bom_ref),
             DependencyEdge(comps["y"].bom_ref, comps["x"].bom_ref)]
    inv = ProjectInventory(project_name="scope", root_ref=root, components=list(comps.values()), edges=edges)
    order = compute_graph_metadata(inv)
    propagate_scope(inv, {comps["a"].bom_ref: "dev", comps["b"].bom_ref: "required"}, order)
    assert {name: comp.scope for name, comp in comps.items()} == {
        "a": "dev", "b": "required", "y": "required", "x": "required"}


def test_hostile_lock_with_many_versions_of_one_name_yields_linear_edges():
    """Regression: every lock dependency linked to every allowed locked version (N*(N-1) edges)."""
    n = 300
    lock = "".join(f'[[package]]\nname = "a"\nversion = "1.0.{i}"\n\n[package.dependencies]\na = "*"\n\n'
                   for i in range(n))
    started = time.monotonic()
    inv = parse_project({"poetry.lock": lock}, "p")
    assert len(inv.edges) <= 2 * n
    assert time.monotonic() - started < 10
    # Each version links only to the highest other version its specifier allows.
    assert ("pkg:pypi/a@1.0.0", "pkg:pypi/a@1.0.299") in edge_set(inv)
    assert ("pkg:pypi/a@1.0.299", "pkg:pypi/a@1.0.298") in edge_set(inv)


def test_lock_dependency_links_the_highest_satisfying_version_and_never_invents_edges():
    lock = (
        '[[package]]\nname = "app"\nversion = "1.0"\n\n[package.dependencies]\nlib = ">=1,<2"\nother = ">=9"\n\n'
        '[[package]]\nname = "lib"\nversion = "1.2"\n\n'
        '[[package]]\nname = "lib"\nversion = "1.5"\n\n'
        '[[package]]\nname = "lib"\nversion = "2.0"\n\n'
        '[[package]]\nname = "other"\nversion = "1.0"\n\n'
    )
    inv = parse_project({"poetry.lock": lock}, "p")
    children = {child for parent, child in edge_set(inv) if parent == "pkg:pypi/app@1.0"}
    assert children == {"pkg:pypi/lib@1.5"}
    assert any("match no locked version" in w for w in inv.warnings)


def test_component_truncation_clears_dependencies_known_on_parents_that_lose_edges(monkeypatch):
    monkeypatch.setattr(settings, "MAX_PROJECT_COMPONENTS", 3)
    lock = '[[package]]\nname = "aaa"\nversion = "1.0"\n\n[package.dependencies]\nzzz = ">=1"\n\n' \
           '[[package]]\nname = "zzz"\nversion = "1.0"\n\n'
    inv = parse_project({"requirements.txt": "x1==1.0\nx2==1.0\n", "svc/poetry.lock": lock}, "p")
    assert "pkg:pypi/zzz@1.0" not in {c.bom_ref for c in inv.components}
    assert not comp(inv, "pkg:pypi/aaa@1.0").dependencies_known


def test_purl_versions_are_percent_encoded():
    """Regression: '+' and '!' were left raw, producing non-canonical purls and bom-refs."""
    assert make_purl("torch", "2.0.1+cu118") == "pkg:pypi/torch@2.0.1%2Bcu118"
    assert make_purl("Foo_Bar", "1!2.0") == "pkg:pypi/foo-bar@1%212.0"
    assert make_purl("x", "1.0.post1") == "pkg:pypi/x@1.0.post1"
    inv = parse_project({"requirements.txt": "torch==2.0.1+cu118\n"}, "p")
    [torch] = inv.components
    assert torch.purl == torch.bom_ref == "pkg:pypi/torch@2.0.1%2Bcu118" and torch.version == "2.0.1+cu118"


def test_discovery_never_lists_more_than_the_entry_budget(tmp_path, monkeypatch):
    """Regression: a whole directory listing was materialised and sorted before the entry cap applied."""
    from app.sbom import discover

    pulled = {"n": 0}

    class FakeEntry:
        def __init__(self, name: str) -> None:
            self.name, self.path = name, str(tmp_path / name)

        def is_symlink(self) -> bool:
            return False

        def is_dir(self, follow_symlinks: bool = True) -> bool:
            return False

    class FakeScandir:
        def __init__(self, path) -> None:
            pass

        def __enter__(self):
            def entries():
                for i in range(200_000):
                    pulled["n"] += 1
                    yield FakeEntry(f"f{i:07d}.dat")
            return entries()

        def __exit__(self, *exc) -> bool:
            return False

    monkeypatch.setattr(discover, "MAX_SCANNED_ENTRIES", 50)
    monkeypatch.setattr(discover.os, "scandir", FakeScandir)
    notes: list[str] = []
    assert discover.discover_manifests(tmp_path, warnings=notes) == {}
    assert pulled["n"] <= 51
    assert notes == ["stopped after visiting 50 directory entries"]
