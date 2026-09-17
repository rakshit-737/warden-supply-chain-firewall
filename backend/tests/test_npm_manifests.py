"""npm manifest parsing: package.json, package-lock.json (v1-v3), graph merge and adversarial input."""

from __future__ import annotations

import base64
import hashlib
import json

from app.sbom.npm import is_npm_manifest, npm_purl, parse_npm
from app.sbom.parsers import parse_project

ROOT = "pkg:generic/project"


def _sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


PACKAGE_JSON = """{
  "name": "web",
  "dependencies": {
    "express": "^4.19.2",
    "@babel/core": "7.24.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"""

LOCK = {
    "name": "web",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "web", "dependencies": {"express": "^4.19.2", "@babel/core": "7.24.0"},
             "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/express": {"version": "4.19.2", "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
                                 "integrity": _sri(b"express"), "dependencies": {"debug": "2.6.9"}},
        "node_modules/debug": {"version": "4.3.4", "integrity": _sri(b"debug-4")},
        "node_modules/express/node_modules/debug": {"version": "2.6.9", "integrity": _sri(b"debug-2")},
        "node_modules/@babel/core": {"version": "7.24.0", "dependencies": {"debug": "^4.1.0"}},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
        "node_modules/evil": {"version": "0.0.1", "resolved": "git+https://user:tok@example.com/evil.git",
                              "optional": True},
    },
}


def _refs(result):
    return {c.bom_ref: c for c in result.components}


def test_manifest_detection():
    assert is_npm_manifest("package.json") == "npm-package"
    assert is_npm_manifest("app/package-lock.json") == "npm-lock"
    assert is_npm_manifest("npm-shrinkwrap.json") == "npm-lock"
    assert is_npm_manifest("node_modules/x/package.json") is None
    assert is_npm_manifest("requirements.txt") is None


def test_purl_encodes_scope():
    assert npm_purl("@babel/core", "7.24.0") == "pkg:npm/%40babel/core@7.24.0"
    assert npm_purl("left-pad", "1.3.0") == "pkg:npm/left-pad@1.3.0"
    assert npm_purl("left-pad", None) is None


def test_lock_v3_versions_hashes_scopes_and_nested_resolution():
    result = parse_npm({"package.json": PACKAGE_JSON, "package-lock.json": json.dumps(LOCK)}, ROOT)
    refs = _refs(result)
    express = refs["pkg:npm/express@4.19.2"]
    assert express.direct and express.resolution == "locked"
    assert express.file_hashes == ["sha512:" + hashlib.sha512(b"express").hexdigest()]
    assert refs["pkg:npm/jest@29.7.0"].direct
    assert result.explicit_scope["pkg:npm/jest@29.7.0"] == "dev"
    assert not refs["pkg:npm/debug@4.3.4"].direct
    edges = {(e.parent, e.child) for e in result.edges}
    # express resolves its own nested debug; @babel/core falls back to the top-level one
    assert ("pkg:npm/express@4.19.2", "pkg:npm/debug@2.6.9") in edges
    assert ("pkg:npm/%40babel/core@7.24.0", "pkg:npm/debug@4.3.4") in edges
    assert (ROOT, "pkg:npm/express@4.19.2") in edges
    assert (ROOT, "pkg:npm/debug@4.3.4") not in edges


def test_git_dependency_has_no_version_and_no_credentials():
    result = parse_npm({"package-lock.json": json.dumps(LOCK)}, ROOT)
    evil = [c for c in result.components if c.name == "evil"]
    assert evil and evil[0].version is None and evil[0].purl is None
    assert "tok" not in json.dumps([c.to_dict() for c in result.components])


def test_package_json_without_lock_is_unresolved_with_lines():
    result = parse_npm({"package.json": PACKAGE_JSON}, ROOT)
    refs = _refs(result)
    assert refs["pkg:npm/%40babel/core@7.24.0"].resolution == "pinned"
    express = next(c for c in result.components if c.name == "express")
    assert express.version is None and express.resolution == "unresolved"
    assert express.declared_at == [{"file": "package.json", "line": 4}]
    assert any("no package-lock.json" in w for w in result.warnings)
    decl = next(d for d in result.declarations if d.name == "jest")
    assert decl.scope == "dev" and decl.line == 8


def test_lock_v1_nested_dependencies():
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "integrity": _sri(b"a"),
              "dependencies": {"b": {"version": "2.0.0", "dev": True}}},
    }}
    result = parse_npm({"package-lock.json": json.dumps(lock)}, ROOT)
    edges = {(e.parent, e.child) for e in result.edges}
    assert (ROOT, "pkg:npm/a@1.0.0") in edges
    assert ("pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0") in edges


def test_parse_project_merges_python_and_npm():
    inv = parse_project({"requirements.txt": "requests==2.32.3\n", "package.json": PACKAGE_JSON,
                         "package-lock.json": json.dumps(LOCK)}, "mixed")
    ecosystems = {c.ecosystem for c in inv.components}
    assert ecosystems == {"pypi", "npm"}
    by_ref = {c.bom_ref: c for c in inv.components}
    assert by_ref["pkg:npm/express@4.19.2"].depth == 1
    assert by_ref["pkg:npm/debug@2.6.9"].depth == 2
    assert by_ref["pkg:npm/jest@29.7.0"].scope == "dev"
    assert {m["type"] for m in inv.manifests} >= {"npm-package", "npm-lock", "requirements"}
    assert not any("not supported manifests" in w for w in inv.warnings)


def test_malformed_and_hostile_input_fails_soft():
    hostile = {
        "package.json": "{not json",
        "a/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/../../etc": {"version": "1.0.0"},
            "node_modules/ok": {"version": "1.0.0", "integrity": "sha512-!!!notbase64"},
            "node_modules/cyc": {"version": "1.0.0", "dependencies": {"cyc": "*"}},
            "node_modules/weird": "not-a-dict",
        }}),
        "b/package-lock.json": b"\xff\xfe\x00garbage",
        "c/package-lock.json": json.dumps([1, 2, 3]),
    }
    result = parse_npm(hostile, ROOT)
    names = {c.name for c in result.components}
    assert "ok" in names and "cyc" in names
    assert not any(".." in n for n in names)
    ok = next(c for c in result.components if c.name == "ok")
    assert ok.file_hashes == []
    assert any("not valid JSON" in w for w in result.warnings)
    inv = parse_project(hostile)
    assert inv.components  # the rest still parses


def test_deep_v1_tree_is_bounded():
    node: dict = {"version": "1.0.0"}
    tree = node
    for _ in range(200):
        child = {"version": "1.0.0"}
        tree["dependencies"] = {"x": child}
        tree = child
    result = parse_npm({"package-lock.json": json.dumps({"lockfileVersion": 1, "dependencies": {"x": node}})}, ROOT)
    assert any("deeper than 64" in w for w in result.warnings)


def test_oversized_manifest_is_skipped(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_MANIFEST_BYTES", 10)
    result = parse_npm({"package.json": PACKAGE_JSON}, ROOT)
    assert result.components == []
    assert any("MAX_MANIFEST_BYTES" in w for w in result.warnings)


def test_npm_components_never_reach_pypi_lookups():
    from app.sbom.resolver import _resolvable

    inv = parse_project({"package.json": PACKAGE_JSON})
    babel = next(c for c in inv.components if c.name == "@babel/core")
    assert babel.resolution == "pinned" and babel.purl
    assert not _resolvable(babel)


def test_unpinned_npm_dependency_is_a_hygiene_finding():
    from app.sbom.hygiene import hygiene_findings

    findings = hygiene_findings(parse_project({"package.json": PACKAGE_JSON}))
    flagged = {f.evidence["package"] for f in findings if f.evidence.get("package")}
    assert {"express", "jest"} <= flagged
    assert "@babel/core" not in flagged


def test_discovery_finds_npm_files_but_not_node_modules(tmp_path):
    from app.sbom.discover import discover_manifests

    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text("{}")
    found = discover_manifests(tmp_path)
    assert list(found) == ["package.json"]
