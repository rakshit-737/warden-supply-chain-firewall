"""SPDX 2.3 builder: offline validation against the official schema, identifiers, relationships.

The SPDX 2.3 JSON schema in ``tests/data/schemas`` is the unmodified official file (see its README).
Vulnerability, risk and finding inputs are test fixtures with synthetic identifiers.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from app.analysis.findings import Finding, Severity
from app.intel.models import Vulnerability
from app.sbom import build_spdx, parse_project
from app.sbom.models import Component, DependencyEdge, ProjectInventory, make_purl
from app.sbom.spdx import DEFAULT_NAMESPACE_BASE, sanitize_id_part

DATA = Path(__file__).parent / "data"
SBOM = DATA / "sbom"
TIMESTAMP = "2026-09-15T12:00:00Z"
SPDX_ID_RE = re.compile(r"^SPDXRef-[A-Za-z0-9.\-]+$")
TOKEN = "ghp_" + "Z9y8X7w6V5" * 4


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads((DATA / "schemas" / "spdx-2.3.schema.json").read_text(encoding="utf-8"))
    return Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)


def assert_valid(validator: Draft7Validator, document: dict) -> None:
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message[:300]}" for e in errors[:10])


def project_inventory() -> ProjectInventory:
    files: dict[str, bytes] = {}
    for directory, prefix in (("poetry", ""), ("requirements", "legacy-svc/")):
        for path in sorted((SBOM / directory).glob("*.fixture")):
            files[prefix + path.name.removesuffix(".fixture")] = path.read_bytes()
    return parse_project(files, "fixture-project")


def hostile_inventory() -> ProjectInventory:
    comps = [
        Component(bom_ref="pkg:pypi/x@1_0", name="x", normalized_name="x", version="1_0", purl=None),
        Component(bom_ref="pkg:pypi/x@1-0", name="x", normalized_name="x", version="1-0", purl=make_purl("x", "1-0")),
        Component(bom_ref="pkg:pypi/‮evil name/..#@2", name="‮evil \x1b[1mname", normalized_name="evil/../#",
                  version="2 beta", purl=None, licenses=["MIT OR"]),
        # A raw (un-normalised) credential in every identifying field: the builder must redact it.
        Component(bom_ref=f"pkg:pypi/{TOKEN}@3.0", name=TOKEN, normalized_name=TOKEN, version="3.0",
                  purl=f"pkg:pypi/{TOKEN}@3.0", licenses=["Apache-2.0"]),
    ]
    root = "warden:project/hostile"
    edges = [DependencyEdge(root, c.bom_ref) for c in comps[:2]] + [
        DependencyEdge(comps[1].bom_ref, comps[2].bom_ref), DependencyEdge(comps[2].bom_ref, comps[3].bom_ref),
        DependencyEdge(comps[3].bom_ref, "pkg:pypi/ghost@9"), DependencyEdge(comps[0].bom_ref, comps[0].bom_ref),
    ]
    return ProjectInventory(project_name=f"hostile#{TOKEN}/\x00", root_ref=root, components=comps, edges=edges)


def fixture_vulnerabilities() -> dict[str, list]:
    """Synthetic records in the shape produced by app.intel (test fixtures only)."""
    osv = Vulnerability(id="GHSA-fx11-fx11-fx11", severity="high", sources=["osv"],
                        references=["https://example.com/advisories/fx11"])
    nvd_only = {"id": "CVE-2099-20002", "severity": "low", "sources": ["nvd"],
                "references": ["https://example.com/advisories/cve-2099-20002"]}
    no_url = {"id": "WARDEN-FIXTURE-3", "severity": "medium", "sources": []}
    return {"pkg:pypi/httpx@0.27.0": [osv, nvd_only, no_url]}


def full_document(**overrides) -> dict:
    kwargs = dict(
        vulns_by_ref=fixture_vulnerabilities(),
        risk_by_ref={"pkg:pypi/httpx@0.27.0": {"final_score": 81, "decision": "block"}},
        findings_by_ref={"pkg:pypi/httpx@0.27.0": [Finding("NETWORK_EGRESS", Severity.medium, 2.0, "fixture")]},
        timestamp=TIMESTAMP,
    )
    kwargs.update(overrides)
    return build_spdx(project_inventory(), **kwargs)


def packages_by_name_version(document: dict) -> dict[tuple[str, str | None], dict]:
    return {(p["name"], p.get("versionInfo")): p for p in document["packages"]}


# ------------------------------------------------------------------------------------ schema
def test_documents_validate_against_the_official_spdx_23_schema(validator):
    assert_valid(validator, full_document())
    assert_valid(validator, build_spdx(ProjectInventory(project_name="empty", root_ref="warden:project/empty"),
                                       timestamp=TIMESTAMP))
    assert_valid(validator, build_spdx(hostile_inventory(), timestamp=TIMESTAMP))


def test_schema_validation_is_not_vacuous(validator):
    document = full_document()
    for mutate in (
        lambda d: d.pop("spdxVersion"),
        lambda d: d["relationships"][0].update(relationshipType="LIKES"),
        lambda d: d["packages"][1].update(checksums=[{"algorithm": "SHA999", "checksumValue": "00"}]),
        lambda d: d["packages"][1].update(filesAnalyzed="no"),
    ):
        broken = copy.deepcopy(document)
        mutate(broken)
        assert not validator.is_valid(broken)


# ------------------------------------------------------------------------------------ document
def test_document_creation_info_and_deterministic_namespace():
    first, second = full_document(), full_document()
    assert json.dumps(first) == json.dumps(second)
    assert (first["spdxVersion"], first["dataLicense"], first["SPDXID"]) == ("SPDX-2.3", "CC0-1.0", "SPDXRef-DOCUMENT")
    assert first["creationInfo"] == {"created": TIMESTAMP, "creators": ["Tool: warden-x-2.0.0"]}
    namespace = first["documentNamespace"]
    assert namespace.startswith(DEFAULT_NAMESPACE_BASE + "/fixture-project-") and "#" not in namespace
    assert full_document(timestamp="2026-09-16T00:00:00Z")["documentNamespace"] != namespace
    assert full_document(vulns_by_ref={})["documentNamespace"] != namespace

    inventory = project_inventory()
    inventory.components.reverse()
    inventory.edges.reverse()
    reordered = build_spdx(inventory, vulns_by_ref=fixture_vulnerabilities(),
                           risk_by_ref={"pkg:pypi/httpx@0.27.0": {"final_score": 81, "decision": "block"}},
                           findings_by_ref={"pkg:pypi/httpx@0.27.0": [Finding("NETWORK_EGRESS", Severity.medium, 2.0,
                                                                              "fixture")]},
                           timestamp=TIMESTAMP)
    assert json.dumps(reordered) == json.dumps(first)


def test_relationships_describe_project_and_follow_dependency_edges():
    inventory = project_inventory()
    document = build_spdx(inventory, timestamp=TIMESTAMP)
    ids = {p["SPDXID"] for p in document["packages"]} | {"SPDXRef-DOCUMENT"}
    relationships = [(r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])
                     for r in document["relationships"]]
    assert relationships[0] == ("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Project")
    assert all(a in ids and b in ids for a, _rel, b in relationships)
    by_key = packages_by_name_version(document)

    def sid(name: str, version: str | None) -> str:
        return by_key[(name, version)]["SPDXID"]

    depends = {(a, b) for a, rel, b in relationships if rel == "DEPENDS_ON"}
    direct = {sid(c.name, c.version) for c in inventory.components if c.direct}
    assert {b for a, b in depends if a == "SPDXRef-Project"} == direct
    assert (sid("anyio", "4.3.0"), sid("idna", "3.7")) in depends
    assert (sid("sniffio", "1.3.1"), sid("anyio", "4.3.0")) in depends  # cycle preserved
    assert len(relationships) == len(set(relationships))


# ------------------------------------------------------------------------------------ packages
def test_packages_carry_purls_checksums_and_noassertion_when_unknown():
    document = full_document()
    packages = packages_by_name_version(document)
    root = document["packages"][0]
    assert (root["SPDXID"], root["name"], root["versionInfo"], root["primaryPackagePurpose"]) == \
        ("SPDXRef-Project", "fixture-project", "0.3.0", "APPLICATION")

    httpx = packages[("httpx", "0.27.0")]
    assert httpx["externalRefs"][0] == {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                        "referenceLocator": "pkg:pypi/httpx@0.27.0"}
    assert httpx["checksums"] == [{"algorithm": "SHA256", "checksumValue": "12" * 32},
                                  {"algorithm": "SHA256", "checksumValue": "34" * 32}]
    assert "2 distribution-file digests" in httpx["comment"]
    for package in document["packages"]:
        assert package["licenseConcluded"] == "NOASSERTION"
        assert package["downloadLocation"] == "NOASSERTION"
        assert package["copyrightText"] == "NOASSERTION"
        assert package["licenseDeclared"] == "NOASSERTION"  # the fixtures state no licenses
        assert SPDX_ID_RE.match(package["SPDXID"])

    flask = packages[("flask", None)]
    assert "versionInfo" not in flask and "externalRefs" not in flask and "checksums" not in flask
    assert packages[("acme-git", "1.0.0")].get("externalRefs") is None  # git-locked: no registry purl
    assert "resolution=locked" in httpx["comment"] and "direct=true" in httpx["comment"]


def test_vulnerability_references_and_warden_annotations():
    httpx = packages_by_name_version(full_document())[("httpx", "0.27.0")]
    security = [r for r in httpx["externalRefs"] if r["referenceCategory"] == "SECURITY"]
    assert security == [
        {"referenceCategory": "SECURITY", "referenceType": "advisory",
         "referenceLocator": "https://example.com/advisories/cve-2099-20002", "comment": "CVE-2099-20002"},
        {"referenceCategory": "SECURITY", "referenceType": "advisory",
         "referenceLocator": "https://osv.dev/vulnerability/GHSA-fx11-fx11-fx11", "comment": "GHSA-fx11-fx11-fx11"},
    ]  # WARDEN-FIXTURE-3 has no URL, so no reference is fabricated for it
    assert httpx["annotations"] == [{
        "annotationDate": TIMESTAMP, "annotationType": "OTHER", "annotator": "Tool: warden-x-2.0.0",
        "comment": "warden:risk_score=81; warden:decision=block; warden:finding_count=1; "
                   "warden:max_finding_severity=medium",
    }]


def test_declared_license_only_for_valid_spdx_expressions(validator):
    document = build_spdx(hostile_inventory(), timestamp=TIMESTAMP)
    assert_valid(validator, document)
    declared = sorted(p["licenseDeclared"] for p in document["packages"])
    assert declared == ["Apache-2.0", "NOASSERTION", "NOASSERTION", "NOASSERTION", "NOASSERTION"]


# ------------------------------------------------------------------------------------ hostile input
def test_spdx_ids_are_sanitised_unique_and_secrets_redacted(validator):
    document = build_spdx(hostile_inventory(), timestamp=TIMESTAMP)
    assert_valid(validator, document)
    ids = [p["SPDXID"] for p in document["packages"]]
    assert len(ids) == len(set(ids)) == 5
    assert all(SPDX_ID_RE.match(i) for i in ids)
    # "1_0" and "1-0" sanitise to the same text; the bom-ref digest keeps them distinct.
    x_ids = sorted(i for i in ids if i.startswith("SPDXRef-Package-x-1-0-"))
    assert len(x_ids) == 2
    relationships = {(r["spdxElementId"], r["relatedSpdxElement"]) for r in document["relationships"]}
    assert all(a != b for a, b in relationships)  # self edges dropped
    dumped = json.dumps(document)
    # IDs, slugs and purls lower-case names and drop "_", so check the secret body case-insensitively.
    assert TOKEN[4:].lower() not in dumped.lower() and "ghost" not in dumped
    assert "#" not in document["documentNamespace"]
    control = re.compile("[\x00-\x08\x0b-\x1f\x7f‪-‮]")
    assert not control.search(json.loads(dumped)["name"])
    assert all(not control.search(p["name"]) for p in document["packages"])


@pytest.mark.parametrize(
    ("raw", "expected"), [("a_b c", "a-b-c"), ("..x..", "x"), ("___", "x"), ("1.0+local", "1.0-local")],
)
def test_sanitize_id_part(raw, expected):
    assert sanitize_id_part(raw) == expected
