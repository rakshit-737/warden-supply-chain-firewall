"""CycloneDX 1.6 builder: offline validation against the official schema, determinism, honest content.

Schemas are the unmodified official files in ``tests/data/schemas`` (see its README), resolved
through a local ``referencing`` registry so validation never touches the network. Vulnerability,
risk and finding inputs below are test fixtures with synthetic identifiers, not real advisories.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from app.analysis.findings import Finding, Severity
from app.intel.models import Vulnerability
from app.sbom import build_cyclonedx, parse_project
from app.sbom.cyclonedx import score_method, spdx_expression
from app.sbom.models import Component, DependencyEdge, ProjectInventory, make_bom_ref, make_purl

DATA = Path(__file__).parent / "data"
SCHEMAS = DATA / "schemas"
SBOM = DATA / "sbom"
TIMESTAMP = "2026-09-15T12:00:00Z"
TOKEN = "ghp_" + "A1b2C3d4E5" * 4  # looks like a GitHub token; must be redacted


# ------------------------------------------------------------------------------------ helpers
@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    registry: Registry = Registry()
    schemas = {}
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        schemas[name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7))
    return Draft7Validator(schemas["bom-1.6.schema.json"], registry=registry,
                           format_checker=Draft7Validator.FORMAT_CHECKER)


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
    def component(name: str, version: str | None, **kw) -> Component:
        return Component(bom_ref=make_bom_ref(name, version), name=name, normalized_name=name.lower(),
                         version=version, purl=make_purl(name, version), **kw)

    evil = component("evil", "1.0", licenses=["Apache License 2.0"])
    weird = Component(bom_ref="pkg:pypi/we\x1bird‮@1.0\nx", name="we\x1b[31mird‮\nname", normalized_name="weird",
                      version="1.0+local_\x07tag", purl=None, licenses=["LicenseRef-custom"],
                      hashes={"sha256": "xyz"}, file_hashes=["md5:abc", "sha256:" + "g" * 64, "sha1:" + "a" * 40])
    # A raw (un-normalised) credential in every identifying field: the builder must redact it.
    token = Component(bom_ref=f"pkg:pypi/{TOKEN}@2.0", name=TOKEN, normalized_name=TOKEN, version="2.0",
                      purl=f"pkg:pypi/{TOKEN}@2.0", direct=False, depth=2)
    inventory = ProjectInventory(project_name=f"proj {TOKEN} \x1b[2J", root_ref="pkg:pypi/evil@1.0",
                                 components=[evil, weird, token], project_version="1.0 beta\x00")
    inventory.edges = [DependencyEdge(inventory.root_ref, evil.bom_ref), DependencyEdge(evil.bom_ref, weird.bom_ref),
                       DependencyEdge(weird.bom_ref, token.bom_ref), DependencyEdge(token.bom_ref, "pkg:pypi/ghost@0")]
    return inventory


def fixture_vulnerabilities() -> dict[str, list]:
    """Records in the shape produced by app.intel (synthetic ids; test fixtures only)."""
    kev = Vulnerability(
        id="GHSA-fx01-fx01-fx01", aliases=["CVE-2099-10001", "PYSEC-2099-1"], summary="Fixture advisory one",
        severity="high", cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_version="3.1",
        published="2026-01-02T03:04:05Z", modified="2026-02-03T04:05:06+00:00", fixed_versions=["0.27.1"],
        references=["https://example.com/advisories/fx01", "https://example.com/advisories/fx01"], kev=True,
        kev_date_added="2026-03-01", epss_score=0.91234, epss_percentile=0.99,
        sources=["osv", "cisa-kev", "first-epss"],
    )
    v4 = Vulnerability(id="GHSA-fx02-fx02-fx02", severity="medium", cvss_version="4.0",
                       cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", sources=["osv"])
    raw = {"id": "PYSEC-2099-7", "severity": "low", "cwes": ["CWE-79", "NVD-CWE-Other", 89, "CWE-abc", True],
           "references": [{"url": "https://example.com/p7"}, "javascript:alert(1)", "https://example.com/has space"],
           "sources": ["nvd"]}
    withdrawn = {"id": "GHSA-fx03-fx03-fx03", "severity": "critical", "withdrawn": True, "sources": ["osv"]}
    return {
        "pkg:pypi/httpx@0.27.0": [kev, v4],
        "pkg:pypi/anyio@4.3.0": [kev.to_dict(), raw, withdrawn, "not-a-record", {"id": ""}],
        "pkg:pypi/not-in-inventory@1.0": [raw],
    }


RISK = {"pkg:pypi/httpx@0.27.0": {"risk_score": 72.6, "decision": "warn", "severity": "high"},
        "pkg:pypi/anyio@4.3.0": 12, "pkg:pypi/idna@3.7": float("nan"), "pkg:pypi/certifi@2024.2.2": True}
FINDINGS = {"pkg:pypi/httpx@0.27.0": [Finding("NETWORK_EGRESS", Severity.medium, 2.0, "fixture finding"),
                                      {"code": "X", "severity": "critical"}, {"severity": "bogus"}],
            "pkg:pypi/click@8.1.7": []}


def full_document(**overrides) -> dict:
    kwargs = dict(findings_by_ref=FINDINGS, vulns_by_ref=fixture_vulnerabilities(), risk_by_ref=RISK,
                  timestamp=TIMESTAMP, tool_version="2.0.0")
    kwargs.update(overrides)
    return build_cyclonedx(project_inventory(), **kwargs)


def components_by_ref(document: dict) -> dict[str, dict]:
    return {c["bom-ref"]: c for c in document["components"]}


def props(component: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def all_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (all_strings(k) + all_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in all_strings(v)]
    return []


# ------------------------------------------------------------------------------------ schema
def test_documents_validate_against_the_official_cyclonedx_16_schema(validator):
    assert_valid(validator, full_document())
    assert_valid(validator, build_cyclonedx(ProjectInventory(project_name="empty", root_ref="warden:project/empty"),
                                            timestamp=TIMESTAMP))
    assert_valid(validator, build_cyclonedx(hostile_inventory(), timestamp=TIMESTAMP))


def test_schema_validation_is_not_vacuous(validator):
    document = full_document()
    for mutate in (
        lambda d: d.update(bomFormat="SPDX"),
        lambda d: d.update(serialNumber="urn:uuid:not-a-uuid"),
        lambda d: d["components"][0].update(scope="sometimes"),
        lambda d: d["components"][0].update(hashes=[{"alg": "SHA-256", "content": "zz"}]),
        lambda d: d["vulnerabilities"][0]["ratings"][0].update(method="CVSSv99"),
    ):
        broken = copy.deepcopy(document)
        mutate(broken)
        assert not validator.is_valid(broken)


# ------------------------------------------------------------------------------------ header / determinism
def test_document_header_and_metadata():
    inventory = project_inventory()
    document = build_cyclonedx(inventory, timestamp=TIMESTAMP, tool_version="2.0.0")
    assert (document["bomFormat"], document["specVersion"], document["version"]) == ("CycloneDX", "1.6", 1)
    assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        document["serialNumber"])
    metadata = document["metadata"]
    assert metadata["timestamp"] == TIMESTAMP
    assert metadata["tools"]["components"] == [{"type": "application", "name": "Warden", "version": "2.0.0"}]
    assert metadata["component"] == {"type": "application", "bom-ref": inventory.root_ref, "name": "fixture-project",
                                     "version": "0.3.0"}
    manifests = [p["value"] for p in metadata["properties"] if p["name"] == "warden:manifest"]
    assert any(v.startswith("poetry.lock (poetry-lock) sha256:") for v in manifests)


def test_output_is_deterministic_and_serial_is_bound_to_content():
    first, second = full_document(), full_document()
    assert json.dumps(first) == json.dumps(second)

    inventory = project_inventory()
    inventory.components.reverse()
    inventory.edges.reverse()
    shuffled = build_cyclonedx(inventory, findings_by_ref=FINDINGS, vulns_by_ref=fixture_vulnerabilities(),
                               risk_by_ref=RISK, timestamp=TIMESTAMP, tool_version="2.0.0")
    assert json.dumps(shuffled) == json.dumps(first)

    assert full_document(timestamp="2026-09-15T12:00:01Z")["serialNumber"] != first["serialNumber"]
    assert full_document(risk_by_ref={})["serialNumber"] != first["serialNumber"]


# ------------------------------------------------------------------------------------ components
def test_components_scope_hashes_purl_and_properties():
    document = full_document()
    components = components_by_ref(document)
    httpx = components["pkg:pypi/httpx@0.27.0"]
    assert (httpx["type"], httpx["name"], httpx["version"], httpx["purl"], httpx["scope"]) == \
        ("library", "httpx", "0.27.0", "pkg:pypi/httpx@0.27.0", "required")
    assert httpx["hashes"] == [{"alg": "SHA-256", "content": "12" * 32}, {"alg": "SHA-256", "content": "34" * 32}]
    assert components["pkg:pypi/pytest@8.2.0"]["scope"] == "excluded"
    assert components["pkg:pypi/pysocks@1.7.1"]["scope"] == "optional"

    flask = components["pkg:pypi/flask"]  # declared with a range only in legacy-svc/requirements.txt
    assert "version" not in flask and "purl" not in flask and "hashes" not in flask
    assert not any("licenses" in c for c in document["components"])  # no data source stated a license

    httpx_props = props(httpx)
    assert httpx_props["warden:direct"] == ["true"] and httpx_props["warden:depth"] == ["1"]
    assert httpx_props["warden:risk_score"] == ["73"] and httpx_props["warden:decision"] == ["warn"]
    assert httpx_props["warden:finding_count"] == ["3"] and httpx_props["warden:max_finding_severity"] == ["critical"]
    assert httpx_props["warden:resolution"] == ["locked"]
    assert {"poetry.lock:4", "pyproject.toml:8"} <= set(httpx_props["warden:declared_at"])
    sniffio_props = props(components["pkg:pypi/sniffio@1.3.1"])
    assert sniffio_props["warden:direct"] == ["false"] and sniffio_props["warden:depth"] == ["2"]
    idna_props = props(components["pkg:pypi/idna@3.7"])
    assert "warden:risk_score" not in idna_props  # NaN risk is dropped, not coerced
    assert "warden:risk_score" not in props(components["pkg:pypi/certifi@2024.2.2"])  # bool is not a score
    assert props(components["pkg:pypi/anyio@4.3.0"])["warden:risk_score"] == ["12"]
    assert props(components["pkg:pypi/click@8.1.7"])["warden:finding_count"] == ["0"]
    assert "warden:finding_count" not in idna_props  # findings unknown for this component


def test_licenses_come_only_from_recorded_data():
    inventory = project_inventory()
    inventory.component("pkg:pypi/httpx@0.27.0").licenses = ["BSD-3-Clause"]
    inventory.component("pkg:pypi/anyio@4.3.0").licenses = ["(Apache-2.0 OR MIT) AND BSD-2-Clause"]
    inventory.component("pkg:pypi/idna@3.7").licenses = ["Some custom licence text"]
    components = components_by_ref(build_cyclonedx(inventory, timestamp=TIMESTAMP))
    assert components["pkg:pypi/httpx@0.27.0"]["licenses"] == [{"expression": "BSD-3-Clause"}]
    assert components["pkg:pypi/anyio@4.3.0"]["licenses"] == [{"expression": "(Apache-2.0 OR MIT) AND BSD-2-Clause"}]
    assert components["pkg:pypi/idna@3.7"]["licenses"] == [{"license": {"name": "Some custom licence text"}}]


def test_hashes_are_never_invented_from_malformed_values(validator):
    document = build_cyclonedx(hostile_inventory(), timestamp=TIMESTAMP)
    assert_valid(validator, document)
    assert not any("hashes" in c for c in document["components"])


# ------------------------------------------------------------------------------------ dependencies
def test_dependencies_list_every_component_and_the_project():
    inventory = project_inventory()
    document = build_cyclonedx(inventory, timestamp=TIMESTAMP)
    dependencies = {d["ref"]: d["dependsOn"] for d in document["dependencies"]}
    assert set(dependencies) == {c.bom_ref for c in inventory.components} | {inventory.root_ref}
    assert dependencies[inventory.root_ref] == sorted(c.bom_ref for c in inventory.components if c.direct)
    assert dependencies["pkg:pypi/anyio@4.3.0"] == ["pkg:pypi/idna@3.7", "pkg:pypi/sniffio@1.3.1"]
    assert dependencies["pkg:pypi/sniffio@1.3.1"] == ["pkg:pypi/anyio@4.3.0"]  # cycle preserved
    assert dependencies["pkg:pypi/flask"] == []
    compositions = {c["aggregate"]: c["dependencies"] for c in document["compositions"][1:]}
    assert "pkg:pypi/httpx@0.27.0" in compositions["complete"]  # lock file recorded its dependencies
    assert "pkg:pypi/flask" in compositions["unknown"]  # requirements file says nothing about them


def test_sanitised_bom_refs_stay_unique_and_consistent(validator):
    def component(ref: str, name: str) -> Component:
        return Component(bom_ref=ref, name=name, normalized_name=name, version="1", purl=None)

    root = "warden:project/refs"
    raw = component("pkg:pypi/a\x01@1", "a")  # sanitises to the literal text of the next ref
    literal = component("pkg:pypi/a\\x01@1", "b")
    clean = component("pkg:pypi/c@1", "c")
    inventory = ProjectInventory(project_name="refs", root_ref=root, components=[raw, literal, clean],
                                 edges=[DependencyEdge(root, raw.bom_ref), DependencyEdge(raw.bom_ref, literal.bom_ref),
                                        DependencyEdge(literal.bom_ref, clean.bom_ref)])
    document = build_cyclonedx(inventory, timestamp=TIMESTAMP)
    assert_valid(validator, document)
    by_name = {c["name"]: c["bom-ref"] for c in document["components"]}
    assert by_name["b"] == "pkg:pypi/a\\x01@1" and by_name["c"] == "pkg:pypi/c@1"  # safe refs unchanged
    assert by_name["a"].startswith("pkg:pypi/a\\x01@1#") and len(set(by_name.values())) == 3
    dependencies = {d["ref"]: d["dependsOn"] for d in document["dependencies"]}
    assert dependencies[root] == [by_name["a"]]
    assert dependencies[by_name["a"]] == [by_name["b"]] and dependencies[by_name["b"]] == [by_name["c"]]


def test_dangling_edges_and_root_ref_collisions_are_handled(validator):
    document = build_cyclonedx(hostile_inventory(), timestamp=TIMESTAMP)
    refs = [c["bom-ref"] for c in document["components"]] + [document["metadata"]["component"]["bom-ref"]]
    assert len(refs) == len(set(refs))
    assert document["metadata"]["component"]["bom-ref"] == "pkg:pypi/evil@1.0#project"
    dependencies = {d["ref"]: d["dependsOn"] for d in document["dependencies"]}
    assert not any("ghost" in child for children in dependencies.values() for child in children)


# ------------------------------------------------------------------------------------ vulnerabilities
def test_vulnerabilities_are_mapped_grouped_and_filtered():
    vulnerabilities = {v["id"]: v for v in full_document()["vulnerabilities"]}
    assert sorted(vulnerabilities) == ["GHSA-fx01-fx01-fx01", "GHSA-fx02-fx02-fx02", "PYSEC-2099-7"]

    kev = vulnerabilities["GHSA-fx01-fx01-fx01"]
    assert kev["source"] == {"name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-fx01-fx01-fx01"}
    assert [r["id"] for r in kev["references"]] == ["CVE-2099-10001", "PYSEC-2099-1"]
    assert kev["ratings"] == [{"score": 7.5, "severity": "high", "method": "CVSSv31",
                               "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]
    assert kev["advisories"] == [{"url": "https://example.com/advisories/fx01"}]
    assert kev["affects"] == [{"ref": "pkg:pypi/anyio@4.3.0"}, {"ref": "pkg:pypi/httpx@0.27.0"}]
    assert (kev["published"], kev["updated"]) == ("2026-01-02T03:04:05Z", "2026-02-03T04:05:06Z")
    kev_props = {p["name"]: p["value"] for p in kev["properties"]}
    assert kev_props["warden:kev"] == "true" and kev_props["warden:epss"] == "0.91234"
    assert kev_props["warden:kev_date_added"] == "2026-03-01" and kev_props["warden:fixed_versions"] == "0.27.1"

    v4 = vulnerabilities["GHSA-fx02-fx02-fx02"]
    assert v4["ratings"][0]["method"] == "CVSSv4" and "score" not in v4["ratings"][0]
    assert {p["name"]: p["value"] for p in v4["properties"]}["warden:kev"] == "false"

    raw = vulnerabilities["PYSEC-2099-7"]
    assert raw["cwes"] == [79, 89]  # only numeric CWE ids survive
    assert raw["ratings"] == [{"severity": "low", "method": "other"}]
    assert raw["advisories"] == [{"url": "https://example.com/p7"}]
    assert raw["affects"] == [{"ref": "pkg:pypi/anyio@4.3.0"}]  # the unknown component ref is ignored
    assert "source" not in raw  # NVD source links are only built for CVE ids


def test_advisory_shared_by_packages_keeps_each_packages_ratings_and_fixes(validator):
    """Regression: grouping by id alone applied the first package's rating and fixed versions to every
    affected component (tensorflow 2.11.0 was told 2.10.2 fixes it)."""
    def library(name: str, version: str) -> Component:
        return Component(bom_ref=make_bom_ref(name, version), name=name, normalized_name=name, version=version,
                         purl=make_purl(name, version))

    tf, cpu = library("tensorflow", "2.11.0"), library("tensorflow-cpu", "2.10.0")
    root = "warden:project/tf"
    inventory = ProjectInventory(project_name="tf", root_ref=root, components=[tf, cpu],
                                 edges=[DependencyEdge(root, tf.bom_ref), DependencyEdge(root, cpu.bom_ref)])
    shared = {"id": "GHSA-tf00-tf00-tf00", "summary": "Fixture advisory", "sources": ["osv"]}  # test fixture
    vulns = {tf.bom_ref: [{**shared, "severity": "high", "cvss_score": 7.5, "fixed_versions": ["2.11.1"]}],
             cpu.bom_ref: [{**shared, "severity": "critical", "cvss_score": 9.8, "fixed_versions": ["2.10.2"]}]}
    document = build_cyclonedx(inventory, vulns_by_ref=vulns, timestamp=TIMESTAMP)
    assert_valid(validator, document)
    assert [len(v["affects"]) for v in document["vulnerabilities"]] == [1, 1]
    entries = {v["affects"][0]["ref"]: v for v in document["vulnerabilities"]}
    for ref, score, fixed in ((tf.bom_ref, 7.5, "2.11.1"), (cpu.bom_ref, 9.8, "2.10.2")):
        entry = entries[ref]
        assert entry["id"] == "GHSA-tf00-tf00-tf00" and entry["ratings"][0]["score"] == score
        assert {p["name"]: p["value"] for p in entry["properties"]}["warden:fixed_versions"] == fixed
    identical = build_cyclonedx(inventory, vulns_by_ref={tf.bom_ref: [shared], cpu.bom_ref: [shared]},
                                timestamp=TIMESTAMP)
    assert [len(v["affects"]) for v in identical["vulnerabilities"]] == [2]  # identical data is still grouped


@pytest.mark.parametrize(
    ("version", "vector", "expected"),
    [
        ("3.1", None, "CVSSv31"),
        (None, "CVSS:3.1/AV:N", "CVSSv31"),
        ("3.0", None, "CVSSv3"),
        (None, "CVSS:4.0/AV:N", "CVSSv4"),
        ("2.0", None, "CVSSv2"),
        (None, "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSSv2"),
        (None, None, "other"),
        ("banana", "nonsense", "other"),
    ],
)
def test_score_method(version, vector, expected):
    assert score_method(version, vector) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("MIT", "MIT"),
        ("  Apache-2.0   OR  MIT ", "Apache-2.0 OR MIT"),
        ("GPL-2.0-or-later WITH Classpath-exception-2.0", "GPL-2.0-or-later WITH Classpath-exception-2.0"),
        ("(MIT", None),
        ("MIT OR", None),
        ("MIT MIT", None),
        ("LicenseRef-internal", None),
        ("Apache License, Version 2.0", None),
        ("", None),
        (42, None),
    ],
)
def test_spdx_expression_syntax_check(value, expected):
    assert spdx_expression(value) == expected


# ------------------------------------------------------------------------------------ hostile input
def test_hostile_strings_are_sanitised_and_secrets_redacted(validator):
    document = build_cyclonedx(hostile_inventory(), timestamp=TIMESTAMP)
    assert_valid(validator, document)
    dumped = json.dumps(document).lower()
    assert TOKEN[4:].lower() not in dumped  # purls / refs lower-case names, so compare the secret body
    control = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
    for value in all_strings(document):
        assert not control.search(value), value
    weird = next(c for c in document["components"] if c["name"].startswith("we"))
    assert weird["licenses"] == [{"license": {"name": "LicenseRef-custom"}}]
