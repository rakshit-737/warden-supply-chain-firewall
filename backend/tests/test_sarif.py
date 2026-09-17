"""SARIF 2.1.0 output: schema validity, honest locations, stable fingerprints, CLI wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analysis.findings import Finding, Location, Severity
from app.analysis.signals import Code
from app.reporting.sarif import FINGERPRINT_KEY, SARIF_VERSION, build_sarif
from cli import warden_cli

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_PATH = Path(__file__).parent / "data" / "schemas" / "sarif-schema-2.1.0.json"


def validate(log: dict) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft4Validator(schema).validate(log)


def finding(code: str, severity: Severity, *, file: str | None = None, line: int | None = None,
            message: str = "observed") -> Finding:
    location = Location(file=file, line=line) if file else None
    return Finding(code, severity, 1.0, message, {"k": code}, confidence=0.7, location=location,
                   analyzer="test").with_defaults()


def test_an_empty_report_is_valid():
    log = build_sarif([], tool_version="2.0.0")
    validate(log)
    assert log["version"] == SARIF_VERSION and log["runs"][0]["results"] == []


def test_findings_become_rules_and_results_with_github_severity():
    log = build_sarif([
        finding(Code.UNPINNED_DEPENDENCY, Severity.low, file="requirements.txt", line=2),
        finding(Code.DEPENDENCY_CONFUSION, Severity.critical, file="requirements.txt", line=5),
    ], tool_version="2.0.0")
    validate(log)
    run = log["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {Code.UNPINNED_DEPENDENCY, Code.DEPENDENCY_CONFUSION}
    assert rules[Code.DEPENDENCY_CONFUSION]["properties"]["security-severity"] == "9.5"
    assert any(tag.startswith("external/cwe/") for tag in rules[Code.DEPENDENCY_CONFUSION]["properties"]["tags"])
    first = run["results"][0]  # most severe first
    assert first["ruleId"] == Code.DEPENDENCY_CONFUSION and first["level"] == "error"
    assert run["tool"]["driver"]["rules"][first["ruleIndex"]]["id"] == first["ruleId"]


def test_locations_are_never_invented():
    with_line = finding(Code.MISSING_HASHES, Severity.low, file="requirements.txt", line=3)
    file_only = finding(Code.MISSING_HASHES, Severity.low, file="requirements-dev.txt")
    nowhere = finding(Code.NEW_PACKAGE, Severity.low)
    log = build_sarif([with_line, file_only, nowhere], tool_version="2.0.0")
    validate(log)
    by_file = {}
    for result in log["runs"][0]["results"]:
        locations = result.get("locations")
        key = locations[0]["physicalLocation"]["artifactLocation"]["uri"] if locations else None
        by_file[key] = result
    assert by_file["requirements.txt"]["locations"][0]["physicalLocation"]["region"] == {"startLine": 3}
    assert "region" not in by_file["requirements-dev.txt"]["locations"][0]["physicalLocation"]
    assert None in by_file and "locations" not in by_file[None]


def test_fingerprints_are_the_stable_finding_ids():
    one = finding(Code.UNPINNED_DEPENDENCY, Severity.low, file="requirements.txt", line=2)
    first = build_sarif([one], tool_version="2.0.0")
    second = build_sarif([one], tool_version="2.0.0")
    fp = first["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY]
    assert fp == one.finding_id == second["runs"][0]["results"][0]["partialFingerprints"][FINGERPRINT_KEY]


def test_attacker_controlled_messages_are_sanitised():
    hostile = finding(Code.UNPINNED_DEPENDENCY, Severity.low, file="requirements.txt", line=1,
                      message="pkg\x1b[2J‮" + "gh" + "p_" + "A" * 36)
    text = json.dumps(build_sarif([hostile], tool_version="2.0.0"))
    assert "\\u001b" not in text and "‮" not in text
    assert "gh" + "p_" + "A" * 36 not in text


def test_the_cli_writes_a_valid_sarif_file(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://packages.example.invalid/simple\nrequests\n", encoding="utf-8")
    out = tmp_path / "warden.sarif"
    code = warden_cli.main(["project", "scan", str(tmp_path), "--format", "sarif", "--output", str(out)])
    capsys.readouterr()
    assert code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    validate(log)
    results = log["runs"][0]["results"]
    assert results and all(r.get("locations") for r in results)
    lines = {r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"]
             for r in results if "region" in r["locations"][0]["physicalLocation"]}
    assert lines[Code.INDEX_SOURCE_AMBIGUITY] == 1 and lines[Code.UNPINNED_DEPENDENCY] == 2
