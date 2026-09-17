"""The ``warden`` CLI: argument handling, terminal safety, and the local engine commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli import warden_cli

REPO_ROOT = Path(__file__).resolve().parents[2]


def run(argv: list[str], capsys) -> tuple[int, str, str]:
    code = warden_cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\nflask>=3.0\n", encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------- arguments
def test_api_commands_require_a_token(capsys, monkeypatch):
    monkeypatch.delenv("WARDEN_TOKEN", raising=False)
    code, _, err = run(["scan", "requests==2.32.3"], capsys)
    assert code == 3 and "token" in err


def test_the_token_and_api_default_to_environment_variables(monkeypatch):
    monkeypatch.setenv("WARDEN_TOKEN", "from-env")
    monkeypatch.setenv("WARDEN_API", "https://warden.example.invalid")
    args = warden_cli.build_parser().parse_args(["scan", "requests"])
    assert args.token == "from-env" and args.api == "https://warden.example.invalid"


def test_local_commands_do_not_need_a_token(capsys, monkeypatch, project):
    monkeypatch.delenv("WARDEN_TOKEN", raising=False)
    code, out, _ = run(["project", "scan", str(project)], capsys)
    assert code == 0 and "WARDEN PROJECT SCAN" in out


# --------------------------------------------------------------------------- terminal safety
def test_terminal_safe_escapes_control_and_bidi_characters():
    hostile = "evil\x1b[2J\x1b]0;owned\x07name‮"
    safe = warden_cli.terminal_safe(hostile)
    assert "\x1b" not in safe and "\x07" not in safe and "‮" not in safe
    assert "\\x1b" in safe


def test_verdict_lines_never_echo_raw_escape_sequences():
    verdict = {"decision": "block", "risk_score": 99, "package_name": "pkg\x1b[31m", "version": "1.0\r\n",
               "signals": [{"code": "IOC\x1b_MATCH"}]}
    line = warden_cli._fmt(verdict, no_color=True)
    assert "\x1b" not in line and "\r" not in line and "\n" not in line


# --------------------------------------------------------------------------- sbom generate
def test_sbom_generate_writes_a_cyclonedx_document(capsys, project, tmp_path):
    out_file = tmp_path / "sbom.json"
    code, _, err = run(["sbom", "generate", str(project), "--output", str(out_file)], capsys)
    assert code == 0, err
    document = json.loads(out_file.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    purls = {c.get("purl") for c in document["components"]}
    assert "pkg:pypi/requests@2.32.3" in purls


def test_sbom_generation_is_reproducible_with_source_date_epoch(capsys, project, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    _, first, _ = run(["sbom", "generate", str(project)], capsys)
    _, second, _ = run(["sbom", "generate", str(project)], capsys)
    assert first == second
    assert json.loads(first)["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"


def test_sbom_generate_supports_spdx(capsys, project):
    code, out, _ = run(["sbom", "generate", str(project), "--format", "spdx"], capsys)
    assert code == 0 and json.loads(out)["spdxVersion"] == "SPDX-2.3"


def test_sbom_generate_refuses_a_directory_without_manifests(capsys, tmp_path):
    code, _, err = run(["sbom", "generate", str(tmp_path)], capsys)
    assert code == 3 and "no supported manifests" in err


# --------------------------------------------------------------------------- policy validate
def test_the_shipped_policies_validate(capsys):
    for name in ("production", "staging", "development"):
        code, out, err = run(["policy", "validate", str(REPO_ROOT / "policies" / f"{name}.yaml")], capsys)
        assert code == 0, err
        assert "policy_hash=" in out


def test_an_invalid_policy_fails_with_located_errors(capsys, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "apiVersion: warden.dev/v1\nkind: Policy\nmetadata: {name: bad, environment: staging}\n"
        "spec:\n  deny: {codes: [NOT_A_CODE]}\n",
        encoding="utf-8",
    )
    code, _, err = run(["policy", "validate", str(bad)], capsys)
    assert code == 2
    assert "spec.deny.codes" in err and "NOT_A_CODE" in err


def test_policy_validate_json_output(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"apiVersion": "warden.dev/v1", "kind": "Nope"}), encoding="utf-8")
    code, out, _ = run(["policy", "validate", str(bad), "--format", "json"], capsys)
    assert code == 2
    body = json.loads(out)
    assert body["valid"] is False and body["errors"]


def test_policy_validate_reports_an_unreadable_file(capsys, tmp_path):
    code, _, err = run(["policy", "validate", str(tmp_path / "missing.yaml")], capsys)
    assert code == 3 and "cannot read" in err


# --------------------------------------------------------------------------- project scan
def test_project_scan_reports_hygiene_findings_with_manifest_locations(capsys, project):
    code, out, _ = run(["project", "scan", str(project), "--format", "json"], capsys)
    body = json.loads(out)
    assert code == 0
    assert body["components"] == 2 and body["direct"] == 2
    unpinned = [f for f in body["findings"] if f["code"] == "UNPINNED_DEPENDENCY"]
    assert unpinned and unpinned[0]["location"]["file"] == "requirements.txt"
    assert unpinned[0]["location"]["line"] == 2


def test_project_scan_fails_on_the_configured_severity(capsys, tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://packages.example.invalid/simple\nrequests==2.32.3\n", encoding="utf-8")
    code_default, _, _ = run(["project", "scan", str(tmp_path)], capsys)
    code_strict, _, err = run(["project", "scan", str(tmp_path), "--fail-on", "medium"], capsys)
    assert code_default == 0  # index ambiguity is medium; the default threshold is high
    assert code_strict == 2 and "FAILED" in err


def test_project_scan_rejects_a_missing_directory(capsys, tmp_path):
    code, _, err = run(["project", "scan", str(tmp_path / "nope")], capsys)
    assert code == 3 and "not a directory" in err
