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


# --------------------------------------------------------------------------- diff
class _DiffOrchestrator:
    def analyze(self, ecosystem, name, version, options=None):
        from app.analysis.orchestrator import AnalysisResult

        hostile = version == "2.0.0"
        signals = [{"code": "NETWORK_EGRESS", "severity": "high", "message": "\x1b[2Jcalls home",
                    "location": {"file": "pkg/__init__.py", "line": 1}}] if hostile else []
        return AnalysisResult(ecosystem, name, version, 60 if hostile else 5, 0, 60 if hostile else 5,
                              "high" if hostile else "info", {}, signals, "2.0.0", 1, False,
                              capabilities=["network"] if hostile else [])


@pytest.fixture()
def diff_engine(monkeypatch):
    from cli import local

    monkeypatch.setattr(local, "orchestrator_factory", _DiffOrchestrator)


def test_diff_reports_escalation_and_can_fail(capsys, diff_engine):
    code, out, _ = run(["diff", "demo", "1.0.0", "2.0.0"], capsys)
    assert code == 0 and "ESCALATED" in out and "NETWORK_EGRESS" in out
    assert "\x1b" not in out
    code, _, err = run(["diff", "demo", "1.0.0", "2.0.0", "--fail-on-drift"], capsys)
    assert code == 2 and "escalated" in err


def test_diff_json_and_unchanged(capsys, diff_engine):
    code, out, _ = run(["diff", "demo", "1.0.0", "1.0.1", "--format", "json", "--fail-on-drift"], capsys)
    assert code == 0 and json.loads(out)["verdict"] == "unchanged"


@pytest.mark.parametrize("argv", [["diff", "../x", "1", "2"], ["diff", "demo", "1.0", "1.0"]])
def test_diff_rejects_bad_input(capsys, diff_engine, argv):
    code, _, err = run(argv, capsys)
    assert code == 3 and err.startswith("error:")


# --------------------------------------------------------------------------- image scan / report / containers
@pytest.fixture()
def no_trivy(monkeypatch):
    from app.containers import service
    from app.containers.trivy import TrivyOutcome

    monkeypatch.setattr(service, "scan_image_archive", lambda data, offline=False: TrivyOutcome("ok", "0.99"))


def write_image(tmp_path: Path, user: str = "app") -> Path:
    from tests.test_container_image import APK, base_config, docker_save, f, tar_bytes

    archive = tmp_path / "image.tar"
    archive.write_bytes(docker_save([tar_bytes([f("lib/apk/db/installed", APK)])], base_config(user=user)))
    return archive


def test_image_scan_table_json_sbom_and_gate(tmp_path, capsys, no_trivy):
    archive = write_image(tmp_path)
    code, out, _ = run(["image", "scan", str(archive)], capsys)
    assert code == 0 and "ALLOW" in out and "apk 2" in out
    sbom = tmp_path / "bom.json"
    code, out, _ = run(["image", "scan", str(archive), "--format", "json", "--sbom-output", str(sbom)], capsys)
    assert code == 0 and json.loads(out)["component_counts"] == {"apk": 2}
    assert json.loads(sbom.read_text())["bomFormat"] == "CycloneDX"
    root = write_image(tmp_path, user="root")
    code, _, err = run(["image", "scan", str(root), "--fail-on", "medium"], capsys)
    assert code == 2 and "FAILED" in err


def test_image_scan_of_a_non_image_fails(tmp_path, capsys, no_trivy):
    bogus = tmp_path / "bogus.tar"
    bogus.write_bytes(b"nope")
    code, _, err = run(["image", "scan", str(bogus), "--fail-on", "critical"], capsys)
    assert code == 2 and "completely" in err
    code, _, err = run(["image", "scan", str(tmp_path / "missing.tar")], capsys)
    assert code == 3


def test_image_scan_sarif(tmp_path, capsys, no_trivy):
    out_file = tmp_path / "image.sarif"
    code, _, _ = run(["image", "scan", str(write_image(tmp_path, user="root")), "--format", "sarif",
                      "-o", str(out_file), "--fail-on", "critical"], capsys)
    log = json.loads(out_file.read_text())
    assert code == 0 and log["runs"][0]["results"][0]["ruleId"] == "DOCKERFILE_ROOT_USER"


def test_project_scan_lints_container_files(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.33.0\n", encoding="utf-8")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "Dockerfile").write_text("FROM ubuntu\nRUN curl -s https://x.invalid | sh\n",
                                                    encoding="utf-8")
    (tmp_path / "dockerfile.py").write_text("from os import path\n", encoding="utf-8")
    code, out, _ = run(["project", "scan", str(tmp_path), "--format", "json"], capsys)
    found = {(f["code"], f["location"]["file"]) for f in json.loads(out)["findings"] if f.get("location")}
    assert ("DOCKERFILE_CURL_PIPE_SHELL", "deploy/Dockerfile") in found
    assert not any(file == "dockerfile.py" for _, file in found)
    assert code == 2


@pytest.mark.parametrize("fmt", ["markdown", "html", "sarif"])
def test_report_renders_saved_results(tmp_path, capsys, no_trivy, fmt):
    code, out, _ = run(["image", "scan", str(write_image(tmp_path, user="root")), "--format", "json",
                        "--fail-on", "critical"], capsys)
    saved = tmp_path / "image.json"
    saved.write_text(out, encoding="utf-8")
    code, rendered, _ = run(["report", str(saved), "--format", fmt], capsys)
    expected = r"DOCKERFILE\_ROOT\_USER" if fmt == "markdown" else "DOCKERFILE_ROOT_USER"
    assert code == 0 and expected in rendered
    if fmt == "html":
        assert "<script" not in rendered and "default-src 'none'" in rendered


def test_report_escapes_hostile_content(tmp_path, capsys):
    hostile = {"project": "<img src=x onerror=alert(1)>", "components": 1, "direct": 1, "failed": True,
               "warnings": [], "findings": [{"code": "UNPINNED_DEPENDENCY", "severity": "low", "weight": 1.0,
                                             "message": "<script>alert(1)</script> | ![x](http://evil)",
                                             "evidence": {}}]}
    saved = tmp_path / "project.json"
    saved.write_text(json.dumps(hostile), encoding="utf-8")
    _, html_out, _ = run(["report", str(saved), "--format", "html"], capsys)
    assert "<script>" not in html_out and "<img" not in html_out
    _, md_out, _ = run(["report", str(saved)], capsys)
    assert "<script>" not in md_out and "![x](http://evil)" not in md_out


def test_report_rejects_unknown_documents(tmp_path, capsys):
    saved = tmp_path / "other.json"
    saved.write_text('{"hello": "world"}', encoding="utf-8")
    code, _, err = run(["report", str(saved)], capsys)
    assert code == 3 and "cannot build a report" in err


@pytest.mark.parametrize("argv", [
    ["gate", "-r", "requirements.txt", "--api", "https://w.example.invalid", "--token", "t", "--fail-on", "warn"],
    ["--api", "https://w.example.invalid", "--token", "t", "--fail-on", "warn", "gate", "-r", "requirements.txt"],
])
def test_api_options_work_before_and_after_the_subcommand(argv):
    args = warden_cli.build_parser().parse_args(argv)
    assert args.api == "https://w.example.invalid" and args.token == "t" and args.fail_on == "warn"
    assert args.requirements == "requirements.txt"
