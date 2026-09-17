"""Optional Trivy integration: parsing, graceful degradation and cleanup (Trivy itself is stubbed)."""

from __future__ import annotations

import json
import os

import pytest

from app.analysis.tools import ToolError, ToolResult, ToolStatus
from app.containers import trivy

REPORT = {
    "Results": [
        {"Target": "demo (debian 12)", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2099-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",
             "FixedVersion": "3.0.2", "Severity": "CRITICAL", "PrimaryURL": "https://example.invalid/CVE-2099-0001"},
            {"VulnerabilityID": "CVE-2099-0002", "PkgName": "zlib", "InstalledVersion": "1.2",
             "Severity": "LOW", "PrimaryURL": "javascript:alert(1)"},
            {"VulnerabilityID": "CVE-2099-0001", "PkgName": "openssl", "Severity": "CRITICAL"},
            {"PkgName": "missing-id"},
        ]},
        {"Target": "app/requirements.txt", "Vulnerabilities": None},
    ],
}


def result(stdout="", returncode=0, timed_out=False, truncated=False):
    return ToolResult(returncode=returncode, stdout=stdout, stderr="", timed_out=timed_out, duration_ms=1,
                      truncated=truncated)


@pytest.fixture()
def available(monkeypatch):
    monkeypatch.setattr(trivy, "find_tool", lambda binary: ToolStatus(name="trivy", available=True, version="0.99.0"))


def test_report_parsing_dedupes_orders_and_drops_unsafe_links():
    findings, truncated = trivy.parse_report(json.dumps(REPORT))
    assert not truncated
    assert [(f.evidence["vulnerability_id"], f.severity.value) for f in findings] == [
        ("CVE-2099-0001", "critical"), ("CVE-2099-0002", "low")]
    assert findings[0].references == ("https://example.invalid/CVE-2099-0001",)
    assert findings[1].references == () and "no fixed version" in findings[1].message
    assert findings[0].provenance == "external-tool:trivy"


@pytest.mark.parametrize("payload", ["not json", "[]", '{"Results": 5}'])
def test_unexpected_output_is_rejected(payload):
    with pytest.raises(ValueError):
        trivy.parse_report(payload)


def test_missing_trivy_is_reported_as_unavailable(monkeypatch):
    monkeypatch.setattr(trivy, "find_tool",
                        lambda binary: ToolStatus(name="trivy", available=False, detail="not found on PATH"))
    outcome = trivy.scan_image_archive(b"tar")
    assert outcome.status == "unavailable" and outcome.findings == []


def test_successful_scan_writes_a_private_file_and_cleans_up(monkeypatch, available):
    seen = {}

    def fake_run(argv, *, timeout, cwd, max_output_bytes):
        archive = argv[argv.index("--input") + 1]
        seen.update(argv=argv, cwd=cwd, content=open(archive, "rb").read())
        return result(json.dumps(REPORT))

    monkeypatch.setattr(trivy, "run_tool", fake_run)
    outcome = trivy.scan_image_archive(b"image-bytes", offline=True)
    assert outcome.status == "ok" and len(outcome.findings) == 2 and outcome.version == "0.99.0"
    assert seen["content"] == b"image-bytes" and "--skip-db-update" in seen["argv"]
    assert not os.path.exists(seen["cwd"])
    assert outcome.to_dict()["vulnerabilities"] == 2


@pytest.mark.parametrize(("tool_result", "status"), [
    (result(timed_out=True, returncode=None), "timeout"),
    (result("{}", returncode=1), "error"),
    (result("{}", truncated=True), "error"),
    (result("garbage"), "error"),
])
def test_failures_never_look_clean(monkeypatch, available, tool_result, status):
    monkeypatch.setattr(trivy, "run_tool", lambda *a, **k: tool_result)
    outcome = trivy.scan_image_archive(b"x")
    assert outcome.status == status and outcome.findings == []


def test_launch_failure(monkeypatch, available):
    def boom(*a, **k):
        raise ToolError("refused")

    monkeypatch.setattr(trivy, "run_tool", boom)
    assert trivy.scan_image_archive(b"x").status == "error"
