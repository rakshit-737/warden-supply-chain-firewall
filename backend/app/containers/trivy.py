"""Optional image vulnerability scan through an installed Trivy binary.

Trivy is not bundled. When it is missing, cannot run, times out or prints something that is not its
JSON report, :func:`scan_image_archive` returns a status that says so and no vulnerability findings:
the caller reports "vulnerabilities not assessed", never "no vulnerabilities".

The archive is written to a private temporary directory (mode 0700) for the duration of the run and
removed afterwards. Trivy runs with ``--skip-db-update`` only when ``offline`` is requested, so an
offline scan uses whatever database the host already has.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Code
from app.analysis.tools import DEFAULT_MAX_OUTPUT_BYTES, ToolError, find_tool, remove_tree, run_tool
from app.core.config import settings
from app.core.redaction import sanitize_text

ANALYZER_NAME = "container-trivy"
ANALYZER_VERSION = "1.0.0"
MAX_VULNERABILITY_FINDINGS = 500

_SEVERITY = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "UNKNOWN": Severity.info,
}


@dataclass
class TrivyOutcome:
    status: str  # ok | unavailable | error | timeout
    version: str | None = None
    detail: str | None = None
    findings: list[Finding] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": "trivy", "status": self.status, "version": self.version, "detail": self.detail,
                "vulnerabilities": len(self.findings), "truncated": self.truncated}


def _finding(target: str, vuln: dict) -> Finding | None:
    vuln_id = vuln.get("VulnerabilityID")
    package = vuln.get("PkgName")
    if not isinstance(vuln_id, str) or not isinstance(package, str):
        return None
    severity = _SEVERITY.get(str(vuln.get("Severity") or "UNKNOWN").upper(), Severity.info)
    fixed = vuln.get("FixedVersion") if isinstance(vuln.get("FixedVersion"), str) else None
    installed = vuln.get("InstalledVersion") if isinstance(vuln.get("InstalledVersion"), str) else None
    message = f"{vuln_id} in {package} {installed or ''}".strip()
    message += f" (fixed in {fixed})" if fixed else " (no fixed version published)"
    evidence = {
        "vulnerability_id": sanitize_text(vuln_id, max_len=64),
        "package": sanitize_text(package, max_len=214),
        "installed_version": sanitize_text(installed, max_len=64) if installed else None,
        "fixed_version": sanitize_text(fixed, max_len=128) if fixed else None,
        "target": sanitize_text(target, max_len=200),
        "source": "trivy",
    }
    return Finding(
        Code.CONTAINER_VULNERABILITY, severity, 1.0, sanitize_text(message, max_len=300), evidence,
        confidence=0.9, location=Location(file=sanitize_text(target, max_len=300)),
        provenance=Provenance.tool("trivy"),
        references=tuple(r for r in (vuln.get("PrimaryURL"),) if isinstance(r, str) and r.startswith("https://")),
    ).with_defaults(analyzer=ANALYZER_NAME, analyzer_version=ANALYZER_VERSION)


def parse_report(stdout: str) -> tuple[list[Finding], bool]:
    """Findings from a Trivy JSON report; raises ``ValueError`` when it is not one."""
    report = json.loads(stdout)
    if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
        raise ValueError("unexpected Trivy report shape")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    truncated = False
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            key = (target, str(vuln.get("VulnerabilityID")), str(vuln.get("PkgName")))
            if key in seen:
                continue
            seen.add(key)
            finding = _finding(target, vuln)
            if finding is None:
                continue
            if len(findings) >= MAX_VULNERABILITY_FINDINGS:
                truncated = True
                break
            findings.append(finding)
    findings.sort(key=lambda f: (-f.severity.rank, f.evidence["vulnerability_id"], f.evidence["package"]))
    return findings, truncated


def scan_image_archive(data: bytes, *, offline: bool = False, timeout: float | None = None) -> TrivyOutcome:
    binary = settings.TRIVY_BINARY
    status = find_tool(binary)
    if not status.available:
        return TrivyOutcome("unavailable", detail=status.detail or "not installed")
    workdir = tempfile.mkdtemp(prefix="warden-image-")
    try:
        os.chmod(workdir, 0o700)
        archive = os.path.join(workdir, "image.tar")
        with open(archive, "wb") as fh:
            fh.write(data)
        argv = [binary, "image", "--input", archive, "--format", "json", "--quiet", "--scanners", "vuln"]
        if offline:
            argv += ["--skip-db-update", "--offline-scan"]
        try:
            result = run_tool(argv, timeout=float(timeout or settings.CONTAINER_SCAN_TIMEOUT_SECONDS),
                              cwd=workdir, max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES * 4)
        except (ToolError, ValueError) as exc:
            return TrivyOutcome("error", status.version, f"launch failed ({type(exc).__name__})")
        if result.timed_out:
            return TrivyOutcome("timeout", status.version, "trivy timed out")
        if result.returncode != 0 or result.truncated:
            detail = "output truncated" if result.truncated else f"exited {result.returncode}"
            return TrivyOutcome("error", status.version, detail)
        try:
            findings, truncated = parse_report(result.stdout)
        except ValueError:
            return TrivyOutcome("error", status.version, "unreadable report")
        return TrivyOutcome("ok", status.version, None, findings, truncated)
    finally:
        remove_tree(workdir)
