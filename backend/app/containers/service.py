"""Container image scan: image analysis, optional Trivy, decision and a CycloneDX component list.

Decision rules (advisory, applied the same way by the API and the CLI):

* ``block`` - a critical or high finding with confidence >= 0.7 (including known vulnerabilities);
* ``warn`` - otherwise a medium finding, an incomplete analysis, or vulnerabilities that were not
  assessed (Trivy missing or failed): "not checked" is never reported as "clean";
* ``allow`` - none of the above.

``risk_score`` is the severity floor of the worst finding (critical 80, high 60, medium 35, low 15).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.analysis.findings import Finding
from app.containers.image import ImageAnalyzer, ImageReport
from app.containers.trivy import TrivyOutcome, scan_image_archive

CONFIDENCE_GATE = 0.7
_FLOOR = {"info": 0, "low": 15, "medium": 35, "high": 60, "critical": 80}


@dataclass
class ContainerScanResult:
    report: ImageReport
    vulnerability_scan: TrivyOutcome
    findings: list[Finding] = field(default_factory=list)
    decision: str = "allow"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    sbom: dict = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        data = self.report.to_dict()
        data.pop("findings")
        data.pop("components")
        return {**data, "decision": self.decision, "risk_score": self.risk_score, "reasons": self.reasons,
                "finding_counts": _severity_counts(self.findings)}


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in _FLOOR}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def decide(findings: list[Finding], *, complete: bool, vulnerabilities_assessed: bool) -> tuple[str, int, list[str]]:
    reasons: list[str] = []
    risk = max((_FLOOR[f.severity.value] for f in findings), default=0)
    blocking = [f for f in findings if f.severity.value in ("critical", "high") and f.confidence >= CONFIDENCE_GATE]
    if blocking:
        codes = sorted({f.code for f in blocking})
        reasons.append(f"{len(blocking)} high or critical finding(s): {', '.join(codes)}")
        return "block", risk, reasons
    decision = "allow"
    if any(f.severity.value == "medium" for f in findings):
        decision = "warn"
        reasons.append("medium-severity findings")
    if not complete:
        decision = "warn"
        reasons.append("the image could not be analysed completely")
    if not vulnerabilities_assessed:
        decision = "warn"
        reasons.append("known vulnerabilities were not assessed (Trivy unavailable or failed)")
    return decision, risk, reasons


def build_sbom(report: ImageReport, tool_version: str, timestamp: datetime | None = None) -> dict:
    """A CycloneDX 1.6 document listing the packages found in the image."""
    moment = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
    seed = report.config_digest or "|".join(report.image_refs) or "unknown-image"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/rakshit-737/warden-supply-chain-security/image/{seed}")
    components = []
    seen: set[str] = set()
    for c in report.components:
        ref = c.purl or f"{c.type}:{c.name}@{c.version or 'unknown'}"
        if ref in seen:
            continue
        seen.add(ref)
        component: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": c.name}
        if c.version:
            component["version"] = c.version
        if c.purl:
            component["purl"] = c.purl
        component["properties"] = [{"name": "warden:layer", "value": str(c.layer)},
                                   {"name": "warden:package-type", "value": c.type}]
        components.append(component)
    image_name = report.image_refs[0] if report.image_refs else "container-image"
    metadata_component: dict[str, Any] = {"type": "container", "bom-ref": "image", "name": image_name}
    if report.config_digest:
        metadata_component["hashes"] = [{"alg": "SHA-256", "content": report.config_digest.split(":", 1)[1]}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": moment.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "Warden", "version": tool_version}]},
            "component": metadata_component,
        },
        "components": components,
    }


def scan_image(data: bytes, filename: str = "image.tar", *, vulnerabilities: bool = True, offline: bool = False,
               tool_version: str = "2.0.0", analyzer: ImageAnalyzer | None = None) -> ContainerScanResult:
    report = (analyzer or ImageAnalyzer()).analyze(data, filename)
    if vulnerabilities and report.config_digest is not None:
        outcome = scan_image_archive(data, offline=offline)
    elif vulnerabilities:
        outcome = TrivyOutcome("skipped", detail="image could not be parsed")
    else:
        outcome = TrivyOutcome("skipped", detail="disabled by request")
    findings = [*report.findings, *outcome.findings]
    findings.sort(key=lambda f: (-f.severity.rank, f.code, f.finding_id))
    decision, risk, reasons = decide(findings, complete=report.complete,
                                     vulnerabilities_assessed=outcome.status == "ok")
    return ContainerScanResult(report=report, vulnerability_scan=outcome, findings=findings, decision=decision,
                               risk_score=risk, reasons=reasons, sbom=build_sbom(report, tool_version))
