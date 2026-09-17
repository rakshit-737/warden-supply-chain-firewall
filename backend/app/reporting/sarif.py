"""SARIF 2.1.0 output for Warden findings (GitHub code scanning and other SARIF consumers).

One run per report. Each distinct finding code becomes a rule carrying its title, remediation, the
CWE / ATT&CK tags from the taxonomy and a ``security-severity`` score, which GitHub uses to rank
alerts. Each finding becomes a result.

Locations are never invented. A result gets a ``physicalLocation`` only when the finding knows its
file, and a ``region`` only when it knows the line. For project scans those are the manifest file
and the line that declared the dependency, which is exactly where a developer fixes it. Findings
without a location are still reported, but GitHub code scanning only displays results that have
one, so callers that upload to GitHub should prefer location-bearing findings (project scans
produce them).

``partialFingerprints`` carries the finding id so an alert keeps its identity across runs while
the underlying evidence stays the same.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.analysis import taxonomy
from app.analysis.findings import Finding, Severity
from app.core.redaction import sanitize_text

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Warden X"
INFORMATION_URI = "https://github.com/rakshit-737/warden-supply-chain-firewall"
SRCROOT = "%SRCROOT%"
FINGERPRINT_KEY = "wardenFindingId/v1"

# SARIF has three result levels; GitHub additionally reads a numeric ``security-severity``.
_LEVELS = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}
_SECURITY_SEVERITY = {
    Severity.critical: "9.5",
    Severity.high: "8.0",
    Severity.medium: "5.5",
    Severity.low: "3.0",
    Severity.info: "0.0",
}


def _rule(code: str, representative: Finding) -> dict[str, Any]:
    info = taxonomy.get(code)
    title = (info.title if info else None) or representative.title or code.replace("_", " ").title()
    remediation = (info.remediation if info else None) or representative.remediation or ""
    tags = ["security", "supply-chain"]
    if representative.category:
        tags.append(representative.category)
    tags.extend(f"external/cwe/{cwe.lower()}" for cwe in (info.cwe if info else representative.cwe))
    tags.extend(f"attack/{technique}" for technique in (info.attack if info else representative.attack))
    rule: dict[str, Any] = {
        "id": code,
        "name": "".join(part.capitalize() for part in code.split("_")),
        "shortDescription": {"text": sanitize_text(title, max_len=200)},
        "fullDescription": {"text": sanitize_text(title, max_len=1000)},
        "defaultConfiguration": {"level": _LEVELS[representative.severity]},
        "properties": {
            "tags": sorted(set(tags)),
            "security-severity": _SECURITY_SEVERITY[representative.severity],
        },
    }
    if remediation:
        rule["help"] = {
            "text": sanitize_text(remediation, max_len=2000),
            "markdown": sanitize_text(remediation, max_len=2000),
        }
    references = list(info.references if info else representative.references)
    if references:
        rule["helpUri"] = references[0]
    return rule


def _location(finding: Finding) -> list[dict[str, Any]]:
    loc = finding.location
    if loc is None or not loc.file:
        return []
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": loc.file.replace("\\", "/"), "uriBaseId": SRCROOT},
    }
    if loc.line:
        region: dict[str, Any] = {"startLine": loc.line}
        if loc.end_line and loc.end_line >= loc.line:
            region["endLine"] = loc.end_line
        if loc.column is not None:
            region["startColumn"] = loc.column + 1  # SARIF columns are 1-based
        physical["region"] = region
    return [{"physicalLocation": physical}]


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.code,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": sanitize_text(finding.message, max_len=1000)},
        "partialFingerprints": {FINGERPRINT_KEY: finding.finding_id},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "category": finding.category,
            "analyzer": finding.analyzer,
        },
    }
    locations = _location(finding)
    if locations:
        result["locations"] = locations
    return result


def build_sarif(findings: Iterable[Finding], *, tool_version: str,
                automation_id: str | None = None) -> dict[str, Any]:
    """A complete SARIF 2.1.0 log for ``findings`` (one run)."""
    ordered = sorted(
        (f.with_defaults() for f in findings),
        key=lambda f: (-f.severity.rank, f.code, f.location.file if f.location and f.location.file else "",
                       f.location.line if f.location and f.location.line else 0, f.finding_id),
    )
    representatives: dict[str, Finding] = {}
    for finding in ordered:
        current = representatives.get(finding.code)
        if current is None or finding.severity.rank > current.severity.rank:
            representatives[finding.code] = finding
    codes = sorted(representatives)
    index = {code: i for i, code in enumerate(codes)}

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": tool_version,
                "informationUri": INFORMATION_URI,
                "rules": [_rule(code, representatives[code]) for code in codes],
            },
        },
        "originalUriBaseIds": {SRCROOT: {"description": {"text": "The scanned project root"}}},
        "results": [_result(f, index[f.code]) for f in ordered],
        "columnKind": "unicodeCodePoints",
    }
    if automation_id:
        run["automationDetails"] = {"id": sanitize_text(automation_id, max_len=200)}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
