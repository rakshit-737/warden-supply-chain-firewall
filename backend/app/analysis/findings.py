"""Unified security finding model — the contract every Warden X analyzer emits.

Built-in AST analysis, YARA, Semgrep, secrets detection, vulnerability intelligence,
provenance, release diffing and attack-chain correlation all produce ``Finding`` objects.
A finding is one explainable security observation carrying:

* ``severity``   — the impact *if* the finding is a true positive (info … critical);
* ``confidence`` — how likely it is to be a true positive (0.0 … 1.0). Kept deliberately
  separate from severity so "high impact, weak evidence" is distinguishable from "high
  impact, deterministic evidence";
* ``weight``     — its contribution to the transparent rule score (v1 semantics preserved);
* provenance     — which analyzer (and version) produced it, from which data source;
* an optional source ``location``, CWE / MITRE ATT&CK mappings, remediation, references.

``Signal`` (the v1 name) is an alias of ``Finding``: the first six positional fields are
unchanged, so every v1 construction site keeps working.

Evidence is attacker-influenced data (file names, string literals, registry metadata). It is
sanitised on construction — control and bidi characters escaped, sizes bounded, high-
confidence secret patterns redacted — so a finding can be safely logged, stored, rendered
and exported. Sanitisation is idempotent, which keeps ``finding_id`` stable across
serialisation round-trips.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from app.core.redaction import sanitize_evidence, sanitize_text

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @classmethod
    def coerce(cls, value: Severity | str) -> Severity:
        return value if isinstance(value, Severity) else cls(str(value).strip().lower())


class Category(str, Enum):
    """What kind of risk a finding describes. Drives policy rules and risk dimensions."""

    MALICIOUS_BEHAVIOR = "malicious_behavior"
    CAPABILITY = "capability"  # a capability that benign software also uses (network, subprocess)
    INSTALL_TIME = "install_time_execution"
    OBFUSCATION = "obfuscation"
    CREDENTIAL_ACCESS = "credential_access"
    TYPOSQUAT = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    IOC = "ioc"
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    PROVENANCE = "provenance"
    REPUTATION = "reputation"
    BEHAVIOR_DRIFT = "behavior_drift"
    ATTACK_CHAIN = "attack_chain"
    SUSPICIOUS_ARTIFACT = "suspicious_artifact"
    INTEGRITY = "integrity"
    CODE_WEAKNESS = "code_weakness"
    MISCONFIGURATION = "misconfiguration"
    DEPENDENCY_HYGIENE = "dependency_hygiene"
    PIPELINE = "pipeline"  # analysis-pipeline status: fetch failures, unavailable tools
    OTHER = "other"


class Provenance:
    """Canonical values for ``Finding.provenance`` (the data source of a finding)."""

    STATIC = "static-analysis"
    REGISTRY = "registry-metadata"
    CORRELATION = "correlation"
    RELEASE_DIFF = "release-diff"
    POLICY = "policy"
    SANDBOX = "dynamic-sandbox"

    @staticmethod
    def tool(name: str) -> str:
        return f"external-tool:{name}"

    @staticmethod
    def intel(source: str) -> str:
        return f"intel:{source}"


@dataclass(frozen=True)
class Location:
    """Where a finding was observed. Only populated with positions an analyzer really knows."""

    file: str | None = None
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    snippet: str | None = None

    def __post_init__(self) -> None:
        if self.file is not None:
            object.__setattr__(self, "file", sanitize_text(self.file, max_len=512))
        if self.snippet is not None:
            object.__setattr__(self, "snippet", sanitize_text(self.snippet, max_len=160))
        for name in ("line", "end_line"):
            v = getattr(self, name)
            object.__setattr__(self, name, int(v) if isinstance(v, int) and v >= 1 else None)
        col = self.column
        object.__setattr__(self, "column", int(col) if isinstance(col, int) and col >= 0 else None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "snippet": self.snippet,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> Location | None:
        if not data:
            return None
        return cls(
            file=data.get("file"),
            line=data.get("line"),
            column=data.get("column"),
            end_line=data.get("end_line"),
            snippet=data.get("snippet"),
        )


def _as_str_tuple(values: Iterable[Any] | None) -> tuple[str, ...]:
    if not values:
        return ()
    if isinstance(values, str):
        values = (values,)
    return tuple(sanitize_text(v, max_len=200) for v in values)


@dataclass(frozen=True)
class Finding:
    # --- v1 ``Signal`` fields (positional order is a compatibility contract) ---------
    code: str
    severity: Severity
    weight: float
    message: str
    evidence: dict = field(default_factory=dict)
    # Capability tag used by the policy engine for hard capability blocks.
    capability: str | None = None
    # --- Warden X fields (keyword-only) ---------------------------------------------
    confidence: float = field(default=0.8, kw_only=True)
    category: str | None = field(default=None, kw_only=True)
    title: str | None = field(default=None, kw_only=True)
    analyzer: str | None = field(default=None, kw_only=True)
    analyzer_version: str | None = field(default=None, kw_only=True)
    location: Location | None = field(default=None, kw_only=True)
    cwe: tuple[str, ...] = field(default=(), kw_only=True)
    attack: tuple[str, ...] = field(default=(), kw_only=True)
    remediation: str | None = field(default=None, kw_only=True)
    references: tuple[str, ...] = field(default=(), kw_only=True)
    provenance: str = field(default=Provenance.STATIC, kw_only=True)
    # finding_ids this finding is derived from (attack chains, drift findings).
    related: tuple[str, ...] = field(default=(), kw_only=True)

    def __post_init__(self) -> None:
        set_ = object.__setattr__
        set_(self, "code", sanitize_text(self.code, max_len=64, redact=False))
        set_(self, "severity", Severity.coerce(self.severity))
        weight = float(self.weight)
        set_(self, "weight", weight if weight == weight else 0.0)  # NaN guard
        set_(self, "message", sanitize_text(self.message, max_len=500))
        evidence = self.evidence if isinstance(self.evidence, dict) else {"value": self.evidence}
        set_(self, "evidence", sanitize_evidence(evidence))
        conf = float(self.confidence)
        set_(self, "confidence", 0.0 if conf != conf else round(min(1.0, max(0.0, conf)), 4))
        if isinstance(self.category, Enum):
            set_(self, "category", self.category.value)
        if isinstance(self.location, dict):
            set_(self, "location", Location.from_dict(self.location))
        if self.title is not None:
            set_(self, "title", sanitize_text(self.title, max_len=160))
        if self.remediation is not None:
            set_(self, "remediation", sanitize_text(self.remediation, max_len=1000))
        for name in ("cwe", "attack", "references", "related"):
            set_(self, name, _as_str_tuple(getattr(self, name)))

    # ------------------------------------------------------------------ identity
    @property
    def finding_id(self) -> str:
        """Deterministic id: same analyzer + code + location + evidence => same id."""
        loc = self.location
        basis = json.dumps(
            [self.analyzer or "", self.code, loc.file if loc else None, loc.line if loc else None, self.evidence],
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )
        return "WX-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:20]

    @property
    def description(self) -> str:
        return self.message

    # ------------------------------------------------------------------ enrichment
    def with_defaults(self, *, analyzer: str | None = None, analyzer_version: str | None = None) -> Finding:
        """Fill provenance and taxonomy defaults (category, title, CWE, ATT&CK, remediation)."""
        from app.analysis import taxonomy

        info = taxonomy.get(self.code)
        updates: dict[str, Any] = {}
        if analyzer and not self.analyzer:
            updates["analyzer"] = analyzer
        if analyzer_version and not self.analyzer_version:
            updates["analyzer_version"] = analyzer_version
        if info is not None:
            if not self.category:
                updates["category"] = info.category
            if not self.title:
                updates["title"] = info.title
            if not self.cwe and info.cwe:
                updates["cwe"] = info.cwe
            if not self.attack and info.attack:
                updates["attack"] = info.attack
            if not self.remediation and info.remediation:
                updates["remediation"] = info.remediation
            if not self.references and info.references:
                updates["references"] = info.references
        if not self.category and "category" not in updates:
            updates["category"] = Category.OTHER.value
        if not self.title and "title" not in updates:
            updates["title"] = self.code.replace("_", " ").title()
        return replace(self, **updates) if updates else self

    # ------------------------------------------------------------------ serialisation
    def to_dict(self) -> dict[str, Any]:
        from app.analysis import taxonomy

        return {
            # v1 keys
            "code": self.code,
            "severity": self.severity.value,
            "weight": self.weight,
            "message": self.message,
            "evidence": self.evidence,
            "capability": self.capability,
            # Warden X keys
            "finding_id": self.finding_id,
            "confidence": self.confidence,
            "category": self.category,
            "title": self.title,
            "analyzer": self.analyzer,
            "analyzer_version": self.analyzer_version,
            "location": self.location.to_dict() if self.location else None,
            "cwe": list(self.cwe),
            "attack": list(self.attack),
            "remediation": self.remediation,
            "references": list(self.references),
            "provenance": self.provenance,
            "related": list(self.related),
            "compliance": taxonomy.compliance_for(self.code),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Rebuild a finding from ``to_dict`` output or a legacy v1 signal dict."""
        return cls(
            str(data["code"]),
            Severity.coerce(data.get("severity", "info")),
            float(data.get("weight", 0.0) or 0.0),
            str(data.get("message", "")),
            dict(data.get("evidence") or {}),
            data.get("capability"),
            confidence=float(data.get("confidence", 0.8) if data.get("confidence") is not None else 0.8),
            category=data.get("category"),
            title=data.get("title"),
            analyzer=data.get("analyzer"),
            analyzer_version=data.get("analyzer_version"),
            location=Location.from_dict(data.get("location")),
            cwe=tuple(data.get("cwe") or ()),
            attack=tuple(data.get("attack") or ()),
            remediation=data.get("remediation"),
            references=tuple(data.get("references") or ()),
            provenance=data.get("provenance") or Provenance.STATIC,
            related=tuple(data.get("related") or ()),
        )


def sort_key(finding: Finding) -> tuple:
    """Most important first: severity, then confidence, then weight, then code."""
    return (-finding.severity.rank, -finding.confidence, -finding.weight, finding.code)


def max_severity(findings: Iterable[Finding]) -> Severity:
    best = Severity.info
    for f in findings:
        if f.severity.rank > best.rank:
            best = f.severity
    return best
