"""Tests for Risk Engine 2.0 (app.analysis.risk) and the rule score it builds on.

Vulnerability records below are hand-written test fixtures shaped like
``Vulnerability.to_dict()``; they are not real advisories.
"""

from __future__ import annotations

import json

import pytest

from app.analysis import risk, scoring
from app.analysis.findings import Finding, Severity
from app.analysis.risk import DIMENSIONS, assess, derive_intel_status, extract_vulnerabilities, vulnerability_score
from app.analysis.signals import Code


class _Model:
    def __init__(self, available: bool = False, ml: int = 0, anomaly: float = 0.0) -> None:
        self.available = available
        self._ml = ml
        self._anomaly = anomaly
        self.metadata: dict = {}

    def predict(self, features):
        return (self._ml, self._anomaly) if self.available else (0, 0.0)


@pytest.fixture(autouse=True)
def _rules_only(monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _Model(False))
    monkeypatch.setattr(scoring.settings, "SCORE_FUSION", "max")


def _f(code, severity, weight, confidence=0.8, evidence=None, *, stamp=True, **kw) -> Finding:
    finding = Finding(code, severity, weight, f"test {code}", evidence or {}, confidence=confidence, **kw)
    return finding.with_defaults(analyzer="test", analyzer_version="0") if stamp else finding


def _vuln_finding(vid: str, *, code=Code.KNOWN_VULNERABILITY, weight=0.0, **record) -> Finding:
    # Fixture record shaped like intel.models.Vulnerability.to_dict().
    return _f(code, Severity.high, weight, 0.9, {"vulnerability": {"id": vid, **record}})


OK = {"status": "ok", "sources": {"osv": "ok"}}


# --------------------------------------------------------------------------- shape
def test_output_dict_has_exact_spec_shape():
    out = assess([], intel_status=OK).to_dict()
    assert set(out) == {
        "method", "final_score", "severity", "confidence", "malicious_risk", "rule_score", "ml_score",
        "vulnerability_risk", "dimensions", "floors_applied",
    }
    assert out["method"] == "warden-risk-2.0"
    assert list(out["dimensions"]) == list(DIMENSIONS)
    for dim in out["dimensions"].values():
        assert set(dim) == {"score", "confidence", "contributors", "rationale"}
    json.dumps(out)  # serialisable


# --------------------------------------------------------------------------- floor
def test_floor_raises_critical_high_confidence_ioc_to_80():
    ioc = _f(Code.IOC_MATCH, Severity.critical, 12.0, 0.95)
    breakdown = assess([ioc], intel_status=OK)
    assert breakdown.rule_score == 54
    assert breakdown.final_score == 80
    assert breakdown.severity == "critical"
    [floor] = breakdown.floors_applied
    assert floor["minimum"] == 80 and floor["previous_score"] == 54 and floor["raised"] is True
    assert floor["finding_ids"] == [ioc.finding_id]
    assert breakdown.confidence == 0.95


def test_floor_requires_confidence_of_at_least_0_9():
    breakdown = assess([_f(Code.IOC_MATCH, Severity.critical, 12.0, 0.89)], intel_status=OK)
    assert breakdown.final_score == 54
    assert breakdown.floors_applied == []


def test_floor_requires_critical_severity():
    breakdown = assess([_f(Code.IOC_MATCH, Severity.high, 12.0, 0.99)], intel_status=OK)
    assert breakdown.floors_applied == []


def test_floor_ignores_categories_outside_the_list():
    # Typosquatting is a strong indicator but not a floor category.
    breakdown = assess([_f(Code.TYPOSQUAT, Severity.critical, 10.0, 0.95)], intel_status=OK)
    assert breakdown.final_score == 45
    assert breakdown.floors_applied == []


def test_integrity_floor_only_for_hash_mismatch():
    mismatch = assess([_f(Code.HASH_MISMATCH, Severity.critical, 10.0, 0.99)], intel_status=OK)
    assert mismatch.final_score == 80
    divergence = assess([_f(Code.SDIST_WHEEL_MISMATCH, Severity.critical, 5.0, 0.99)], intel_status=OK)
    assert divergence.floors_applied == []


def test_floor_uses_taxonomy_category_when_finding_is_unstamped():
    raw = _f(Code.ENCODED_EXEC, Severity.critical, 10.0, 0.9, stamp=False)
    assert raw.category is None
    assert assess([raw], intel_status=OK).final_score == 80


def test_floor_recorded_but_not_raised_when_score_already_high():
    findings = [
        _f(Code.IOC_MATCH, Severity.critical, 12.0, 0.95),
        _f(Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0, 0.85),
    ]
    breakdown = assess(findings, intel_status=OK)
    assert breakdown.final_score == 100
    assert breakdown.floors_applied[0]["raised"] is False


# --------------------------------------------------------------------------- ML
@pytest.mark.parametrize("fusion", ["max", "mean"])
def test_ml_can_never_lower_the_deterministic_score(monkeypatch, fusion):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _Model(True, ml=0, anomaly=0.0))
    monkeypatch.setattr(scoring.settings, "SCORE_FUSION", fusion)
    findings = [
        _f(Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0, 0.85),
        _f(Code.NETWORK_EGRESS, Severity.low, 1.5, 0.5),
    ]
    breakdown = assess(findings, intel_status=OK)
    assert breakdown.rule_score == 61
    assert breakdown.ml_score == 0
    assert breakdown.malicious_risk >= 61
    assert breakdown.final_score >= 61
    assert scoring.score(findings, None).risk_score >= scoring.compute_rule_score(findings)

    floored = assess([_f(Code.IOC_MATCH, Severity.critical, 12.0, 0.95)], intel_status=OK)
    assert floored.final_score == 80


def test_ml_can_raise_the_score_and_feeds_anomaly(monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _Model(True, ml=90, anomaly=0.3))
    breakdown = assess([_f(Code.NETWORK_EGRESS, Severity.low, 1.5, 0.5)], intel_status=OK)
    assert breakdown.malicious_risk == 90
    assert breakdown.final_score == 90
    assert breakdown.dimensions["anomaly"].score == 30
    assert breakdown.confidence == 0.6


def test_anomaly_is_unknown_without_a_model():
    assert assess([], intel_status=OK).dimensions["anomaly"].score is None


# --------------------------------------------------------------------------- vulnerabilities
def test_vulnerability_only_package_is_behaviourally_low_but_vulnerable():
    runs = [{"name": "static_code", "status": "ok"}, {"name": "vulnerability", "status": "ok"}]
    findings = [_vuln_finding("PYSEC-TEST-1", weight=8.0, severity="high", cvss_score=7.5)]
    breakdown = assess(findings, intel_status=OK, analyzer_runs=runs)
    assert breakdown.rule_score == 0  # vulnerability findings never count as malicious behaviour
    assert breakdown.malicious_risk == 0
    assert breakdown.dimensions["behavioral"].score == 0
    assert breakdown.dimensions["vulnerability"].score == 75
    assert breakdown.vulnerability_risk == 75
    assert breakdown.final_score == 75
    assert breakdown.severity == "high"
    assert breakdown.dimensions["vulnerability"].contributors == [findings[0].finding_id]


def test_intel_unavailable_makes_vulnerability_unknown_not_zero():
    unavailable = _f(Code.INTEL_UNAVAILABLE, Severity.info, 0.0, 1.0,
                     {"status": "unavailable", "sources": {"osv": "network"}})
    breakdown = assess([unavailable])
    assert breakdown.vulnerability_risk is None
    assert breakdown.dimensions["vulnerability"].score is None
    assert breakdown.dimensions["exploitability"].score is None
    assert breakdown.to_dict()["vulnerability_risk"] is None
    assert breakdown.final_score == 0
    status = derive_intel_status([unavailable])
    assert status["status"] == "unavailable" and status["sources"] == {"osv": "network"}


@pytest.mark.parametrize("status", ["not_run", "partial", "disabled", "unavailable"])
def test_no_vulnerabilities_is_zero_only_when_intel_ok(status):
    assert assess([], intel_status={"status": status}).vulnerability_risk is None
    ok = assess([], intel_status=OK)
    assert ok.vulnerability_risk == 0
    assert ok.dimensions["exploitability"].score == 0


def test_partial_intel_still_scores_known_vulnerabilities():
    breakdown = assess([_vuln_finding("PYSEC-TEST-2", severity="medium")], intel_status={"status": "partial"})
    assert breakdown.vulnerability_risk == 45
    assert breakdown.dimensions["vulnerability"].confidence == 0.6


@pytest.mark.parametrize(("record", "expected"), [
    ({"cvss_score": 9.8}, 98),
    ({"cvss_score": 7.25}, 73),  # round half up
    ({"cvss_score": 0.0, "severity": "critical"}, 0),  # an explicit CVSS score wins over the bucket
    ({"severity": "critical"}, 90),
    ({"severity": "HIGH"}, 70),
    ({"severity": "medium"}, 45),
    ({"severity": "low"}, 20),
    ({"severity": "unknown"}, 45),
    ({}, 45),
    ({"cvss_score": "not-a-number", "severity": "low"}, 20),
    ({"cvss_score": 11.0, "severity": "high"}, 70),
    ({"cvss_score": 5.0, "kev": True}, 90),
    ({"cvss_score": 9.5, "epss_score": 0.5}, 100),
    ({"cvss_score": 6.0, "epss_score": 0.49}, 60),
    ({"cvss_score": 3.0, "kev": True, "epss_score": 0.7}, 100),
    ({"cvss_score": 3.0, "kev": "true"}, 30),  # only a real boolean counts as KEV
])
def test_vulnerability_score_formula(record, expected):
    assert vulnerability_score({"id": "X", **record}) == expected


def test_withdrawn_advisories_are_ignored():
    breakdown = assess([_vuln_finding("PYSEC-TEST-3", cvss_score=9.9, withdrawn=True)], intel_status=OK)
    assert breakdown.vulnerability_risk == 0


def test_extract_vulnerabilities_dedupes_and_marks_kev():
    findings = [
        _vuln_finding("CVE-TEST-1", cvss_score=5.0),
        _vuln_finding("CVE-TEST-1", cvss_score=5.0, aliases=["dup"]),
        _vuln_finding("CVE-TEST-1", code=Code.KNOWN_EXPLOITED_VULNERABILITY, cvss_score=5.0),
        _vuln_finding("PYSEC-TEST-4", severity="low"),
        _f(Code.KNOWN_VULNERABILITY, Severity.high, 0.0, 0.9, {"vulnerability": {"summary": "no id"}}),
        _f(Code.KNOWN_VULNERABILITY, Severity.high, 0.0, 0.9, {"vulnerability": "not-a-dict"}),
    ]
    vulns = extract_vulnerabilities(findings)
    assert [v["id"] for v in vulns] == ["CVE-TEST-1", "PYSEC-TEST-4"]
    assert vulns[0]["kev"] is True
    assert assess(findings, intel_status=OK).vulnerability_risk == 90


def test_exploitability_from_kev_and_epss():
    kev = assess([_vuln_finding("CVE-TEST-5", cvss_score=4.0, kev=True)], intel_status=OK)
    assert kev.dimensions["exploitability"].score == 100
    epss = assess([_vuln_finding("CVE-TEST-6", cvss_score=4.0, epss_score=0.123)], intel_status=OK)
    assert epss.dimensions["exploitability"].score == 12


def test_exploitability_is_unknown_not_zero_without_kev_or_epss_data():
    """Regression: a failed EPSS lookup with a known vulnerability serialised exploitability as 0."""
    finding = _vuln_finding("CVE-TEST-7", cvss_score=7.5, kev=False, epss_score=None)
    for status in ({"status": "partial", "sources": {"first-epss": "error"}}, OK):
        dim = assess([finding], intel_status=status).dimensions["exploitability"]
        assert dim.score is None and dim.confidence == 0.0
        assert dim.contributors == [finding.finding_id] and "unknown" in dim.rationale
    assert assess([finding], intel_status=OK).to_dict()["dimensions"]["exploitability"]["score"] is None


def test_epss_score_is_a_lower_bound_when_kev_status_is_unknown():
    from app.intel.models import SOURCE_KEV

    assert risk.KEV_SOURCE == SOURCE_KEV
    finding = _vuln_finding("CVE-TEST-8", cvss_score=5.0, epss_score=0.2)
    kev_failed = assess([finding], intel_status={"status": "partial", "sources": {SOURCE_KEV: "error"}})
    dim = kev_failed.dimensions["exploitability"]
    assert dim.score == 20 and dim.confidence == 0.5 and "lower bound" in dim.rationale
    kev_ok = assess([finding], intel_status={"status": "partial", "sources": {SOURCE_KEV: "ok", "nvd": "error"}})
    assert kev_ok.dimensions["exploitability"].confidence == 0.8


# --------------------------------------------------------------------------- final = max
def test_final_is_max_of_malicious_and_vulnerability_risk():
    malicious_dominant = assess([
        _f(Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0, 0.85),
        _f(Code.ENV_HARVEST, Severity.critical, 9.0, 0.65),
        _vuln_finding("CVE-TEST-7", cvss_score=5.0),
    ], intel_status=OK)
    assert (malicious_dominant.malicious_risk, malicious_dominant.vulnerability_risk) == (95, 50)
    assert malicious_dominant.final_score == 95

    vuln_dominant = assess([
        _f(Code.TYPOSQUAT, Severity.high, 6.0, 0.6),
        _vuln_finding("CVE-TEST-8", cvss_score=6.1, kev=True),
    ], intel_status=OK)
    assert (vuln_dominant.malicious_risk, vuln_dominant.vulnerability_risk) == (27, 90)
    assert vuln_dominant.final_score == 90
    assert vuln_dominant.confidence == 0.9


# --------------------------------------------------------------------------- pipeline
def test_pipeline_errors_raise_risk_and_lower_confidence():
    baseline = assess([], intel_status=OK)
    assert baseline.final_score == 0
    error = _f(Code.ANALYZER_ERROR, Severity.medium, 2.0, 1.0, {"analyzer": "x", "error_type": "RuntimeError"})
    with_error = assess([error], intel_status=OK)
    assert with_error.final_score == 9
    assert with_error.confidence <= 0.5
    fetch = _f(Code.FETCH_FAILED, Severity.medium, 3.0, 1.0)
    both = assess([error, fetch], intel_status=OK, analyzer_runs=[{"name": "static_code", "status": "ok"}])
    assert both.final_score == 22
    assert both.dimensions["behavioral"].confidence == 0.25


def test_status_findings_with_zero_weight_do_not_raise_risk():
    tool = _f(Code.TOOL_UNAVAILABLE, Severity.info, 0.0, 1.0)
    assert assess([tool], intel_status=OK).final_score == 0


# --------------------------------------------------------------------------- rule score
def test_secret_and_container_findings_are_excluded_from_rule_score():
    findings = [
        _f(Code.SECRET_DETECTED, Severity.high, 8.0, 0.95),
        _f(Code.DOCKERFILE_ROOT_USER, Severity.medium, 3.0, 0.9),
        _f(Code.CONTAINER_VULNERABILITY, Severity.high, 5.0, 0.9),
    ]
    assert scoring.compute_rule_score(findings) == 0


def test_rule_score_accepts_legacy_signal_dicts_and_clamps_negative_weights():
    assert scoring.compute_rule_score([{"code": "IOC_MATCH", "weight": 12}]) == 54
    assert scoring.compute_rule_score([{"code": "IOC_MATCH", "weight": "junk"}]) == 0
    assert scoring.compute_rule_score([
        _f(Code.IOC_MATCH, Severity.critical, 12.0), _f(Code.NETWORK_EGRESS, Severity.low, -50.0),
    ]) == 54


def test_taxonomy_primary_codes_are_not_support_capped():
    # DEPENDENCY_CONFUSION is primary via the taxonomy, so 10.0 counts in full (not capped to 9).
    assert scoring.compute_rule_score([_f(Code.DEPENDENCY_CONFUSION, Severity.high, 10.0)]) == 45
    assert Code.ATTACK_CHAIN in scoring.primary_codes()
    assert Code.INSTALL_HOOK_EXEC in scoring.primary_codes()


def test_rule_contributions_share_the_support_cap():
    findings = [
        _f(Code.NETWORK_EGRESS, Severity.low, 6.0, evidence={"n": 1}),
        _f(Code.SUBPROCESS_EXEC, Severity.low, 12.0, evidence={"n": 2}),
        _f(Code.IOC_MATCH, Severity.critical, 11.0),
    ]
    rows = {r["code"]: r for r in scoring.rule_contributions(findings)}
    assert rows[Code.IOC_MATCH]["points"] == 50.0 and rows[Code.IOC_MATCH]["kind"] == "primary"
    # support total 18 > cap 9, so each support finding is scaled by 0.5
    assert rows[Code.SUBPROCESS_EXEC]["points"] == round(6.0 / 22 * 100, 2)
    assert rows[Code.NETWORK_EGRESS]["points"] == round(3.0 / 22 * 100, 2)


# --------------------------------------------------------------------------- dimensions
def test_dimensions_distinguish_unknown_from_examined():
    runs = [{"name": "metadata", "status": "ok"}, {"name": "static_code", "status": "ok"},
            {"name": "provenance", "status": "error"}]
    breakdown = assess([], intel_status=OK, analyzer_runs=runs)
    dims = breakdown.dimensions
    assert dims["reputation"].score == 0
    assert dims["behavioral"].score == 0
    assert dims["provenance"].score is None  # the analyzer errored: unknown, not clean
    assert dims["dependency"].score is None
    assert dims["integrity"].score is None
    assert dims["blast_radius"].score is None


def test_reputation_and_provenance_dimensions_use_their_findings():
    findings = [
        _f(Code.NEW_PACKAGE, Severity.medium, 4.0, 0.4),
        _f(Code.SINGLE_MAINTAINER, Severity.low, 1.5, 0.3),
        _f(Code.PROVENANCE_FAILED, Severity.high, 8.0, 0.9),
    ]
    dims = assess(findings, intel_status=OK).dimensions
    assert dims["reputation"].score == 25
    assert dims["reputation"].confidence == round((4.0 * 0.4 + 1.5 * 0.3) / 5.5, 2)
    assert dims["provenance"].score == 36
    assert dims["provenance"].contributors == [findings[2].finding_id]


def test_blast_radius_requires_project_context():
    ok = assess([], intel_status=OK, project_context={"blast_radius": 0.42, "transitive_dependents": 7})
    assert ok.dimensions["blast_radius"].score == 42
    assert "7 transitive dependents" in ok.dimensions["blast_radius"].rationale
    for bad in ({"blast_radius": 1.5}, {"blast_radius": "0.4"}, {}):
        assert assess([], intel_status=OK, project_context=bad).dimensions["blast_radius"].score is None


def test_assessment_is_deterministic_and_order_independent():
    findings = [
        _f(Code.INSTALL_HOOK_EXEC, Severity.critical, 12.0, 0.85),
        _f(Code.NETWORK_EGRESS, Severity.low, 1.5, 0.5),
        _f(Code.NEW_PACKAGE, Severity.low, 2.0, 0.4),
        _vuln_finding("CVE-TEST-9", cvss_score=8.8),
        _vuln_finding("CVE-TEST-10", cvss_score=8.8),
        _f(Code.IOC_MATCH, Severity.critical, 12.0, 0.95),
    ]
    first = json.dumps(assess(findings, intel_status=OK).to_dict(), sort_keys=True)
    second = json.dumps(assess(list(findings), intel_status=OK).to_dict(), sort_keys=True)
    reversed_order = json.dumps(assess(list(reversed(findings)), intel_status=OK).to_dict(), sort_keys=True)
    assert first == second == reversed_order


def test_derive_intel_status_from_runs():
    assert derive_intel_status([], []) == {"status": "not_run"}
    assert derive_intel_status([], [{"name": "vulnerability", "status": "ok"}])["status"] == "ok"
    skipped = derive_intel_status([], [{"name": "vulnerability", "status": "skipped", "detail": "offline"}])
    assert skipped == {"status": "not_run", "reason": "offline"}
    assert derive_intel_status([], [{"name": "vulnerability", "status": "timeout"}])["status"] == "unavailable"
    partial = _f(Code.INTEL_UNAVAILABLE, Severity.info, 0.0, 1.0, {"status": "partial", "sources": {"kev": "error"}})
    assert derive_intel_status([partial], [{"name": "vulnerability", "status": "ok"}])["status"] == "partial"
    assert risk.METHOD == "warden-risk-2.0"


def test_intel_switched_off_or_disabled_is_never_reported_as_ok():
    runs_ok = [{"name": "vulnerability", "status": "ok"}]
    # The analyzer honoured the scan's intel=False switch: a successful run with no findings.
    off = derive_intel_status([], runs_ok, intel_requested=False)
    assert off == {"status": "not_run", "reason": "disabled in scan options"}
    assert assess([], intel_status=off).vulnerability_risk is None

    detail = "vulnerability intelligence disabled (INTEL_ENABLED)"
    disabled = derive_intel_status([], [{"name": "vulnerability", "status": "unavailable", "detail": detail}])
    assert disabled == {"status": "disabled", "reason": detail}
    assert assess([], intel_status=disabled).dimensions["vulnerability"].score is None

    # Real vulnerability findings are never discarded because of the switch.
    vuln = _vuln_finding("PYSEC-TEST-11", severity="low")
    assert derive_intel_status([vuln], runs_ok, intel_requested=False)["status"] == "ok"
