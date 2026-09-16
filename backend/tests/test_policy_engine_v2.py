"""Policy engine v2: evaluation order, confidence gating, non-overridables, exceptions, vulnerability
and requirement rules, environments, fail-safe behaviour and false-positive controls.

Findings and vulnerability records are fixtures built with the public Finding / Vulnerability
shapes (``GHSA-fixture-*`` ids are not real advisories). The "benign" results model what the
static analyzers report for ordinary libraries; they must not be blocked by the shipped policies.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analysis.findings import Finding, Location
from app.analysis.orchestrator import AnalysisResult
from app.analysis.scoring import compute_rule_score
from app.analysis.signals import Capability, Code
from app.db.base import Base
from app.db.models import Decision, Policy, PolicyException, Role, User
from app.policy import engine as engine_module
from app.policy.document import PolicyDocument, VulnerabilityRule, from_legacy, load_policy_text, validate_policy_data
from app.policy.engine import DEFAULT_POLICY, PolicyDecision, evaluate, policy_hash_of, vulnerability_criteria
from app.policy.exceptions import load_active_exceptions, version_matches

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
TODAY = NOW.date()
POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"
PROD = load_policy_text((POLICIES_DIR / "production.yaml").read_text(encoding="utf-8"), today=TODAY)


# =========================================================================== fixtures
def finding(code: str, *, severity: str = "high", weight: float = 5.0, confidence: float = 0.8,
            capability: str | None = None, category: str | None = None, evidence: dict | None = None,
            file: str = "sample_pkg/__init__.py", line: int = 1) -> dict:
    return Finding(
        code, severity, weight, f"{code} observed (fixture)", evidence or {}, capability, confidence=confidence,
        category=category, location=Location(file=file, line=line),
    ).with_defaults(analyzer="test-fixture", analyzer_version="0").to_dict()


def result(*signals: dict, name: str = "sample-pkg", version: str = "1.4.0", risk: int | None = None,
           capabilities: list[str] | None = None, vulnerabilities=(), intel: str | None = "ok",
           provenance: dict | None = None, package_intel: dict | None = None, scan_options: dict | None = None,
           ml_score: int = 0, ml_available: bool = False) -> AnalysisResult:
    rule = compute_rule_score(list(signals))
    caps = sorted({s["capability"] for s in signals if s.get("capability")}) if capabilities is None else capabilities
    return AnalysisResult(
        "pypi", name, version, rule, ml_score, rule if risk is None else risk, "info", {}, list(signals), "2.0.0", 1,
        ml_available, capabilities=caps, vulnerabilities=list(vulnerabilities),
        intel_status={"status": intel} if intel else {}, provenance=provenance or {},
        package_intel=package_intel or {}, scan_options=scan_options or {},
    )


def doc(**spec) -> PolicyDocument:
    data = {"apiVersion": "warden.dev/v1", "kind": "Policy",
            "metadata": {"name": "engine-fixture", "environment": "production"}, "spec": spec}
    outcome = validate_policy_data(data, today=TODAY)
    assert outcome.valid, outcome.errors
    return outcome.document


def run(res: AnalysisResult, policy, **kwargs) -> PolicyDecision:
    kwargs.setdefault("now", NOW)
    return evaluate(res, policy, **kwargs)


def vuln(vid: str, **fields) -> dict:
    return {"id": vid, "severity": "unknown", "cvss_score": None, "kev": False, "epss_score": None, **fields}


def vuln_finding(record: dict, code: str = Code.KNOWN_VULNERABILITY) -> dict:
    return finding(code, severity="high", weight=0.0, confidence=0.9,
                   evidence={"vulnerability": record, "package": "sample-pkg", "version": "1.4.0"})


def db_exception(**fields) -> PolicyException:
    row = dict(id=uuid.uuid4(), package="sample-pkg", version_spec=None, codes=[], categories=[], environment=None,
               policy_id=None, justification="Reviewed by the security team (fixture)", requested_by=uuid.uuid4(),
               approved_by=uuid.uuid4(), status="approved", expires_at=NOW + timedelta(days=30))
    row.update(fields)
    return PolicyException(**row)


def dynamic_exec(confidence: float = 0.8) -> dict:
    return finding(Code.DYNAMIC_EXEC, severity="medium", weight=4.0, confidence=confidence,
                   capability=Capability.DYNAMIC_EXEC, file="sample_pkg/templates.py", line=33)


def rules(decision: PolicyDecision, effect: str) -> list[str]:
    return [r["rule"] for r in decision.reasons if r["effect"] == effect]


# Modelled on what the static analyzers report for an ordinary HTTP client library.
BENIGN_HTTP_CLIENT = (
    finding(Code.NETWORK_EGRESS, severity="low", weight=1.5, confidence=0.5, capability=Capability.NETWORK,
            file="sample_pkg/adapters.py", line=120),
    finding(Code.SUBPROCESS_EXEC, severity="medium", weight=3.0, confidence=0.55, capability=Capability.SUBPROCESS,
            file="sample_pkg/utils.py", line=41),
    finding(Code.DANGEROUS_IMPORT, severity="low", weight=2.0, confidence=0.4, file="sample_pkg/compat.py", line=3),
)


# =========================================================================== compatibility / defaults
def test_v1_call_uses_the_builtin_default_and_reports_its_hash():
    decision = evaluate(result(risk=85), None)
    assert decision.decision == Decision.block and decision.matched_rules == ["block_threshold"]
    assert decision.policy_hash == policy_hash_of(None)
    assert decision.policy_hash == from_legacy({"name": "builtin-default", **DEFAULT_POLICY}).policy_hash
    assert decision.environment is None and decision.exceptions_applied == []


def test_decision_environment_comes_from_the_call_then_the_policy():
    assert run(result(), doc()).environment == "production"
    assert run(result(), doc(), environment="Staging").environment == "staging"
    assert run(result(), Policy(name="legacy", environment="development")).environment == "development"
    with pytest.raises(ValueError):
        run(result(), doc(), environment="moon")


def test_evaluation_is_deterministic():
    first = run(result(*BENIGN_HTTP_CLIENT, intel="unavailable"), PROD).to_dict()
    for _ in range(3):
        assert run(result(*BENIGN_HTTP_CLIENT, intel="unavailable"), PROD).to_dict() == first


# =========================================================================== ordering / non-overridable
def test_denylist_is_evaluated_before_exceptions_and_the_allowlist():
    row = Policy(name="legacy", denylist=["Sample_Pkg"], allowlist=["sample-pkg"], blocked_capabilities=[])
    decision = run(result(), row, exceptions=[db_exception()])
    assert decision.decision == Decision.block and decision.matched_rules == ["denylist"]
    assert decision.exceptions_applied == []


@pytest.mark.parametrize("signal,rule", [
    pytest.param(finding(Code.IOC_MATCH, severity="critical", weight=12, confidence=0.95, capability=Capability.IOC),
                 "known_malicious_indicator", id="ioc-exact"),
    pytest.param(finding(Code.IOC_MATCH, severity="critical", weight=12, confidence=0.3),
                 "known_malicious_indicator", id="ioc-low-confidence"),
    pytest.param(finding(Code.HASH_MISMATCH, severity="critical", weight=10, confidence=1.0),
                 "artifact_hash_mismatch", id="hash-mismatch"),
    pytest.param(finding(Code.ATTACK_CHAIN, severity="critical", weight=12, confidence=0.9),
                 "critical_attack_chain", id="critical-chain-0.9"),
])
def test_non_overridable_findings_ignore_exceptions_and_the_allowlist(signal, rule):
    policy = doc(allow={"packages": ["sample-pkg"]},
                 exceptions=[{"package": "sample-pkg", "expires": (TODAY + timedelta(days=30)).isoformat(),
                              "reason": "Whole-package waiver (fixture)"}])
    # The second row names the code itself, as a tampered database row would.
    grants = [db_exception(), db_exception(codes=[signal["code"]], categories=[signal["category"]])]
    decision = run(result(signal), policy, exceptions=grants)
    assert decision.decision == Decision.block and rule in decision.matched_rules
    assert decision.exceptions_applied == [] and "allowlist" not in rules(decision, "allow")


def test_legacy_ioc_capability_without_a_finding_is_non_overridable():
    decision = run(result(capabilities=[Capability.IOC]), Policy(name="legacy", allowlist=["sample-pkg"]))
    assert decision.decision == Decision.block and decision.matched_rules == ["known_malicious_indicator"]


def test_attack_chain_below_the_non_overridable_bar_can_be_excepted():
    chain = finding(Code.ATTACK_CHAIN, severity="critical", weight=12, confidence=0.89)
    policy = doc(deny={"categories": ["attack_chain"]})
    blocked = run(result(chain), policy)
    assert blocked.decision == Decision.block and blocked.matched_rules == ["deny_category:attack_chain"]
    waived = run(result(chain), policy, exceptions=[db_exception(categories=["attack_chain"])])
    assert waived.decision == Decision.allow, waived.reasons
    [applied] = waived.exceptions_applied
    assert applied["finding_ids"] == [chain["finding_id"]] and applied["source"] == "database"
    assert any(r["effect"] == "exempt" and r["exception_id"] == applied["id"] for r in waived.reasons)


def test_allowlist_overrides_later_rules_but_exception_records_are_kept():
    network = finding(Code.NETWORK_EGRESS, weight=6, confidence=0.8, capability=Capability.NETWORK)
    policy = doc(deny={"codes": ["DYNAMIC_EXEC"], "vulnerabilities": {"known_exploited": True}},
                 allow={"packages": ["Sample.Pkg"]})
    res = result(dynamic_exec(), network, risk=95, vulnerabilities=[vuln("GHSA-fixture-kev", kev=True)])
    decision = run(res, policy, exceptions=[db_exception(codes=["NETWORK_EGRESS"])])
    assert decision.decision == Decision.allow and decision.matched_rules == ["allowlist"]
    assert [a["finding_ids"] for a in decision.exceptions_applied] == [[network["finding_id"]]]


# =========================================================================== confidence gating
@pytest.mark.parametrize("confidence,expected", [(0.69, Decision.allow), (0.7, Decision.block)])
def test_deny_rules_are_gated_on_min_confidence(confidence, expected):
    signal = finding(Code.DNS_EXFILTRATION, severity="medium", weight=0.5, confidence=confidence)
    decision = run(result(signal), doc(deny={"codes": ["DNS_EXFILTRATION"]}))
    assert decision.decision == expected
    if expected == Decision.allow:
        [note] = [r for r in decision.reasons if r["rule"] == "deny_rules_below_min_confidence"]
        assert note["effect"] == "info" and note["finding_ids"] == [signal["finding_id"]]


def test_blocked_capabilities_need_a_confident_finding_unless_the_capability_is_unbacked():
    weak = finding(Code.INSTALL_HOOK_EXEC, weight=1.0, confidence=0.6, capability=Capability.INSTALL_EXEC)
    assert run(result(weak, risk=10), None).decision == Decision.allow
    strong = finding(Code.INSTALL_HOOK_EXEC, severity="critical", weight=1.0, confidence=0.85,
                     capability=Capability.INSTALL_EXEC)
    decision = run(result(strong, risk=10), None)
    assert decision.decision == Decision.block and decision.matched_rules == ["blocked_capability:install_hook_exec"]
    legacy = run(result(risk=10, capabilities=[Capability.INSTALL_EXEC]), None)
    assert legacy.decision == Decision.block and legacy.reasons[0]["finding_ids"] == []


def test_signals_without_a_usable_confidence_are_evaluated_at_the_finding_default():
    legacy = {"code": "INSTALL_HOOK_EXEC", "severity": "critical", "weight": 10, "message": "x", "evidence": {},
              "capability": Capability.INSTALL_EXEC}
    assert run(result(legacy, risk=5), None).decision == Decision.block
    assert run(result({**legacy, "confidence": "very"}, risk=5), None).decision == Decision.block
    assert run(result({**legacy, "confidence": float("nan")}, risk=5), None).decision == Decision.block


def test_warn_rules_use_their_own_lower_gate():
    signal = finding(Code.STRING_RECONSTRUCTION, severity="low", weight=0.5, confidence=0.55)
    decision = run(result(signal), doc(warn={"categories": ["obfuscation"]}))
    assert decision.decision == Decision.warn and decision.matched_rules == ["warn_category:obfuscation"]


# =========================================================================== false-positive controls
def test_benign_http_client_is_allowed_by_the_production_policy():
    res = result(*BENIGN_HTTP_CLIENT, provenance={"status": "unverified", "hash_verified": True},
                 package_intel={"age_days": 400.0})
    decision = run(res, PROD)
    assert decision.decision == Decision.allow, decision.reasons


def test_cloud_sdk_reading_credentials_from_the_environment_warns_but_is_not_blocked():
    signals = (
        finding(Code.ENV_HARVEST, severity="high", weight=6.0, confidence=0.65, capability=Capability.ENV_HARVEST,
                evidence={"variables": ["AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN"]}, file="sample_pkg/session.py"),
        finding(Code.NETWORK_EGRESS, severity="low", weight=1.5, confidence=0.5, capability=Capability.NETWORK),
    )
    decision = run(result(*signals), PROD)
    assert decision.decision == Decision.warn and decision.matched_rules == ["warn_category:credential_access"]
    assert rules(decision, "block") == []


def test_native_extension_package_is_not_blocked_by_the_production_policy():
    signals = (
        finding(Code.NATIVE_CODE_LOADING, severity="low", weight=1.0, confidence=0.5,
                capability=Capability.NATIVE_CODE),
        finding(Code.BINARY_EXECUTABLE, severity="low", weight=1.0, confidence=0.35, capability=Capability.NATIVE_CODE,
                file="sample_pkg/_core.so"),
        *BENIGN_HTTP_CLIENT[1:],
    )
    decision = run(result(*signals), PROD)
    assert decision.decision == Decision.allow, decision.reasons
    assert "warn_rules_below_min_confidence" in rules(decision, "info")


def test_production_policy_warns_instead_of_allowing_when_intelligence_is_missing():
    decision = run(result(*BENIGN_HTTP_CLIENT, intel="disabled"), PROD)
    assert decision.decision == Decision.warn and decision.matched_rules == ["vulnerability_status_unknown"]


# =========================================================================== exceptions
def test_scoped_exception_waives_only_the_matching_findings():
    network = finding(Code.NETWORK_EGRESS, weight=6.0, confidence=0.8, capability=Capability.NETWORK)
    policy = doc(deny={"codes": ["NETWORK_EGRESS", "DYNAMIC_EXEC"]})
    grant = db_exception(codes=["NETWORK_EGRESS"])
    decision = run(result(network, dynamic_exec()), policy, exceptions=[grant])
    assert decision.decision == Decision.block and decision.matched_rules == ["deny_code:DYNAMIC_EXEC"]
    [applied] = decision.exceptions_applied
    assert applied["id"] == str(grant.id) and applied["finding_ids"] == [network["finding_id"]]
    assert applied["codes"] == ["NETWORK_EGRESS"] and applied["finding_count"] == 1


@pytest.mark.parametrize("status", ["pending", "rejected", "revoked", "expired", ""])
def test_only_approved_database_exceptions_apply(status):
    decision = run(result(dynamic_exec()), doc(deny={"codes": ["DYNAMIC_EXEC"]}),
                   exceptions=[db_exception(status=status)])
    assert decision.decision == Decision.block and decision.exceptions_applied == []


def test_unreviewed_or_unsupported_exception_objects_never_apply():
    policy = doc(deny={"codes": ["DYNAMIC_EXEC"]})
    unreviewed = {"package": "sample-pkg", "codes": ["DYNAMIC_EXEC"],
                  "expires_at": (NOW + timedelta(days=1)).isoformat()}  # no status: treated as pending
    assert run(result(dynamic_exec()), policy, exceptions=[unreviewed]).decision == Decision.block
    approved_by_nobody = {**unreviewed, "status": "approved"}
    assert run(result(dynamic_exec()), policy, exceptions=[approved_by_nobody]).decision == Decision.block
    reviewed = {**unreviewed, "status": "approved", "requested_by": "dev-1", "approved_by": "sec-1"}
    assert run(result(dynamic_exec()), policy, exceptions=[reviewed]).decision == Decision.allow
    self_approved = {**reviewed, "approved_by": "dev-1"}
    assert run(result(dynamic_exec()), policy, exceptions=[self_approved]).decision == Decision.block
    # Rows written around the two-person workflow (no approver, or the requester approving) never apply.
    requester = uuid.uuid4()
    for row in (db_exception(approved_by=None), db_exception(requested_by=requester, approved_by=requester)):
        assert run(result(dynamic_exec()), policy, exceptions=[row]).decision == Decision.block
    with pytest.raises(TypeError):
        run(result(), policy, exceptions=[object()])


def test_database_exception_expiry_is_exclusive_and_timezone_aware():
    expires = datetime(2026, 10, 1, tzinfo=UTC)
    policy = doc(deny={"codes": ["DYNAMIC_EXEC"]})
    grant = db_exception(expires_at=expires, codes=["DYNAMIC_EXEC"])

    def decide(now: datetime, row: PolicyException = grant) -> Decision:
        return run(result(dynamic_exec()), policy, exceptions=[row], now=now).decision

    assert decide(expires - timedelta(microseconds=1)) == Decision.allow
    assert decide(expires) == Decision.block
    assert decide(datetime(2026, 10, 1, 5, 29, 59, tzinfo=IST)) == Decision.allow  # 23:59:59 UTC
    assert decide(datetime(2026, 10, 1, 5, 30, tzinfo=IST)) == Decision.block  # 00:00:00 UTC
    naive_row = db_exception(expires_at=expires.replace(tzinfo=None), codes=["DYNAMIC_EXEC"])  # SQLite reads naive UTC
    assert decide(expires - timedelta(seconds=1), naive_row) == Decision.allow
    assert decide(expires, naive_row) == Decision.block


def test_document_exception_stops_at_midnight_utc_on_its_expiry_date():
    policy = doc(deny={"codes": ["DYNAMIC_EXEC"]},
                 exceptions=[{"package": "Sample_Pkg", "codes": ["DYNAMIC_EXEC"], "expires": "2026-10-01",
                              "reason": "Template engine compiles trusted templates (fixture)"}])

    def decide(now: datetime) -> PolicyDecision:
        return run(result(dynamic_exec()), policy, now=now)

    active = decide(datetime(2026, 9, 30, 23, 59, 59, 999999, tzinfo=UTC))
    assert active.decision == Decision.allow
    assert active.exceptions_applied[0]["source"] == "policy_document"
    assert active.exceptions_applied[0]["id"].startswith("policy:")
    assert decide(datetime(2026, 10, 1, tzinfo=UTC)).decision == Decision.block
    assert decide(datetime(2026, 10, 1, 4, 0, tzinfo=IST)).decision == Decision.allow  # 22:30 UTC on 30 Sep
    assert decide(datetime(2026, 10, 1, 0, 0)).decision == Decision.block  # naive "now" is UTC


@pytest.mark.parametrize("version,covered", [
    ("1.9.9", True), ("2.0", False), ("2.0rc1", False), ("1.5rc1", True), ("not-a-version", False),
])
def test_version_scoped_exception(version, covered):
    grant = db_exception(version_spec="<2.0", codes=["DYNAMIC_EXEC"])
    decision = run(result(dynamic_exec(), version=version), doc(deny={"codes": ["DYNAMIC_EXEC"]}), exceptions=[grant])
    assert (decision.decision == Decision.allow) is covered


def test_version_matching_fails_towards_not_covered():
    assert version_matches(None, "anything") and version_matches("", "1.0")
    assert not version_matches("<2.0", None)
    assert not version_matches("latest please", "1.0")
    assert not version_matches(">=1.0", "1.0; rm -rf /")


def test_environment_and_policy_scoped_exceptions():
    policy_id = uuid.uuid4()
    row = Policy(id=policy_id, name="scoped", environment="staging",
                 document=doc(deny={"codes": ["DYNAMIC_EXEC"]}).with_environment("staging").to_dict())
    staging_only = db_exception(environment="staging", codes=["DYNAMIC_EXEC"])
    assert run(result(dynamic_exec()), row, exceptions=[staging_only]).decision == Decision.allow
    assert run(result(dynamic_exec()), row, exceptions=[staging_only], environment="production").decision \
        == Decision.block
    for_this_policy = db_exception(policy_id=policy_id, codes=["DYNAMIC_EXEC"])
    assert run(result(dynamic_exec()), row, exceptions=[for_this_policy]).decision == Decision.allow
    for_another_policy = db_exception(policy_id=uuid.uuid4(), codes=["DYNAMIC_EXEC"])
    assert run(result(dynamic_exec()), row, exceptions=[for_another_policy]).decision == Decision.block
    # A policy without an id (built-in default, bare document) only receives global exceptions.
    assert run(result(dynamic_exec()), doc(deny={"codes": ["DYNAMIC_EXEC"]}),
               exceptions=[for_this_policy]).decision == Decision.block


def test_unscoped_exception_waives_everything_but_non_overridables_and_ignores_the_ml_score():
    encoded = finding(Code.ENCODED_EXEC, severity="critical", weight=12, confidence=0.9,
                      capability=Capability.OBFUSCATION, line=3)
    res = result(dynamic_exec(), encoded, risk=88, ml_score=88, ml_available=True,
                 capabilities=[Capability.DYNAMIC_EXEC, Capability.OBFUSCATION, Capability.INSTALL_EXEC])
    policy = doc(deny={"capabilities": ["install_hook_exec"], "codes": ["ENCODED_EXEC"]},
                 require={"provenance": ["attested"]})
    blocked = run(res, policy)
    assert {"deny_code:ENCODED_EXEC", "blocked_capability:install_hook_exec", "block_threshold"} \
        <= set(blocked.matched_rules)
    waived = run(res, policy, exceptions=[db_exception()])
    assert waived.decision == Decision.allow, waived.reasons
    [applied] = waived.exceptions_applied
    assert applied["capabilities"] == ["install_hook_exec"] and applied["finding_count"] == 2
    assert any(r["rule"] == "risk_score_after_exceptions" and "88 -> 0" in r["detail"] for r in waived.reasons)
    assert "requirement_waived:provenance" in rules(waived, "exempt")


def test_scoped_exception_keeps_the_ml_score_and_the_critical_floor():
    grant = db_exception(codes=["DYNAMIC_EXEC"])
    ml_driven = run(result(dynamic_exec(), risk=75, ml_score=75, ml_available=True), doc(), exceptions=[grant])
    assert ml_driven.decision == Decision.block and ml_driven.matched_rules == ["block_threshold"]
    pth = finding(Code.PTH_STARTUP_HOOK, severity="critical", weight=10, confidence=0.95, file="sample.pth")
    floored = run(result(dynamic_exec(), pth, risk=80), doc(), exceptions=[grant])
    assert floored.decision == Decision.block and floored.matched_rules == ["block_threshold"]


def test_waiving_one_vulnerability_code_does_not_hide_a_kev_listing():
    record = vuln("GHSA-fixture-0001", severity="high", kev=True, cvss_score=8.1)
    res = result(vuln_finding(record), vuln_finding(record, Code.KNOWN_EXPLOITED_VULNERABILITY), risk=90,
                 vulnerabilities=[record])
    policy = doc(deny={"vulnerabilities": {"known_exploited": True}})
    partial = run(res, policy, exceptions=[db_exception(codes=["KNOWN_VULNERABILITY"])])
    assert partial.decision == Decision.block and "deny_vulnerability:known_exploited" in partial.matched_rules
    waived = run(res, policy, exceptions=[db_exception(categories=["vulnerability"])])
    assert waived.decision == Decision.allow, waived.reasons
    assert waived.exceptions_applied[0]["vulnerability_ids"] == ["GHSA-fixture-0001"]


def test_excepted_provenance_finding_waives_the_provenance_requirement():
    failed = finding(Code.PROVENANCE_FAILED, weight=5.0, confidence=0.9)
    res = result(failed, provenance={"status": "failed"}, risk=22)
    policy = doc(require={"provenance": ["attested"]})
    assert run(res, policy).matched_rules == ["requirement:provenance"]
    waived = run(res, policy, exceptions=[db_exception(codes=["PROVENANCE_FAILED"])])
    assert waived.decision == Decision.allow and "requirement_waived:provenance" in rules(waived, "exempt")


# =========================================================================== vulnerability rules
@pytest.mark.parametrize("record,expected", [
    pytest.param(vuln("GHSA-fixture-kev", kev=True, severity="medium", cvss_score=5.0),
                 ["deny_vulnerability:known_exploited"], id="kev"),
    pytest.param(vuln("GHSA-fixture-crit", severity="critical"),
                 ["deny_vulnerability:severity", "deny_vulnerability:cvss"], id="critical-label-implies-cvss-band"),
    pytest.param(vuln("GHSA-fixture-score", cvss_score=9.8),
                 ["deny_vulnerability:severity", "deny_vulnerability:cvss"], id="cvss-implies-severity"),
])
def test_vulnerability_deny_rules(record, expected):
    policy = doc(deny={"vulnerabilities": {"known_exploited": True, "min_severity": "critical", "min_cvss": 9.0}})
    decision = run(result(vulnerabilities=[record]), policy)
    assert decision.decision == Decision.block and decision.matched_rules == expected
    assert decision.reasons[0]["vulnerability_ids"] == [record["id"]]


def test_high_vulnerability_without_cvss_is_decided_from_its_severity_band():
    policy = doc(deny={"vulnerabilities": {"min_severity": "critical", "min_cvss": 9.0}},
                 warn={"vulnerabilities": {"min_severity": "high"}})
    decision = run(result(vulnerabilities=[vuln("GHSA-fixture-high", severity="high")]), policy)
    assert decision.decision == Decision.warn and decision.matched_rules == ["warn_vulnerability:severity"]
    assert all(r["rule"] != "vulnerability_status_unknown" for r in decision.reasons)


def test_missing_vulnerability_data_warns_instead_of_allowing():
    policy = doc(deny={"vulnerabilities": {"min_cvss": 7.5, "min_epss": 0.5}})
    decision = run(result(vulnerabilities=[vuln("GHSA-fixture-nodata", severity="high")]), policy)
    assert decision.decision == Decision.warn and decision.matched_rules == ["vulnerability_status_unknown"]
    assert decision.reasons[0]["vulnerability_ids"] == ["GHSA-fixture-nodata"]


@pytest.mark.parametrize("intel", ["unavailable", "partial", "disabled", "not_run", None])
def test_unknown_vulnerability_intelligence_never_silently_allows(intel):
    decision = run(result(intel=intel), doc(deny={"vulnerabilities": {"known_exploited": True}}))
    assert decision.decision == Decision.warn and decision.matched_rules == ["vulnerability_status_unknown"]


def test_known_exploited_vulnerability_blocks_even_when_intelligence_is_partial():
    decision = run(result(vulnerabilities=[vuln("GHSA-fixture-kev", kev=True)], intel="partial"),
                   doc(deny={"vulnerabilities": {"known_exploited": True}}))
    assert decision.decision == Decision.block and decision.matched_rules == ["deny_vulnerability:known_exploited"]
    assert "vulnerability_status_unknown" in rules(decision, "warn")


def test_warn_level_vulnerability_rule_with_unknown_intelligence_is_informational():
    decision = run(result(intel="unavailable"), doc(warn={"vulnerabilities": {"min_severity": "high"}}))
    assert decision.decision == Decision.allow and "vulnerability_status_unknown" in rules(decision, "info")


def test_withdrawn_advisories_are_ignored():
    record = vuln("GHSA-fixture-withdrawn", kev=True, withdrawn=True)
    assert run(result(vulnerabilities=[record]), doc(deny={"vulnerabilities": {"known_exploited": True}})).decision \
        == Decision.allow


def test_cvss_criterion_uses_the_severity_band_only_when_it_is_decisive():
    assert vulnerability_criteria(vuln("a", severity="high"), VulnerabilityRule(min_cvss=7.0)) == {"cvss": True}
    assert vulnerability_criteria(vuln("a", severity="medium"), VulnerabilityRule(min_cvss=7.0)) == {"cvss": False}
    assert vulnerability_criteria(vuln("a", severity="high"), VulnerabilityRule(min_cvss=8.0)) == {"cvss": None}
    assert vulnerability_criteria(vuln("a", cvss_score=float("nan")), VulnerabilityRule(min_severity="low")) \
        == {"severity": None}
    assert vulnerability_criteria(vuln("a", kev="yes"), VulnerabilityRule(known_exploited=True)) \
        == {"known_exploited": False}


# =========================================================================== requirements
@pytest.mark.parametrize("status,decision,rule", [
    ("attested", Decision.allow, "clean"),
    ("unverified", Decision.block, "requirement:provenance"),
    ("failed", Decision.block, "requirement:provenance"),
    ("not_run", Decision.warn, "provenance_status_unknown"),
    (None, Decision.warn, "provenance_status_unknown"),
    ("something-new", Decision.warn, "provenance_status_unknown"),
])
def test_provenance_requirement(status, decision, rule):
    provenance = {} if status is None else {"status": status}
    outcome = run(result(provenance=provenance), doc(require={"provenance": ["attested"]}))
    assert outcome.decision == decision and outcome.matched_rules == [rule]


def test_provenance_requirement_may_accept_several_states():
    policy = doc(require={"provenance": ["attested", "unverified"]})
    assert run(result(provenance={"status": "unverified"}), policy).decision == Decision.allow


@pytest.mark.parametrize("provenance,package_intel,expected", [
    ({"hash_verified": True}, {}, Decision.allow),
    ({"hash_verified": False}, {}, Decision.block),
    ({"hash_verified": None}, {}, Decision.warn),
    ({}, {"artifact": {"hash_verified": True}}, Decision.allow),
    ({}, {}, Decision.warn),
])
def test_hash_verification_requirement(provenance, package_intel, expected):
    decision = run(result(provenance=provenance, package_intel=package_intel), doc(require={"hash_verified": True}))
    assert decision.decision == expected


@pytest.mark.parametrize("scan_options,expected", [
    ({"project_context": {"sbom": True}}, Decision.allow),
    ({"project_context": {"sbom": False}}, Decision.block),
    ({}, Decision.warn),
])
def test_sbom_requirement(scan_options, expected):
    assert run(result(scan_options=scan_options), doc(require={"sbom": True})).decision == expected


@pytest.mark.parametrize("package_intel,signals,expected", [
    ({"age_days": 2.5}, (), Decision.block),
    ({"age_days": 10.0}, (), Decision.allow),
    ({"age_days": None}, (), Decision.warn),
    ({}, (finding(Code.NEW_PACKAGE, severity="medium", weight=4.0, confidence=0.4, evidence={"age_days": 1.0}),),
     Decision.block),
])
def test_minimum_release_age(package_intel, signals, expected):
    decision = run(result(*signals, package_intel=package_intel, risk=0), doc(min_package_age_days=7))
    assert decision.decision == expected


# =========================================================================== fail-safe behaviour
def test_invalid_stored_document_fails_closed():
    broken = {"apiVersion": "warden.dev/v1", "kind": "Policy", "metadata": {"name": "broken"},
              "spec": {"thresholds": {"warn": "forty"}}}
    decision = run(result(), Policy(name="broken", environment="production", document=broken))
    assert decision.decision == Decision.block and decision.matched_rules == ["policy_document_invalid"]
    assert len(decision.policy_hash) == 64


def test_malformed_results_do_not_crash_the_engine():
    res = AnalysisResult(
        "pypi", "odd-pkg", "1.0", 0, 0, float("nan"), "info", {},
        [None, "text", {"code": 42, "confidence": float("inf"), "evidence": ["x"]}, {"no": "code"}],
        "1", 1, False, capabilities=[None, 7, "network_egress"], vulnerabilities=["junk", {"id": None, "kev": "yes"}],
        intel_status="not-a-dict", provenance=["bad"], package_intel="bad", scan_options=None,
    )
    decision = run(res, PROD)
    assert decision.decision == Decision.warn and decision.matched_rules == ["vulnerability_status_unknown"]


def test_oversized_results_fail_closed(monkeypatch):
    monkeypatch.setattr(engine_module, "MAX_EVALUATED_FINDINGS", 3)
    signals = [finding(Code.DANGEROUS_IMPORT, severity="low", weight=0.1, confidence=0.4, line=i) for i in range(1, 6)]
    decision = run(result(*signals), doc())
    assert decision.decision == Decision.block and decision.matched_rules == ["evaluation_limits_exceeded"]


# =========================================================================== database loader
@pytest.fixture()
def session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'exceptions.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    with factory() as db:
        yield db
    engine.dispose()


def test_load_active_exceptions_filters_status_expiry_scope_and_version(session):
    requester = User(id=uuid.uuid4(), email="loader-requester@warden.io", password_hash="unused", role=Role.developer)
    approver = User(id=uuid.uuid4(), email="loader-approver@warden.io", password_hash="unused",
                    role=Role.security_analyst)
    this_policy = Policy(id=uuid.uuid4(), name="loader-prod", environment="production")
    other_policy = Policy(id=uuid.uuid4(), name="loader-staging", environment="staging")
    session.add_all([requester, approver, this_policy, other_policy])
    session.flush()

    def add(**fields) -> PolicyException:
        row = dict(id=uuid.uuid4(), package="sample-pkg", codes=["DYNAMIC_EXEC"], categories=[],
                   justification="Loader fixture exception", requested_by=requester.id, approved_by=approver.id,
                   status="approved", expires_at=NOW + timedelta(days=10))
        row.update(fields)
        exception = PolicyException(**row)
        session.add(exception)
        return exception

    applicable = [add(), add(environment="production"), add(policy_id=this_policy.id), add(version_spec="<2.0")]
    add(status="pending")
    add(status="revoked")
    add(expires_at=NOW - timedelta(seconds=1))
    add(expires_at=NOW)  # expiry is exclusive
    add(environment="staging")
    add(policy_id=other_policy.id)
    add(version_spec=">=2.0")
    add(package="other-pkg")
    add(approved_by=None)  # "approved" without an approver
    add(approved_by=requester.id)  # self-approved
    session.commit()

    grants = load_active_exceptions(session, "Sample_Pkg", "1.4.0", "production", this_policy.id, NOW)
    assert sorted(g.id for g in grants) == sorted(str(r.id) for r in applicable)
    assert all(g.source == "database" and g.expires_at.tzinfo is not None for g in grants)
    global_only = load_active_exceptions(session, "sample-pkg", "1.4.0", None, None, NOW)
    assert sorted(g.id for g in global_only) == sorted(
        str(r.id) for r in applicable if r.environment is None and r.policy_id is None)
    decision = run(result(dynamic_exec()), doc(deny={"codes": ["DYNAMIC_EXEC"]}), exceptions=global_only)
    assert decision.decision == Decision.allow and len(decision.exceptions_applied) == 1
