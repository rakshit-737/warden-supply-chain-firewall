"""Policy-as-code documents: strict validation, normalisation, hashing and hostile-input parsing.

Every document here is hand-written in the warden.dev/v1 format for these tests (fixtures, not
real organisational policies). Parsing tests are adversarial: alias bombs, duplicate keys, Python
object tags, oversized and deeply nested input, secrets and control characters in values.
"""

from __future__ import annotations

import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.analysis.signals import Capability
from app.db.models import Policy
from app.policy.document import (
    MAX_POLICY_BYTES,
    PolicyDocumentError,
    canonical_json,
    effective_policy,
    from_legacy,
    load_policy_text,
    policy_hash,
    validate_policy_data,
    validate_policy_text,
)
from app.policy.engine import DEFAULT_POLICY

TODAY = date(2026, 9, 16)
POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"

SPEC_EXAMPLE = """\
apiVersion: warden.dev/v1
kind: Policy
metadata: {name: prod-strict, environment: production}
spec:
  thresholds: {warn: 40, block: 70}
  min_package_age_days: 0
  deny:
    packages: [Evil_Pkg, evil.pkg]
    codes: [IOC_MATCH, PTH_STARTUP_HOOK, ioc_match]
    categories: [malicious_behavior, attack_chain, dependency_confusion]
    capabilities: [install_hook_exec, ioc]
    vulnerabilities: {known_exploited: true, min_severity: critical, min_cvss: 9.0, min_epss: null}
    min_confidence: 0.7
  warn: {codes: [], categories: [capability], vulnerabilities: {min_severity: high}}
  require: {provenance: null, hash_verified: false, sbom: false}
  allow: {packages: []}
  exceptions:
    - {package: Internal_Package, version: " <2.0 ", codes: [], categories: [], expires: 2026-12-01,
       reason: "Internal mirror package reviewed by the platform team", approved_by: "sec-team"}
"""


def _base(**spec) -> dict:
    return {"apiVersion": "warden.dev/v1", "kind": "Policy",
            "metadata": {"name": "fixture", "environment": "production"}, "spec": spec}


def _exc(**overrides) -> dict:
    entry = {"package": "internal-tool", "expires": (TODAY + timedelta(days=30)).isoformat(),
             "reason": "Reviewed internal build tool"}
    entry.update(overrides)
    return entry


# =========================================================================== valid documents
def test_spec_example_validates_and_is_normalised():
    outcome = validate_policy_text(SPEC_EXAMPLE, today=TODAY)
    assert outcome.valid, outcome.errors
    spec = outcome.normalized["spec"]
    assert spec["deny"]["packages"] == ["evil-pkg"]  # PEP 503 normalised and de-duplicated
    assert spec["deny"]["codes"] == ["IOC_MATCH", "PTH_STARTUP_HOOK"]
    assert spec["deny"]["min_confidence"] == 0.7 and spec["warn"]["min_confidence"] == 0.5
    assert spec["exceptions"] == [{
        "package": "internal-package", "version": "<2.0", "codes": [], "categories": [], "expires": "2026-12-01",
        "reason": "Internal mirror package reviewed by the platform team", "approved_by": "sec-team",
    }]
    assert outcome.document.spec.exceptions[0].expires_at == datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert outcome.policy_hash == policy_hash(outcome.normalized) and len(outcome.policy_hash) == 64
    assert any("vulnerability intelligence" in warning for warning in outcome.warnings)


def test_hash_ignores_key_order_list_order_and_source_format():
    from_yaml = load_policy_text(SPEC_EXAMPLE, today=TODAY)
    data = from_yaml.to_dict()
    reordered = {
        "spec": {key: data["spec"][key] for key in reversed(list(data["spec"]))},
        "metadata": data["metadata"], "kind": "Policy", "apiVersion": "warden.dev/v1",
    }
    reordered["spec"]["deny"] = {**data["spec"]["deny"], "codes": list(reversed(data["spec"]["deny"]["codes"]))}
    from_json = load_policy_text(json.dumps(reordered), "json", today=TODAY)
    assert canonical_json(from_json) == canonical_json(from_yaml)
    assert from_json.policy_hash == from_yaml.policy_hash
    # Normalisation is idempotent: validating the normalised form yields the same hash.
    assert validate_policy_data(from_yaml.to_dict(), today=TODAY).policy_hash == from_yaml.policy_hash
    stricter = json.loads(json.dumps(data))
    stricter["spec"]["thresholds"]["block"] = 60
    assert load_policy_text(json.dumps(stricter), today=TODAY).policy_hash != from_yaml.policy_hash


def test_errors_report_the_path_and_the_yaml_line():
    text = SPEC_EXAMPLE.replace("PTH_STARTUP_HOOK", "PTH_STARTUP_HOK").replace(
        "    min_confidence: 0.7\n", "    min_confidence: 0.7\n    mode: strict\n")
    outcome = validate_policy_text(text, today=TODAY)
    assert not outcome.valid and outcome.document is None and outcome.normalized is None
    errors = {e["loc"]: e for e in outcome.errors}
    assert "unknown finding code" in errors["spec.deny.codes.1"]["msg"] and errors["spec.deny.codes.1"]["line"] == 9
    assert "unknown field" in errors["spec.deny.mode"]["msg"] and errors["spec.deny.mode"]["line"] == 14
    with pytest.raises(PolicyDocumentError) as raised:
        load_policy_text(text, today=TODAY)
    assert raised.value.errors == outcome.errors


INVALID_SPECS = [
    pytest.param({"deny": {"categories": ["malware"]}}, "spec.deny.categories.0", id="unknown-category"),
    pytest.param({"deny": {"capabilities": ["telepathy"]}}, "spec.deny.capabilities.0", id="unknown-capability"),
    pytest.param({"warn": {"codes": ["network egress"]}}, "spec.warn.codes.0", id="code-shape"),
    pytest.param({"deny": {"packages": ["../../etc/passwd"]}}, "spec.deny.packages.0", id="package-traversal"),
    pytest.param({"allow": {"packages": ["evil pkg; rm -rf /"]}}, "spec.allow.packages.0", id="package-shell"),
    pytest.param({"thresholds": {"warn": 80, "block": 70}}, "spec.thresholds", id="warn-above-block"),
    pytest.param({"thresholds": {"warn": "40"}}, "spec.thresholds.warn", id="threshold-string"),
    pytest.param({"thresholds": {"block": True}}, "spec.thresholds.block", id="threshold-bool"),
    pytest.param({"thresholds": {"block": 101}}, "spec.thresholds.block", id="threshold-range"),
    pytest.param({"deny": {"min_confidence": 1.5}}, "spec.deny.min_confidence", id="confidence-range"),
    pytest.param({"warn": {"min_confidence": True}}, "spec.warn.min_confidence", id="confidence-bool"),
    pytest.param({"deny": {"vulnerabilities": {"min_severity": "severe"}}},
                 "spec.deny.vulnerabilities.min_severity", id="unknown-severity"),
    pytest.param({"deny": {"vulnerabilities": {"min_cvss": 11}}}, "spec.deny.vulnerabilities.min_cvss",
                 id="cvss-range"),
    pytest.param({"deny": {"vulnerabilities": {"known_exploited": "yes"}}},
                 "spec.deny.vulnerabilities.known_exploited", id="kev-string"),
    pytest.param({"require": {"provenance": []}}, "spec.require.provenance", id="empty-provenance-states"),
    pytest.param({"require": {"provenance": ["signed"]}}, "spec.require.provenance.0", id="unknown-provenance-state"),
    pytest.param({"min_package_age_days": -1}, "spec.min_package_age_days", id="negative-age"),
    pytest.param({"deny": {"packages": ["left-pad"]}, "allow": {"packages": ["Left_Pad"]}}, "spec",
                 id="denied-and-allowed"),
    pytest.param({"exceptions": [{"package": "x", "reason": "Reviewed by the security team"}]},
                 "spec.exceptions.0.expires", id="exception-without-expiry"),
    pytest.param({"exceptions": [{"package": "x", "expires": "2026-10-01"}]}, "spec.exceptions.0.reason",
                 id="exception-without-reason"),
    pytest.param({"exceptions": [_exc(reason="   too short   ")]}, "spec.exceptions.0.reason", id="short-reason"),
    pytest.param({"exceptions": [_exc(codes=["IOC_MATCH"])]}, "spec.exceptions.0.codes.0", id="exception-ioc"),
    pytest.param({"exceptions": [_exc(codes=["hash_mismatch"])]}, "spec.exceptions.0.codes.0",
                 id="exception-hash-mismatch"),
    pytest.param({"exceptions": [_exc(version="1.2.3")]}, "spec.exceptions.0.version", id="bare-version"),
    pytest.param({"exceptions": [_exc(version="<2.0; rm -rf /")]}, "spec.exceptions.0.version", id="version-injection"),
    pytest.param({"exceptions": [_exc(expires=1790000000)]}, "spec.exceptions.0.expires", id="expiry-timestamp"),
    pytest.param({"exceptions": [_exc(expires="2026-10-01T10:30:00")]}, "spec.exceptions.0.expires",
                 id="expiry-with-time-of-day"),
    pytest.param({"exceptions": [_exc(scope="all")]}, "spec.exceptions.0.scope", id="exception-unknown-field"),
    pytest.param({"unknown": 1}, "spec.unknown", id="unknown-spec-field"),
]


@pytest.mark.parametrize("spec,loc", INVALID_SPECS)
def test_invalid_documents_are_rejected_at_their_location(spec, loc):
    outcome = validate_policy_data(_base(**spec), today=TODAY)
    assert not outcome.valid and outcome.document is None and outcome.policy_hash is None
    assert loc in {e["loc"] for e in outcome.errors}, outcome.errors


@pytest.mark.parametrize("mutate,loc", [
    pytest.param(lambda d: d.update(apiVersion="warden.dev/v2"), "apiVersion", id="api-version"),
    pytest.param(lambda d: d.update(api_version=d.pop("apiVersion")), "apiVersion", id="snake-case-api-version"),
    pytest.param(lambda d: d.update(kind="Policies"), "kind", id="kind"),
    pytest.param(lambda d: d.pop("spec"), "spec", id="missing-spec"),
    pytest.param(lambda d: d["metadata"].update(name="\x1b[31mprod"), "metadata.name", id="control-chars-in-name"),
    pytest.param(lambda d: d["metadata"].update(environment="prod"), "metadata.environment", id="unknown-environment"),
])
def test_invalid_document_envelopes_are_rejected(mutate, loc):
    data = _base()
    mutate(data)
    outcome = validate_policy_data(data, today=TODAY)
    assert loc in {e["loc"] for e in outcome.errors}, outcome.errors


def test_exception_expiry_window_boundary():
    assert validate_policy_data(_base(exceptions=[_exc(expires=(TODAY + timedelta(days=365)).isoformat())]),
                                today=TODAY).valid
    [error] = validate_policy_data(_base(exceptions=[_exc(expires=(TODAY + timedelta(days=366)).isoformat())]),
                                   today=TODAY).errors
    assert error["loc"] == "spec.exceptions.0.expires" and "365" in error["msg"]
    lapsed = validate_policy_data(_base(exceptions=[_exc(expires=TODAY.isoformat())]), today=TODAY)
    assert lapsed.valid and any("expired" in warning for warning in lapsed.warnings)


def test_error_messages_escape_control_characters_and_redact_secrets():
    data = _base(deny={"codes": ["AKIAIOSFODNN7EXAMPLE"]})
    data["spec"]["\x1b[2Jevil"] = 1
    outcome = validate_policy_data(data, today=TODAY)
    assert not outcome.valid
    for error in outcome.errors:
        assert "AKIAIOSFODNN7EXAMPLE" not in error["msg"] and "\x1b" not in error["loc"] + error["msg"]
    assert "spec.<key>" in {e["loc"] for e in outcome.errors}


# =========================================================================== hostile text
def test_yaml_alias_bomb_is_rejected_before_expansion():
    lines = ['a0: &a0 ["lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol", "lol"]']
    lines += [f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 9) + "]" for i in range(1, 10)]
    started = time.monotonic()
    outcome = validate_policy_text("\n".join(lines))
    assert time.monotonic() - started < 2.0
    [error] = outcome.errors
    assert "aliases are not allowed" in error["msg"] and error["line"] == 2


@pytest.mark.parametrize("text,fragment", [
    pytest.param("apiVersion: warden.dev/v1\nkind: Policy\nkind: Policy\n", "duplicate key", id="yaml-duplicate-key"),
    pytest.param('{"apiVersion": "warden.dev/v1", "apiVersion": "x"}', "duplicate key", id="json-duplicate-key"),
    pytest.param("base: &b {warn: 1}\nspec:\n  <<: *b\n", "aliases", id="merge-via-alias"),
    pytest.param("spec:\n  <<: {warn: 1}\n", "merge keys", id="inline-merge-key"),
    pytest.param("!!python/object/apply:os.system ['echo pwned']\n", "constructor", id="python-object-tag"),
    pytest.param("apiVersion: warden.dev/v1\n---\napiVersion: warden.dev/v1\n", "another document", id="multi-doc"),
    pytest.param('{"spec": {"thresholds": {"warn": NaN}}}', "NaN", id="json-nan"),
    pytest.param("- just\n- a\n- list\n", "mapping", id="non-mapping-root"),
    pytest.param("spec: {thresholds: {warn: 1}\n", "line", id="syntax-error"),
])
def test_hostile_or_malformed_text_is_rejected(text, fragment):
    outcome = validate_policy_text(text)
    assert not outcome.valid
    assert fragment in " ".join(f"{e['loc']} {e['msg']}" for e in outcome.errors), outcome.errors


def test_python_tags_are_never_executed(monkeypatch):
    monkeypatch.delenv("WARDEN_POLICY_PWNED", raising=False)
    payload = "!!python/object/apply:builtins.exec [\"import os; os.environ['WARDEN_POLICY_PWNED'] = '1'\"]\n"
    assert not validate_policy_text(payload).valid
    assert "WARDEN_POLICY_PWNED" not in os.environ


def test_oversized_and_deeply_nested_input_is_bounded():
    assert "exceeds" in validate_policy_text("a: '" + "x" * (MAX_POLICY_BYTES + 1) + "'\n").errors[0]["msg"]
    multibyte = "a: '" + "\u00e9" * (MAX_POLICY_BYTES // 2 + 1) + "'"  # fewer characters than bytes
    assert len(multibyte) < MAX_POLICY_BYTES
    assert "exceeds" in validate_policy_text(multibyte).errors[0]["msg"]
    assert "exceeds" in validate_policy_text(b"a" * (MAX_POLICY_BYTES + 1)).errors[0]["msg"]
    assert "nested" in validate_policy_text("[" * 5000).errors[0]["msg"]
    assert "nested" in validate_policy_text('{"a":' * 5000 + "1" + "}" * 5000, "json").errors[0]["msg"]
    assert "nested" in validate_policy_text("a:\n" + "".join("  " * i + "- \n" for i in range(1, 30))).errors[0]["msg"]
    nested: dict = {}
    cursor = nested
    for _ in range(40):
        cursor["x"] = {}
        cursor = cursor["x"]
    assert "nested deeper" in validate_policy_data(nested).errors[0]["msg"]
    assert "UTF-8" in validate_policy_text(b"\xff\xfe apiVersion").errors[0]["msg"]


# =========================================================================== legacy / stored policies
def test_from_legacy_maps_v1_columns():
    row = Policy(name="legacy", environment="staging", warn_threshold=30, block_threshold=60, min_package_age_days=2,
                 blocked_capabilities=["INSTALL_HOOK_EXEC", "not a capability!"], allowlist=["Good_Pkg"],
                 denylist=["Evil.Pkg"])
    doc = from_legacy(row)
    spec = doc.spec
    assert (spec.thresholds.warn, spec.thresholds.block, spec.min_package_age_days) == (30, 60, 2)
    assert spec.deny.capabilities == ["install_hook_exec"]  # not-capability-shaped entries can never match
    assert spec.deny.packages == ["evil-pkg"] and spec.allow.packages == ["good-pkg"]
    assert spec.deny.min_confidence == 0.7 and doc.metadata.environment == "staging"
    # Column defaults are not applied to transient rows: v1 defaults are used instead.
    assert from_legacy(Policy(name="bare")).spec.thresholds.block == 70
    builtin = from_legacy({"name": "builtin", **DEFAULT_POLICY})
    assert builtin.spec.deny.capabilities == sorted([Capability.INSTALL_EXEC, Capability.IOC])
    # v1 rows were never checked for warn <= block by the database; they still convert.
    assert from_legacy({"name": "odd", "warn_threshold": 80, "block_threshold": 60}).spec.thresholds.warn == 80


def test_stored_documents_are_read_leniently_but_structural_damage_is_reported():
    data = _base(deny={"codes": ["IOC_MATCH", "CODE_FROM_A_LATER_RELEASE"]})
    assert not validate_policy_data(data).valid  # strict (API) validation refuses the unknown code
    stored = effective_policy(Policy(name="stored", document=data))
    assert stored.valid and stored.source == "document"
    assert "CODE_FROM_A_LATER_RELEASE" in stored.document.spec.deny.codes
    broken = {**data, "kind": "Pollcy"}
    first, second = effective_policy(Policy(name="x", document=broken)), effective_policy(Policy(document=broken))
    assert not first.valid and first.errors and len(first.policy_hash) == 64
    assert first.policy_hash == second.policy_hash
    legacy = effective_policy(Policy(name="legacy", blocked_capabilities=["ioc"]))
    assert legacy.valid and legacy.source == "legacy"


# =========================================================================== shipped policies
@pytest.mark.parametrize("environment", ["production", "staging", "development"])
def test_shipped_policy_files_validate_strictly(environment):
    outcome = validate_policy_text((POLICIES_DIR / f"{environment}.yaml").read_text(encoding="utf-8"))
    assert outcome.valid, outcome.errors
    assert outcome.document.metadata.environment == environment
    assert outcome.document.spec.exceptions == []


def test_shipped_policies_get_stricter_towards_production():
    prod, staging, dev = (load_policy_text((POLICIES_DIR / f"{env}.yaml").read_text(encoding="utf-8"))
                          for env in ("production", "staging", "development"))
    deny = prod.spec.deny
    assert deny.min_confidence == 0.7
    assert {"malicious_behavior", "attack_chain", "ioc", "dependency_confusion"} <= set(deny.categories)
    assert deny.vulnerabilities.known_exploited and deny.vulnerabilities.min_severity == "critical"
    assert prod.spec.thresholds.block <= staging.spec.thresholds.block <= dev.spec.thresholds.block
    assert deny.min_confidence <= staging.spec.deny.min_confidence <= dev.spec.deny.min_confidence
    assert staging.spec.deny.vulnerabilities.known_exploited
    assert not dev.spec.deny.vulnerabilities.configured and dev.spec.warn.vulnerabilities.configured
    # Capability findings (network, subprocess) are common in benign libraries: never a warn/deny category.
    for doc in (prod, staging, dev):
        assert "capability" not in doc.spec.warn.categories and "capability" not in doc.spec.deny.categories
