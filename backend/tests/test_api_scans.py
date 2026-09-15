"""End-to-end API tests for the scan flow, with a deterministic fake orchestrator so no
network access is required."""

import uuid

import pytest
from sqlalchemy import select

from app.analysis.findings import Finding, Location
from app.analysis.orchestrator import AnalysisResult
from app.analysis.signals import Capability, Code
from app.api.routers import scans as scans_router
from app.core import cache as cache_module
from app.db.models import SecurityEvent, Signal
from app.db.session import SessionLocal
from tests.conftest import auth


class _FakeOrchestrator:
    """Returns a scripted verdict based on the package name so tests are deterministic."""

    def analyze(self, ecosystem, name, version, options=None):
        if name == "reqeusts":  # simulate a typosquat malware hit
            signals = [{
                "code": "TYPOSQUAT", "severity": "critical", "weight": 9.0,
                "message": "edit-distance 1 from requests",
                "evidence": {"target": "requests", "distance": 1}, "capability": Capability.TYPOSQUAT,
            }, {
                "code": "INSTALL_HOOK_EXEC", "severity": "critical", "weight": 10.0,
                "message": "install-time exec", "evidence": {}, "capability": Capability.INSTALL_EXEC,
            }]
            return AnalysisResult(
                ecosystem, name, version or "1.0.0", 95, 92, 95, "critical", {},
                signals, "1.0.0", 42, True, capabilities=[Capability.TYPOSQUAT, Capability.INSTALL_EXEC],
            )
        return AnalysisResult(
            ecosystem, name, version or "2.0.0", 5, 3, 5, "info", {}, [], "1.0.0", 30, True, capabilities=[],
        )


@pytest.fixture(autouse=True)
def _patch_orchestrator(monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _FakeOrchestrator())


def test_clean_package_allowed(client, admin_token):
    resp = client.post(
        "/api/v1/scans", headers=auth(admin_token),
        json={"ecosystem": "pypi", "name": "requests", "version": "2.32.3"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["risk_score"] == 5


def test_malicious_package_blocked(client, admin_token):
    resp = client.post(
        "/api/v1/scans", headers=auth(admin_token),
        json={"ecosystem": "pypi", "name": "reqeusts"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["decision"] == "block"
    assert body["severity"] == "critical"
    assert any(s["code"] == "TYPOSQUAT" for s in body["signals"])
    assert "blocked_capability:install_hook_exec" in body["matched_policy_rules"]


def test_invalid_package_name_rejected(client, admin_token):
    resp = client.post(
        "/api/v1/scans", headers=auth(admin_token),
        json={"ecosystem": "pypi", "name": "../../etc/passwd"},
    )
    assert resp.status_code == 422


def test_unsupported_ecosystem_rejected(client, admin_token):
    resp = client.post(
        "/api/v1/scans", headers=auth(admin_token),
        json={"ecosystem": "npm", "name": "left-pad"},
    )
    assert resp.status_code == 422


def test_scan_history_and_detail(client, admin_token):
    client.post("/api/v1/scans", headers=auth(admin_token),
                json={"ecosystem": "pypi", "name": "reqeusts"})
    listing = client.get("/api/v1/scans", headers=auth(admin_token))
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    stats = client.get("/api/v1/scans/stats/overview", headers=auth(admin_token))
    assert stats.status_code == 200
    assert "by_decision" in stats.json()


def test_audit_log_records_and_serializes(client, admin_token):
    client.post("/api/v1/scans", headers=auth(admin_token),
                json={"ecosystem": "pypi", "name": "reqeusts"})
    resp = client.get("/api/v1/audit", headers=auth(admin_token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 1
    # The metadata field must serialize as a dict under the "metadata" key.
    assert all(isinstance(e["metadata"], dict) for e in body["items"])
    assert any(e["action"] == "scan.create" for e in body["items"])


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


# =========================================================================== Warden X
def _warden_x_finding() -> dict:
    finding = Finding(
        Code.NETWORK_EGRESS, "high", 6.0, "outbound HTTP request to a raw IP address",
        {"host": "203.0.113.7"}, Capability.NETWORK, confidence=0.7,
        location=Location(file="evilpkg/__init__.py", line=12),
    ).with_defaults(analyzer="static_code", analyzer_version="2.0.0")
    data = finding.to_dict()
    data["title"] = "T" * 400  # oversized values are clipped to their column size
    return data


class _WardenXOrchestrator:
    """Emits a fully populated Warden X result (every new AnalysisResult field) or odd shapes."""

    def analyze(self, ecosystem, name, version, options=None):
        if name.startswith("legacy-shape"):
            return _V1OnlyResult(ecosystem, name, version or "1.0.0")
        if name.startswith("malformed"):
            signal = {"code": "NETWORK_EGRESS", "severity": "low", "weight": "heavy", "message": "m",
                      "evidence": None, "confidence": "very", "cwe": "CWE-200", "location": ["not", "a", "dict"],
                      "related": {"not": "a list"}, "remediation": 42}
            return AnalysisResult(ecosystem, name, version or "1.0.0", 5, 0, 5, "info", {}, [signal], "1.0.0", 1,
                                  False, risk={"malicious_risk": float("nan"), "vulnerability_risk": "high"},
                                  model_version=None, attack_chains="not-a-list")
        risk_score = 50 if name.startswith("warn") else 64
        return AnalysisResult(
            ecosystem, name, version or "3.1.0", 40, 12, risk_score, "high", {"f_network": 1.0},
            [_warden_x_finding()], "1.0.0", 77, True, capabilities=[Capability.NETWORK],
            risk={"method": "warden-risk-2.0", "final_score": risk_score, "malicious_risk": 40,
                  "vulnerability_risk": risk_score, "dimensions": {"behavioral": {"score": 40}}},
            attack_chains=[{"id": "chain-1", "stages": ["download", "execute"]}],
            analyzer_runs=[{"name": "static_code", "version": "2.0.0", "status": "ok", "duration_ms": 12,
                            "finding_count": 1, "detail": None}],
            package_intel={"maintainers": 1}, provenance={"status": "unverified"},
            vulnerabilities=[{"id": "GHSA-test-fixture", "severity": "high"}],
            intel_status={"status": "ok", "sources": {"osv": "ok"}}, model_version="iforest-2026.09",
            explanation={"top_features": ["f_network"]}, scan_options={"offline": True},
        )


class _V1OnlyResult:
    """An analysis result object that predates Warden X: only the v1 attributes exist."""

    def __init__(self, ecosystem, name, version):
        self.ecosystem, self.name, self.version = ecosystem, name, version
        self.rule_score, self.ml_score, self.risk_score, self.severity = 3, 1, 3, "info"
        self.features, self.signals, self.analyzer_version = {}, [], "1.0.0"
        self.duration_ms, self.ml_available, self.cached, self.capabilities = 4, False, False, []


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _scan(client, token, name, **extra):
    resp = client.post("/api/v1/scans", headers=auth(token), json={"ecosystem": "pypi", "name": name, **extra})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _event_types(scan_id: str) -> set[str]:
    with SessionLocal() as db:
        return set(db.scalars(select(SecurityEvent.type).where(SecurityEvent.scan_id == uuid.UUID(scan_id))))


def test_every_warden_x_result_field_is_persisted_and_exposed(client, admin_token, monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _WardenXOrchestrator())
    body = _scan(client, admin_token, _unique("wx-full"))
    detail = client.get(f"/api/v1/scans/{body['id']}", headers=auth(admin_token)).json()
    for out in (body, detail):
        assert out["risk"]["method"] == "warden-risk-2.0"
        assert out["malicious_risk"] == 40 and out["vulnerability_risk"] == 64
        assert out["attack_chains"] == [{"id": "chain-1", "stages": ["download", "execute"]}]
        assert out["analyzer_runs"][0]["status"] == "ok"
        assert out["package_intel"] == {"maintainers": 1} and out["provenance"] == {"status": "unverified"}
        assert out["vulnerabilities"] == [{"id": "GHSA-test-fixture", "severity": "high"}]
        assert out["intel_status"]["status"] == "ok" and out["model_version"] == "iforest-2026.09"
        assert out["explanation"] == {"top_features": ["f_network"]} and out["scan_options"] == {"offline": True}
        assert out["environment"] == "production" and out["policy_reasons"] == []

        [signal] = out["signals"]
        expected = _warden_x_finding()
        assert signal["finding_id"] == expected["finding_id"] and signal["finding_id"].startswith("WX-")
        assert signal["confidence"] == 0.7 and signal["category"] == expected["category"]
        assert signal["analyzer"] == "static_code" and signal["analyzer_version"] == "2.0.0"
        assert signal["capability"] == Capability.NETWORK and signal["provenance"] == expected["provenance"]
        assert signal["location"]["file"] == "evilpkg/__init__.py" and signal["location"]["line"] == 12
        assert signal["cwe"] == expected["cwe"] and signal["attack"] == expected["attack"]
        assert signal["remediation"] == expected["remediation"] and signal["references"] == expected["references"]
        assert len(signal["title"]) == 160


def test_v1_shaped_results_still_persist(client, admin_token, monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _WardenXOrchestrator())
    body = _scan(client, admin_token, _unique("legacy-shape"))
    assert body["risk_score"] == 3 and body["malicious_risk"] == 3  # v1 risk_score is the malicious score
    assert body["risk"] is None and body["vulnerability_risk"] is None and body["model_version"] is None
    assert body["attack_chains"] is None and body["signals"] == []


def test_malformed_finding_and_result_values_are_coerced_not_fatal(client, admin_token, monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _WardenXOrchestrator())
    body = _scan(client, admin_token, _unique("malformed"))
    [signal] = body["signals"]
    assert signal["weight"] == 0.0 and signal["evidence"] == {}
    assert signal["confidence"] is None and signal["cwe"] is None and signal["location"] is None
    assert signal["related"] is None and signal["remediation"] is None
    assert body["malicious_risk"] == 5 and body["vulnerability_risk"] is None and body["attack_chains"] is None


def test_rescan_updates_in_place_without_duplicating_findings(client, admin_token, monkeypatch):
    monkeypatch.setattr(scans_router, "_orchestrator", _WardenXOrchestrator())
    name = _unique("wx-rescan")
    first = _scan(client, admin_token, name)
    second = _scan(client, admin_token, name)
    assert first["id"] == second["id"]
    with SessionLocal() as db:
        assert len(db.scalars(select(Signal).where(Signal.scan_id == uuid.UUID(first["id"]))).all()) == 1


def test_search_matches_like_wildcards_literally(client, admin_token):
    tag = uuid.uuid4().hex[:8]
    literal = _scan(client, admin_token, f"likepkg_{tag}")
    _scan(client, admin_token, f"likepkgx{tag}")  # would match an unescaped "_" wildcard

    def names(q: str) -> list[str]:
        resp = client.get("/api/v1/scans", headers=auth(admin_token), params={"q": q, "limit": 200})
        assert resp.status_code == 200, resp.text
        return [item["package_name"] for item in resp.json()["items"]]

    assert names(f"likepkg_{tag}") == [literal["package_name"]]
    assert names("%") == []
    assert names("\\") == []


def test_environment_is_recorded_and_filterable(client, admin_token):
    name = _unique("env-scan")
    body = _scan(client, admin_token, name, environment="Staging")
    assert body["environment"] == "staging"
    listing = client.get("/api/v1/scans", headers=auth(admin_token), params={"q": name, "environment": "staging"})
    assert [item["id"] for item in listing.json()["items"]] == [body["id"]]
    other = client.get("/api/v1/scans", headers=auth(admin_token), params={"q": name, "environment": "development"})
    assert other.json()["items"] == []
    assert client.get("/api/v1/scans", headers=auth(admin_token), params={"environment": "moon"}).status_code == 422
    assert client.post("/api/v1/scans", headers=auth(admin_token),
                       json={"ecosystem": "pypi", "name": name, "environment": "moon"}).status_code == 422


def test_verdicts_are_kept_per_environment(client, admin_token, monkeypatch):
    """Regression: the upsert ignored the environment, so a re-scan under a permissive development
    policy overwrote the production block verdict of the same package version."""
    from types import SimpleNamespace

    from app.db.models import Decision

    monkeypatch.setattr(scans_router, "_active_policy",
                        lambda db, environment="production": SimpleNamespace(id=None, environment=environment))

    def evaluate(result, policy):
        blocked = policy.environment == "production"
        return SimpleNamespace(decision=Decision.block if blocked else Decision.allow,
                               matched_rules=["block_threshold"] if blocked else [], reasons=[])

    monkeypatch.setattr(scans_router, "evaluate", evaluate)
    name = _unique("env-verdict")
    prod = _scan(client, admin_token, name, environment="production")
    dev = _scan(client, admin_token, name, environment="development")
    assert (prod["decision"], dev["decision"]) == ("block", "allow")
    assert prod["id"] != dev["id"] and (prod["environment"], dev["environment"]) == ("production", "development")
    stored = client.get(f"/api/v1/scans/{prod['id']}", headers=auth(admin_token)).json()
    assert (stored["decision"], stored["environment"]) == ("block", "production")
    blocked = client.get("/api/v1/scans", headers=auth(admin_token), params={"q": name, "decision": "block"})
    assert [item["id"] for item in blocked.json()["items"]] == [prod["id"]]
    assert _scan(client, admin_token, name, environment="production")["id"] == prod["id"]  # still idempotent


def test_scan_events_follow_the_decision(client, admin_token, monkeypatch):
    clean = _scan(client, admin_token, _unique("clean-events"))
    assert _event_types(clean["id"]) == {"package_scanned"}

    blocked = _scan(client, admin_token, "reqeusts")
    assert _event_types(blocked["id"]) >= {"package_scanned", "policy_violation", "package_blocked"}
    with SessionLocal() as db:
        row = db.scalar(select(SecurityEvent).where(SecurityEvent.scan_id == uuid.UUID(blocked["id"]),
                                                    SecurityEvent.type == "package_blocked"))
        assert row.severity == "critical" and row.package == "reqeusts"
        assert "blocked_capability:install_hook_exec" in row.details["matched_rules"]

    monkeypatch.setattr(scans_router, "_orchestrator", _WardenXOrchestrator())
    warned = _scan(client, admin_token, _unique("warn-events"))
    assert warned["decision"] == "warn"
    assert _event_types(warned["id"]) == {"package_scanned", "policy_violation"}


def test_stream_outage_does_not_break_scans(client, admin_token, monkeypatch):
    class _BrokenStream:
        def xadd(self, *args, **kwargs):
            raise ConnectionError("redis down")

    monkeypatch.setattr(cache_module, "cache", _BrokenStream())
    body = _scan(client, admin_token, _unique("stream-outage"))
    assert _event_types(body["id"]) == {"package_scanned"}


def test_audit_chain_stays_valid_after_scans(client, admin_token):
    _scan(client, admin_token, _unique("chain-check"))
    verify = client.get("/api/v1/audit/verify", headers=auth(admin_token)).json()
    assert verify["ok"] is True
