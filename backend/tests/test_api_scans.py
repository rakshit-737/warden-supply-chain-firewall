"""End-to-end API tests for the scan flow, with a deterministic fake orchestrator so no
network access is required."""

import pytest

from app.analysis.orchestrator import AnalysisResult
from app.analysis.signals import Capability
from app.api.routers import scans as scans_router
from tests.conftest import auth


class _FakeOrchestrator:
    """Returns a scripted verdict based on the package name so tests are deterministic."""

    def analyze(self, ecosystem, name, version):
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
