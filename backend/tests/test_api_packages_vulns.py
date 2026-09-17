"""Package intelligence and vulnerability routes (database fixtures and a stub intelligence service)."""

from __future__ import annotations

import uuid

import pytest

from app.core.permissions import Role
from app.core.security import create_access_token
from app.db.models import Decision, MonitoredPackage, ReleaseDiff, Scan, Severity, User
from app.db.session import SessionLocal
from app.intel import service as intel_service
from app.intel.models import IntelResult, Vulnerability
from tests.conftest import auth

ADVISORY = {"id": "GHSA-test-0001", "severity": "critical", "kev": True, "cvss_score": 9.8,
            "fixed_versions": ["1.0.1"]}


def seed(name: str) -> None:
    with SessionLocal() as db:
        for version, vulns, risk in (("1.0.0", [ADVISORY], 88), ("1.0.1", [], 10)):
            db.add(Scan(id=uuid.uuid4(), ecosystem="pypi", package_name=name, version=version, analyzer_version="t",
                        severity=Severity.critical if vulns else Severity.info,
                        decision=Decision.block if vulns else Decision.allow, risk_score=risk,
                        vulnerabilities=vulns, environment="production"))
        db.add(MonitoredPackage(id=uuid.uuid4(), ecosystem="pypi", name=name, enabled=True, approved_version="1.0.1"))
        db.add(ReleaseDiff(id=uuid.uuid4(), ecosystem="pypi", package=name, old_version="1.0.0", new_version="1.0.1",
                           analyzer_version="t", drift_detected=False, drift_score=0))
        db.commit()


def _token(role: Role) -> str:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"pv-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                    password_hash="unused", role=role)
        db.add(user)
        db.commit()
        return create_access_token(subject=str(user.id), role=role.value)


def test_package_overview_combines_verdicts_monitoring_and_diffs(client, admin_token):
    name = f"Pkg_{uuid.uuid4().hex[:8]}"
    seed(name)
    lookup = name.lower().replace("_", "-")  # PEP 503 spelling finds the same package
    body = client.get(f"/api/v1/packages/pypi/{lookup}", headers=auth(admin_token)).json()
    assert body["name"] == name
    assert {v["version"] for v in body["verdicts"]} == {"1.0.0", "1.0.1"}
    assert body["vulnerabilities"] == [{"id": "GHSA-test-0001", "severity": "critical", "kev": True,
                                        "versions": ["1.0.0"]}]
    assert body["monitoring"][0]["approved_version"] == "1.0.1"
    assert body["release_diffs"][0]["new_version"] == "1.0.1"


@pytest.mark.parametrize(("path", "status"), [
    ("/api/v1/packages/pypi/never-seen-anywhere", 404),
    ("/api/v1/packages/npm/left-pad", 422),
    ("/api/v1/packages/pypi/..%2Fetc", 404),  # never reaches the route
])
def test_package_overview_errors(client, admin_token, path, status):
    assert client.get(path, headers=auth(admin_token)).status_code == status


def test_vulnerability_list_aggregates_and_filters(client, admin_token):
    name = f"vul-{uuid.uuid4().hex[:8]}"
    seed(name)
    body = client.get("/api/v1/vulnerabilities?kev=true&min_severity=high", headers=auth(admin_token)).json()
    item = next(i for i in body["items"] if i["id"] == "GHSA-test-0001")
    assert {"package": name, "version": "1.0.0"} in item["affected"]
    none = client.get("/api/v1/vulnerabilities?kev=false&min_severity=critical", headers=auth(admin_token)).json()
    assert all(i["id"] != "GHSA-test-0001" for i in none["items"])
    assert client.get("/api/v1/vulnerabilities?min_severity=bogus", headers=auth(admin_token)).status_code == 422


class _StubIntel:
    def __init__(self, result: IntelResult):
        self.result = result
        self.calls = []

    def package_vulnerabilities(self, ecosystem, name, version):
        self.calls.append((ecosystem, name, version))
        return self.result

    def close(self):
        pass


@pytest.fixture()
def stub_intel():
    vuln = Vulnerability(id="PYSEC-2099-1", aliases=["CVE-2099-0001"], summary="test advisory", severity="high",
                         cvss_score=7.5, kev=False, published="2099-01-01T00:00:00Z")
    stub = _StubIntel(IntelResult(vulnerabilities=[vuln], status="ok", ecosystem="pypi", name="demo",
                                  version="1.0"))
    intel_service.reset_intel_service(stub)
    yield stub
    intel_service.reset_intel_service(None)


def test_lookup_caches_advisories(client, admin_token, stub_intel):
    resp = client.get("/api/v1/vulnerabilities/lookup?name=demo&version=1.0", headers=auth(admin_token))
    assert resp.status_code == 200 and resp.json()["status"] == "ok"
    assert stub_intel.calls == [("pypi", "demo", "1.0")]
    cached = client.get("/api/v1/vulnerabilities/PYSEC-2099-1", headers=auth(admin_token)).json()
    assert cached["aliases"] == ["CVE-2099-0001"] and cached["severity"] == "high"


def test_unavailable_lookup_is_reported_not_hidden(client, admin_token, stub_intel):
    stub_intel.result = IntelResult(vulnerabilities=[], status="unavailable", ecosystem="pypi", name="demo",
                                    version="2.0", errors={"osv": "timeout"})
    body = client.get("/api/v1/vulnerabilities/lookup?name=demo&version=2.0", headers=auth(admin_token)).json()
    assert body["status"] == "unavailable" and body["vulnerabilities"] == []


def test_lookup_validates_input_before_calling_out(client, admin_token, stub_intel):
    bad = client.get("/api/v1/vulnerabilities/lookup?name=../x&version=1", headers=auth(admin_token))
    assert bad.status_code == 422
    assert stub_intel.calls == []
    assert client.get("/api/v1/vulnerabilities/UNKNOWN-1", headers=auth(admin_token)).status_code == 404


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_read(client, role):
    token = _token(role)
    assert client.get("/api/v1/vulnerabilities", headers=auth(token)).status_code == 200


def test_anonymous_is_rejected(client):
    assert client.get("/api/v1/vulnerabilities").status_code == 401
    assert client.get("/api/v1/packages/pypi/requests").status_code == 401
