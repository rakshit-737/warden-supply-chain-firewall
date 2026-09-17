"""Container scan API and service: decisions, persistence, SBOM validity, upload limits and RBAC."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7
from sqlalchemy import select

from app.analysis.findings import Finding, Severity
from app.containers import service
from app.containers.trivy import TrivyOutcome
from app.core.config import settings
from app.core.permissions import Role
from app.core.security import create_access_token
from app.db.models import AuditEvent, SecurityEvent, User
from app.db.session import SessionLocal
from tests.conftest import auth
from tests.test_container_image import APK, base_config, docker_save, f, tar_bytes

URL = "/api/v1/containers/scans"
OCTET = {"Content-Type": "application/octet-stream"}
SCHEMAS = Path(__file__).parent / "data" / "schemas"


def cyclonedx_validator() -> Draft7Validator:
    registry: Registry = Registry()
    schemas = {}
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        schemas[name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7))
    return Draft7Validator(schemas["bom-1.6.schema.json"], registry=registry)


def image(user: str = "app") -> bytes:
    return docker_save([tar_bytes([f("lib/apk/db/installed", APK)])], base_config(user=user))


def vuln(severity: Severity) -> Finding:
    return Finding("CONTAINER_VULNERABILITY", severity, 1.0, "CVE-2099-1 in musl",
                   {"vulnerability_id": "CVE-2099-1", "package": "musl"}, confidence=0.9)


@pytest.fixture()
def trivy(monkeypatch):
    state = {"outcome": TrivyOutcome("ok", "0.99.0")}
    monkeypatch.setattr(service, "scan_image_archive", lambda data, offline=False: state["outcome"])
    return state


def _token(role: Role) -> str:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"ctr-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                    password_hash="unused", role=role)
        db.add(user)
        db.commit()
        return create_access_token(subject=str(user.id), role=role.value)


def test_decision_rules():
    medium = Finding("CONTAINER_MISCONFIG", Severity.medium, 1.0, "m", {})
    low_confidence_high = Finding("SECRET_DETECTED", Severity.high, 1.0, "h", {}, confidence=0.5)
    assert service.decide([], complete=True, vulnerabilities_assessed=True) == ("allow", 0, [])
    assert service.decide([vuln(Severity.critical)], complete=True, vulnerabilities_assessed=True)[0] == "block"
    assert service.decide([medium], complete=True, vulnerabilities_assessed=True)[:2] == ("warn", 35)
    assert service.decide([low_confidence_high], complete=True, vulnerabilities_assessed=True)[:2] == ("allow", 60)
    decision, _, reasons = service.decide([], complete=False, vulnerabilities_assessed=False)
    assert decision == "warn" and len(reasons) == 2


def test_service_sbom_is_valid_cyclonedx(trivy):
    result = service.scan_image(image(), tool_version="2.0.0")
    cyclonedx_validator().validate(result.sbom)
    assert [c["purl"] for c in result.sbom["components"]] == [
        "pkg:apk/alpine/busybox@1.36.1-r29", "pkg:apk/alpine/musl@1.2.5-r0"]
    assert result.decision == "allow"


def test_unassessed_vulnerabilities_warn(trivy):
    trivy["outcome"] = TrivyOutcome("unavailable", detail="not found on PATH")
    result = service.scan_image(image())
    assert result.decision == "warn" and any("not assessed" in r for r in result.reasons)


def test_scan_is_stored_with_audit_event_and_sbom(client, admin_token, trivy):
    trivy["outcome"] = TrivyOutcome("ok", "0.99.0", findings=[vuln(Severity.critical)])
    resp = client.post(URL + "?image_ref=demo:1.0", headers={**auth(admin_token), **OCTET},
                       content=image(user="root"))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["decision"] == "block" and body["risk_score"] == 80 and body["status"] == "completed"
    assert body["tools"]["trivy"]["status"] == "ok"
    assert {x["code"] for x in body["findings"]} == {"CONTAINER_VULNERABILITY", "DOCKERFILE_ROOT_USER"}
    assert body["summary"]["component_counts"] == {"apk": 2}

    listed = client.get(URL, headers=auth(admin_token)).json()
    assert any(item["id"] == body["id"] for item in listed["items"])
    sbom = client.get(URL + "/" + body["id"] + "/sbom", headers=auth(admin_token)).json()
    assert sbom["bomFormat"] == "CycloneDX"
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "container.scan",
                                                  AuditEvent.target_id == "demo:1.0"))
        events = db.scalars(select(SecurityEvent).where(SecurityEvent.type == "container_scanned")).all()
        assert any(e.details.get("container_scan_id") == body["id"] for e in events)


def test_garbage_upload_is_stored_as_incomplete_not_clean(client, admin_token, trivy):
    resp = client.post(URL, headers={**auth(admin_token), **OCTET}, content=b"definitely not a tarball")
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "incomplete" and body["decision"] == "block"
    assert body["tools"]["trivy"]["status"] == "skipped"


def test_empty_upload_is_rejected(client, admin_token, trivy):
    assert client.post(URL, headers={**auth(admin_token), **OCTET}, content=b"").status_code == 422


def test_upload_limit_applies_to_this_route_only(client, admin_token, trivy, monkeypatch):
    monkeypatch.setattr(settings, "MAX_IMAGE_UPLOAD_BYTES", settings.MAX_REQUEST_BODY_BYTES * 2)
    fits_here = b"x" * (settings.MAX_REQUEST_BODY_BYTES + 1)
    assert client.post(URL, headers={**auth(admin_token), **OCTET}, content=fits_here).status_code == 201
    too_big = b"x" * (settings.MAX_REQUEST_BODY_BYTES * 2 + 1)
    assert client.post(URL, headers={**auth(admin_token), **OCTET}, content=too_big).status_code == 413
    elsewhere = client.post("/api/v1/scans", headers={**auth(admin_token), "Content-Type": "application/json"},
                            content=fits_here)
    assert elsewhere.status_code == 413


def test_unknown_scan_is_404(client, admin_token):
    assert client.get(URL + "/" + str(uuid.uuid4()), headers=auth(admin_token)).status_code == 404


@pytest.mark.parametrize(("role", "write", "read"), [
    (Role.admin, 201, 200), (Role.security_analyst, 201, 200), (Role.developer, 201, 200),
    (Role.auditor, 403, 200), (Role.read_only, 403, 200),
])
def test_role_matrix(client, trivy, role, write, read):
    token = _token(role)
    assert client.post(URL, headers={**auth(token), **OCTET}, content=image()).status_code == write
    assert client.get(URL, headers=auth(token)).status_code == read


def test_anonymous_upload_is_rejected(client):
    assert client.post(URL, headers=OCTET, content=image()).status_code == 401
