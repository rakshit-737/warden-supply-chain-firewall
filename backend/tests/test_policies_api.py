"""Policy API v2: document validation, policy-as-code create/update/read, audit content, RBAC on the new
routes, and scan evaluation with environments and approved exceptions.

Every test runs on its own SQLite database, so activating policies never leaks into other tests.
Analysis results come from a scripted fixture orchestrator: findings use the public Finding shape and
describe inert placeholder packages; nothing is downloaded, installed or executed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import sessionmaker

from app.analysis.findings import Finding, Location
from app.analysis.orchestrator import AnalysisResult
from app.analysis.scoring import compute_rule_score
from app.analysis.signals import Capability, Code
from app.api.routers import scans as scans_router
from app.core import security
from app.db.base import Base
from app.db.models import AuditEvent, Policy, PolicyException, Role, User
from app.db.session import get_db
from app.main import create_app
from app.policy.document import MAX_POLICY_BYTES, from_legacy, load_policy_text, validate_policy_data
from app.policy.engine import policy_hash_of
from tests.conftest import auth

API = "/api/v1"
POLICIES_DIR = Path(__file__).resolve().parents[2] / "policies"
SHIPPED = {env: (POLICIES_DIR / f"{env}.yaml").read_text(encoding="utf-8")
           for env in ("production", "staging", "development")}
ROLES = (Role.admin, Role.security_analyst, Role.developer, Role.auditor, Role.read_only)


# =========================================================================== fixture orchestrator
def _finding(code: str, *, severity: str = "medium", weight: float = 4.0, confidence: float = 0.8,
             capability: str | None = None, file: str = "sample_pkg/__init__.py", line: int = 1) -> dict:
    finding = Finding(code, severity, weight, f"{code} observed (fixture)", {}, capability, confidence=confidence,
                      location=Location(file=file, line=line))
    return finding.with_defaults(analyzer="test-fixture", analyzer_version="0").to_dict()


def _script(name: str) -> list[dict]:
    """Findings per package-name prefix (placeholder packages)."""
    if name.startswith("templated"):
        # A template engine compiling templates: a capability benign software also exhibits.
        return [_finding(Code.DYNAMIC_EXEC, capability=Capability.DYNAMIC_EXEC, file="templated/compiler.py", line=33)]
    if name.startswith("ioc"):
        return [_finding(Code.IOC_MATCH, severity="critical", weight=12.0, confidence=0.95, capability=Capability.IOC)]
    return []


class _FixtureOrchestrator:
    def __init__(self) -> None:
        self.intel_status = "ok"

    def analyze(self, ecosystem, name, version, options=None):
        signals = _script(name.lower())
        rule = compute_rule_score(signals)
        return AnalysisResult(
            ecosystem, name, version or "1.4.0", rule, 0, rule, "info", {}, signals, "2.0.0", 5, False,
            capabilities=sorted({s["capability"] for s in signals if s.get("capability")}),
            intel_status={"status": self.intel_status}, provenance={"status": "unverified", "hash_verified": True},
            package_intel={"age_days": 400.0},
        )


@dataclass
class Api:
    client: TestClient
    factory: sessionmaker
    headers: dict[Role, dict[str, str]]
    user_ids: dict[Role, uuid.UUID]
    orchestrator: _FixtureOrchestrator


@pytest.fixture()
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'policies-api.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, future=True)

    def _get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    headers: dict[Role, dict[str, str]] = {}
    user_ids: dict[Role, uuid.UUID] = {}
    with factory() as db:
        for role in ROLES:
            user = User(id=uuid.uuid4(), email=f"policies-api-{role.value}@warden.io", password_hash="unused",
                        role=role)
            db.add(user)
            user_ids[role] = user.id
            headers[role] = auth(security.create_access_token(subject=str(user.id), role=role.value))
        db.commit()
    orchestrator = _FixtureOrchestrator()
    monkeypatch.setattr(scans_router, "_orchestrator", orchestrator)
    app = create_app()
    app.dependency_overrides[get_db] = _get_db
    try:
        with TestClient(app) as client:
            yield Api(client, factory, headers, user_ids, orchestrator)
    finally:
        engine.dispose()


# =========================================================================== helpers
def _document(name: str = "api-fixture", environment: str | None = "production", **spec) -> dict:
    return {"apiVersion": "warden.dev/v1", "kind": "Policy", "metadata": {"name": name, "environment": environment},
            "spec": spec}


def _validate(api: Api, body: dict, role: Role = Role.read_only):
    return api.client.post(f"{API}/policies/validate", headers=api.headers[role], json=body)


def _create(api: Api, document: dict, *, role: Role = Role.admin, **extra):
    return api.client.post(f"{API}/policies", headers=api.headers[role], json={"document": document, **extra})


def _active_document_policy(api: Api, **kwargs) -> dict:
    created = _create(api, _document(**kwargs))
    assert created.status_code == 201, created.text
    activated = api.client.post(f"{API}/policies/{created.json()['id']}/activate", headers=api.headers[Role.admin])
    assert activated.status_code == 200, activated.text
    return activated.json()


def _scan(api: Api, name: str, environment: str = "production") -> dict:
    resp = api.client.post(f"{API}/scans", headers=api.headers[Role.developer],
                           json={"ecosystem": "pypi", "name": name, "environment": environment})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _evaluation(scan: dict) -> dict:
    [record] = [r for r in scan["policy_reasons"] if r["rule"] == "policy_evaluation"]
    return record


def _audit(api: Api, action: str, target_id: str | None = None) -> list[dict]:
    with api.factory() as db:
        stmt = select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
        if target_id is not None:
            stmt = stmt.where(AuditEvent.target_id == target_id)
        return [row.metadata_ for row in db.scalars(stmt)]


def _policy_count(api: Api) -> int:
    with api.factory() as db:
        return db.scalar(select(func.count(Policy.id))) or 0


def _request_exception(api: Api, **fields) -> str:
    body = {"justification": "Template compiler reviewed by the security team (fixture)",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(), **fields}
    resp = api.client.post(f"{API}/policies/exceptions", headers=api.headers[Role.developer], json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _approve(api: Api, exception_id: str) -> None:
    resp = api.client.post(f"{API}/policies/exceptions/{exception_id}/approve",
                           headers=api.headers[Role.security_analyst])
    assert resp.status_code == 200, resp.text


# =========================================================================== POST /policies/validate
@pytest.mark.parametrize("environment", ["production", "staging", "development"])
def test_validate_accepts_the_shipped_yaml_and_reports_a_reproducible_hash(api, environment):
    resp = _validate(api, {"yaml": SHIPPED[environment]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    expected = load_policy_text(SHIPPED[environment])
    assert body["valid"] is True and body["errors"] == []
    assert body["policy_hash"] == expected.policy_hash and body["normalized"] == expected.to_dict()
    # The normalised object validates to the same hash: YAML and JSON sources are interchangeable.
    again = _validate(api, {"document": body["normalized"]}).json()
    assert again["valid"] is True and again["policy_hash"] == body["policy_hash"]


def test_validate_reports_located_errors_and_stores_nothing(api):
    text = SHIPPED["production"].replace("- BROWSER_CREDENTIAL_ACCESS", "- BROWSER_CREDENTIAL_ACCES")
    line = next(i for i, row in enumerate(text.splitlines(), 1) if "- BROWSER_CREDENTIAL_ACCES" in row)
    body = _validate(api, {"yaml": text}).json()
    assert body["valid"] is False and body["normalized"] is None and body["policy_hash"] is None
    [error] = body["errors"]
    assert error["loc"] == "spec.deny.codes.1" and "unknown finding code" in error["msg"] and error["line"] == line

    document = _document(thresholds={"warn": 90, "block": 70}, deny={"codes": ["NOT_A_REAL_CODE"]}, surprise=True)
    body = _validate(api, {"document": document}).json()
    assert body["valid"] is False
    assert {"spec.surprise", "spec.deny.codes.0", "spec.thresholds"} <= {e["loc"] for e in body["errors"]}
    assert _policy_count(api) == 0


@pytest.mark.parametrize("body", [
    pytest.param({}, id="neither"),
    pytest.param({"yaml": "kind: Policy", "document": {"kind": "Policy"}}, id="both"),
    pytest.param({"yaml": "x" * (MAX_POLICY_BYTES + 1)}, id="oversized-yaml"),
    pytest.param({"document": ["not", "an", "object"]}, id="document-not-an-object"),
    pytest.param({"yaml": "kind: Policy", "lenient": True}, id="unknown-request-field"),
])
def test_validate_rejects_malformed_requests(api, body):
    resp = _validate(api, body)
    assert resp.status_code == 422, resp.text
    assert resp.json()["error"]["code"] == "validation_error"


def test_validate_bounds_hostile_text_and_redacts_error_messages(api):
    tagged = _validate(api, {"yaml": "!!python/object/apply:os.system ['echo placeholder']\n"}).json()
    assert tagged["valid"] is False and "constructor" in tagged["errors"][0]["msg"]
    # Fewer characters than the request cap, more bytes than the document cap.
    multibyte = "a: '" + "é" * (MAX_POLICY_BYTES // 2 + 1) + "'"
    oversized = _validate(api, {"yaml": multibyte}).json()
    assert oversized["valid"] is False and "exceeds" in oversized["errors"][0]["msg"]
    resp = _validate(api, {"document": _document(deny={"codes": ["AKIAIOSFODNN7EXAMPLE"]})})
    assert resp.json()["valid"] is False and "AKIAIOSFODNN7EXAMPLE" not in resp.text


# =========================================================================== RBAC on the new capabilities
@pytest.mark.parametrize("role", ROLES, ids=lambda r: r.value)
def test_every_role_may_validate_but_only_admins_may_store_documents(api, role):
    assert _validate(api, {"yaml": SHIPPED["staging"]}, role).status_code == 200
    created = _create(api, _document(name=f"rbac-{role.value}", environment="staging"), role=role)
    if role == Role.admin:
        assert created.status_code == 201, created.text
    else:
        assert created.status_code == 403, created.text
        assert created.json()["error"]["code"] == "forbidden"
        assert _policy_count(api) == 0


def test_new_routes_reject_anonymous_callers(api):
    assert api.client.post(f"{API}/policies/validate", json={"yaml": SHIPPED["staging"]}).status_code == 401
    assert api.client.post(f"{API}/policies", json={"document": _document()}).status_code == 401


# =========================================================================== create / update / read
def test_document_policy_is_stored_normalised_mirrored_and_hashed(api):
    document = _document(
        name="api-prod", thresholds={"warn": 35, "block": 65}, min_package_age_days=3,
        deny={"packages": ["Evil_Pkg"], "codes": ["DYNAMIC_EXEC"], "capabilities": ["ioc", "install_hook_exec"]},
        allow={"packages": ["Internal.Tool"]},
    )
    resp = _create(api, document)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    expected = validate_policy_data(document).document
    assert body["document"] == expected.to_dict() and body["policy_hash"] == expected.policy_hash
    assert (body["name"], body["environment"], body["warn_threshold"], body["block_threshold"],
            body["min_package_age_days"]) == ("api-prod", "production", 35, 65, 3)
    assert body["blocked_capabilities"] == ["install_hook_exec", "ioc"]
    assert body["denylist"] == ["evil-pkg"] and body["allowlist"] == ["internal-tool"]

    listed = api.client.get(f"{API}/policies", headers=api.headers[Role.auditor]).json()
    [row] = [p for p in listed if p["id"] == body["id"]]
    assert row["document"] == body["document"] and row["policy_hash"] == body["policy_hash"]
    api.client.post(f"{API}/policies/{body['id']}/activate", headers=api.headers[Role.admin])
    active = api.client.get(f"{API}/policies/active", headers=api.headers[Role.read_only],
                            params={"environment": "production"}).json()
    assert active["id"] == body["id"] and active["policy_hash"] == body["policy_hash"]

    [create_audit] = _audit(api, "policy.create", body["id"])
    assert create_audit["policy_hash"] == body["policy_hash"] and create_audit["policy_source"] == "document"


def test_document_environment_is_used_when_the_request_omits_it(api):
    body = _create(api, _document(name="api-staging", environment="staging")).json()
    assert body["environment"] == "staging" and body["document"]["metadata"]["environment"] == "staging"
    unscoped = _create(api, _document(name="api-unscoped", environment=None), environment="development").json()
    assert unscoped["document"]["metadata"]["environment"] == "development"


@pytest.mark.parametrize("extra", [
    pytest.param({"block_threshold": 90}, id="legacy-rule-field-next-to-document"),
    pytest.param({"name": "another-name"}, id="name-differs-from-metadata"),
    pytest.param({"environment": "development"}, id="environment-differs-from-metadata"),
])
def test_document_and_request_fields_must_agree(api, extra):
    resp = _create(api, _document(name="api-conflict", environment="staging"), **extra)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "validation_error"
    assert _policy_count(api) == 0


def _expires(days: int) -> str:
    return (datetime.now(timezone.utc).date() + timedelta(days=days)).isoformat()


@pytest.mark.parametrize("spec", [
    pytest.param({"deny": {"codes": ["NOT_A_REAL_CODE"]}}, id="unknown-code"),
    pytest.param({"exceptions": [{"package": "internal-tool", "expires": _expires(366),
                                  "reason": "Reviewed internal build tool"}]}, id="exception-beyond-365-days"),
    pytest.param({"exceptions": [{"package": "internal-tool", "codes": ["IOC_MATCH"], "expires": _expires(30),
                                  "reason": "Reviewed internal build tool"}]}, id="exception-for-ioc"),
    pytest.param({"deny": {"min_confidence": 1.5}}, id="confidence-out-of-range"),
])
def test_invalid_documents_are_rejected_on_create(api, spec):
    resp = _create(api, _document(name="api-invalid", **spec))
    assert resp.status_code == 422, resp.text
    assert _policy_count(api) == 0


def test_update_requires_the_document_and_audits_hashes_and_changed_fields(api):
    created = _create(api, _document(name="api-update", thresholds={"warn": 40, "block": 70})).json()
    pid = created["id"]
    # A v1-style PUT would leave the stored document and the legacy columns disagreeing.
    v1 = api.client.put(f"{API}/policies/{pid}", headers=api.headers[Role.admin],
                        json={"name": "api-update", "block_threshold": 60})
    assert v1.status_code == 409, v1.text

    changed = _document(name="api-update", thresholds={"warn": 40, "block": 60}, deny={"codes": ["DYNAMIC_EXEC"]})
    resp = api.client.put(f"{API}/policies/{pid}", headers=api.headers[Role.admin], json={"document": changed})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"] == 2 and body["block_threshold"] == 60
    assert body["policy_hash"] == validate_policy_data(changed).policy_hash != created["policy_hash"]
    [update_audit] = _audit(api, "policy.update", pid)
    assert update_audit["policy_hash_before"] == created["policy_hash"]
    assert update_audit["policy_hash"] == body["policy_hash"]
    assert {"block_threshold", "document"} <= set(update_audit["changed_fields"])
    assert set(update_audit["changes"]["document"]["changed_paths"]) == {"spec.thresholds.block", "spec.deny.codes"}

    # An explicit null converts the policy back to legacy columns; its hash is then the derived document's.
    back = api.client.put(f"{API}/policies/{pid}", headers=api.headers[Role.admin],
                          json={"name": "api-update", "document": None, "warn_threshold": 40, "block_threshold": 60})
    assert back.status_code == 200, back.text
    assert back.json()["document"] is None
    with api.factory() as db:
        assert back.json()["policy_hash"] == from_legacy(db.get(Policy, uuid.UUID(pid))).policy_hash


def test_non_admin_roles_cannot_update_documents(api):
    pid = _create(api, _document(name="api-guarded")).json()["id"]
    for role in ROLES[1:]:
        resp = api.client.put(f"{API}/policies/{pid}", headers=api.headers[role],
                              json={"document": _document(name="api-guarded", thresholds={"block": 99})})
        assert resp.status_code == 403, resp.text


# =========================================================================== scan evaluation
def test_scans_use_the_active_policy_of_their_environment_with_production_fallback(api):
    default = _scan(api, "templated-env", "staging")
    assert default["decision"] == "allow" and _evaluation(default)["policy_hash"] == policy_hash_of(None)

    prod = _active_document_policy(api, name="api-prod", deny={"codes": ["DYNAMIC_EXEC"]})
    fallback = _scan(api, "templated-env", "staging")
    assert fallback["decision"] == "block" and fallback["matched_policy_rules"] == ["deny_code:DYNAMIC_EXEC"]
    record = _evaluation(fallback)
    assert (record["policy_hash"], record["environment"], record["effect"]) == (prod["policy_hash"], "staging", "info")
    assert _audit(api, "scan.create")[-1]["policy_hash"] == prod["policy_hash"]

    staging = _active_document_policy(api, name="api-staging", environment="staging",
                                      warn={"codes": ["DYNAMIC_EXEC"]})
    own = _scan(api, "templated-env", "staging")
    assert own["decision"] == "warn" and _evaluation(own)["policy_hash"] == staging["policy_hash"]
    assert _scan(api, "templated-env", "production")["decision"] == "block"


def test_approved_exception_applies_only_within_its_scope_and_lifetime(api):
    prod = _active_document_policy(api, name="api-prod", deny={"codes": ["DYNAMIC_EXEC"]})
    name = "Templated_Engine"
    assert _scan(api, name)["decision"] == "block"

    exception_id = _request_exception(api, package=name, codes=["DYNAMIC_EXEC"], policy_id=prod["id"],
                                      environment="production")
    pending = _scan(api, name)
    assert pending["decision"] == "block" and _evaluation(pending)["exceptions_applied"] == []

    _approve(api, exception_id)
    allowed = _scan(api, name)
    assert allowed["decision"] == "allow", allowed["policy_reasons"]
    [applied] = _evaluation(allowed)["exceptions_applied"]
    assert applied["id"] == exception_id and applied["source"] == "database" and applied["codes"] == ["DYNAMIC_EXEC"]
    assert [r["exception_id"] for r in allowed["policy_reasons"] if r["effect"] == "exempt"] == [exception_id]
    assert _audit(api, "scan.create")[-1]["exceptions_applied"] == [exception_id]

    # Scoped to production: a staging scan evaluated under the fallback production policy is not exempt.
    assert _scan(api, name, "staging")["decision"] == "block"

    with api.factory() as db:
        db.execute(update(PolicyException).where(PolicyException.id == uuid.UUID(exception_id))
                   .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        db.commit()
    expired = _scan(api, name)
    assert expired["decision"] == "block" and _evaluation(expired)["exceptions_applied"] == []


def test_revoked_exception_stops_applying(api):
    _active_document_policy(api, name="api-prod", deny={"codes": ["DYNAMIC_EXEC"]})
    exception_id = _request_exception(api, package="templated-revoked", codes=["DYNAMIC_EXEC"])
    _approve(api, exception_id)
    assert _scan(api, "templated-revoked")["decision"] == "allow"
    resp = api.client.post(f"{API}/policies/exceptions/{exception_id}/revoke",
                           headers=api.headers[Role.security_analyst])
    assert resp.status_code == 200, resp.text
    assert _scan(api, "templated-revoked")["decision"] == "block"


@pytest.mark.parametrize("self_approved", [True, False], ids=["self-approved", "no-approver"])
def test_approved_rows_written_around_the_workflow_never_apply(api, self_approved):
    _active_document_policy(api, name="api-prod", deny={"codes": ["DYNAMIC_EXEC"]})
    requester = api.user_ids[Role.developer]
    with api.factory() as db:
        db.add(PolicyException(
            id=uuid.uuid4(), package="templated-tampered", codes=["DYNAMIC_EXEC"], categories=[],
            justification="Written directly to the database (fixture)", requested_by=requester,
            approved_by=requester if self_approved else None, status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        ))
        db.commit()
    body = _scan(api, "templated-tampered")
    assert body["decision"] == "block" and _evaluation(body)["exceptions_applied"] == []


def test_known_malicious_indicator_blocks_despite_an_approved_exception_and_the_allowlist(api):
    _active_document_policy(api, name="api-prod", allow={"packages": ["ioc-sample"]})
    _approve(api, _request_exception(api, package="ioc-sample"))  # unscoped: the whole package
    body = _scan(api, "ioc-sample")
    assert body["decision"] == "block" and body["matched_policy_rules"] == ["known_malicious_indicator"]
    assert _evaluation(body)["exceptions_applied"] == []


def test_shipped_production_policy_warns_when_vulnerability_intelligence_is_unavailable(api):
    created = _create(api, load_policy_text(SHIPPED["production"]).to_dict())
    assert created.status_code == 201, created.text
    api.client.post(f"{API}/policies/{created.json()['id']}/activate", headers=api.headers[Role.admin])

    api.orchestrator.intel_status = "unavailable"
    offline = _scan(api, "plain-offline")
    assert offline["decision"] == "warn" and offline["matched_policy_rules"] == ["vulnerability_status_unknown"]
    api.orchestrator.intel_status = "ok"
    online = _scan(api, "plain-online")
    assert online["decision"] == "allow" and online["matched_policy_rules"] == ["clean"]
