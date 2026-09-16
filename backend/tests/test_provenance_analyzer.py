"""Provenance & trust analyzer tests: PEP 740 attestations, repository consistency, maintainer transitions, dormancy.

All HTTP is mocked with respx (the conftest network guard fails any real connection). The provenance documents in
``tests/data/provenance/`` and every registry JSON body below are hand-written FIXTURES modelled on the documented
formats (https://docs.pypi.org/api/integrity/, PEP 740, https://docs.pypi.org/api/json/). Certificates, signatures
and transparency-log entries in them are placeholders, not real Sigstore material. Nothing here is executed.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from app.analysis import orchestrator as orch
from app.analysis import risk, scoring, taxonomy
from app.analysis.acquisition import pypi as pypi_module
from app.analysis.acquisition.pypi import (
    INTEGRITY_ACCEPT,
    LOOKUP_ERROR,
    LOOKUP_FOUND,
    LOOKUP_INVALID_INPUT,
    LOOKUP_MALFORMED,
    LOOKUP_NOT_FOUND,
    PyPIClient,
)
from app.analysis.analyzers import provenance as prov
from app.analysis.analyzers.base import ArtifactInfo, BaseAnalyzer, PackageContext, ScanOptions
from app.analysis.analyzers.provenance import (
    DeclaredRepository,
    ProvenanceAnalyzer,
    ProvenanceState,
    PublisherIdentity,
    assess_attestations,
    assess_dormancy,
    compare_repository,
    declared_repositories,
    diff_maintainers,
    extract_identities,
    mask_email,
    names_overlap,
    normalise_repository_url,
    publisher_repository,
    same_distribution,
    shared_organisation_domains,
)
from app.analysis.fetcher import _hash_mismatch
from app.analysis.findings import Finding, Provenance, Severity
from app.analysis.signals import Code
from app.analysis.taxonomy import Dimension
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import OutboundHTTPError, SafeHttpClient

DATA = Path(__file__).parent / "data" / "provenance"
# FIXTURE: stand-in artifact bytes; the fixture statements attest sha256(FIXTURE_SDIST).
FIXTURE_SDIST = b"FIXTURE: stand-in bytes for sampleproject-4.0.0.tar.gz (not a real archive)\n"
SHA = hashlib.sha256(FIXTURE_SDIST).hexdigest()
OTHER_SHA = hashlib.sha256(b"FIXTURE: different bytes").hexdigest()
FILENAME = "sampleproject-4.0.0.tar.gz"
PROV_URL = f"https://pypi.org/integrity/sampleproject/4.0.0/{FILENAME}/provenance"
PREV_URL = "https://pypi.org/pypi/sampleproject/3.0.0/json"
CHECKED = datetime(2026, 9, 15, 12, 30, 45, 123456, tzinfo=timezone.utc)
CHECKED_ISO = "2026-09-15T12:30:45+00:00"
SUMMARY_KEYS = {"state", "hash_verified", "attestation_present", "publisher", "checked_at"}
ATTESTATION_CODES = (Code.PROVENANCE_ATTESTED, Code.PROVENANCE_UNVERIFIED, Code.PROVENANCE_FAILED)
GITHUB_PUBLISHER = {"kind": "GitHub", "repository": "pypa/sampleproject", "workflow": "release.yml",
                    "environment": None}
_DEFAULT = object()


# --------------------------------------------------------------------------- helpers
def load(name: str = "integrity_provenance_github.json") -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def encode_statement(body: object) -> str:
    return base64.b64encode(json.dumps(body).encode()).decode()


def statement(name: str = FILENAME, sha: str = SHA, **overrides) -> dict:
    body = {"_type": prov.INTOTO_STATEMENT_V1, "subject": [{"name": name, "digest": {"sha256": sha}}],
            "predicateType": prov.PYPI_PUBLISH_PREDICATE_V1, "predicate": None}
    body.update(overrides)
    return body


def _bundle(doc: dict) -> dict:
    return doc["attestation_bundles"][0]


def _att(doc: dict) -> dict:
    return _bundle(doc)["attestations"][0]


def _put_statement(doc: dict, body: object) -> None:
    _att(doc)["envelope"]["statement"] = body if isinstance(body, str) else encode_statement(body)


def doc_with(body: object, *, doc: dict | None = None) -> dict:
    doc = copy.deepcopy(doc if doc is not None else load())
    _put_statement(doc, body)
    return doc


def with_publisher(doc: dict | None = None, **publisher) -> dict:
    doc = copy.deepcopy(doc if doc is not None else load())
    _bundle(doc)["publisher"] = publisher
    return doc


def artifact(*, registry_sha: str | None = SHA, downloaded: str | None = SHA, verified: bool | None = True,
             filename: str = FILENAME) -> ArtifactInfo:
    return ArtifactInfo(filename=filename, url=f"https://files.pythonhosted.org/packages/ab/cd/{filename}",
                        packagetype="sdist", size=len(FIXTURE_SDIST),
                        digests={"sha256": registry_sha} if registry_sha else {},
                        downloaded_sha256=downloaded, hash_verified=verified)


def make_ctx(*, metadata: dict | None = None, art: object = _DEFAULT, options: ScanOptions | None = None,
             signals: list | None = None, ecosystem: str = "pypi", name: str = "sampleproject") -> PackageContext:
    return PackageContext(
        ecosystem=ecosystem, name=name, version="4.0.0", metadata=metadata or {},
        analyzed_artifact=artifact() if art is _DEFAULT else art,
        context_signals=list(signals or []), options=options or ScanOptions(),
    )


def pypi_client() -> PyPIClient:
    registry = SafeHttpClient(name="t-registry", allowed_hosts=["pypi.org"], retries=0, sleep=lambda s: None)
    no_downloads = SafeHttpClient(name="t-artifacts", allowed_hosts=(), retries=0, sleep=lambda s: None)
    return PyPIClient(registry_http=registry, artifact_http=no_downloads)


def analyzer() -> ProvenanceAnalyzer:
    return ProvenanceAnalyzer(client=pypi_client(), clock=lambda: CHECKED)


def never_construct() -> PyPIClient:
    raise AssertionError("the PyPI client must not be constructed")


def offline_analyzer() -> ProvenanceAnalyzer:
    return ProvenanceAnalyzer(client_factory=never_construct, clock=lambda: CHECKED)


def only(findings: list[Finding], code: str) -> Finding:
    matches = [f for f in findings if f.code == code]
    assert len(matches) == 1, [f.code for f in findings]
    return matches[0]


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


def run(ctx: PackageContext, a: ProvenanceAnalyzer | None = None) -> list[Finding]:
    """Analyze and check the contract every provenance finding must satisfy."""
    findings = (a or analyzer()).analyze(ctx)
    assert sum(1 for f in findings if f.code in ATTESTATION_CODES) == 1
    for f in findings:
        assert isinstance(f, Finding)
        summary = f.evidence["provenance_summary"]
        assert set(summary) == SUMMARY_KEYS
        assert summary["state"] in ProvenanceState.EMITTED and summary["state"] != ProvenanceState.VERIFIED
        assert f.location is None  # release-level findings: no invented positions
        assert f.provenance == Provenance.REGISTRY
        stamped = f.with_defaults(analyzer="provenance", analyzer_version=prov.ANALYZER_VERSION)
        again = Finding.from_dict(json.loads(json.dumps(stamped.to_dict())))
        assert again.finding_id == stamped.finding_id
        assert stamped.category == "provenance"
    assert len({json.dumps(f.evidence["provenance_summary"], sort_keys=True) for f in findings}) == 1
    return findings


def release_json(**info) -> dict:
    """FIXTURE: shape of https://pypi.org/pypi/<name>/<version>/json (docs.pypi.org/api/json), trimmed."""
    base = {"name": "sampleproject", "version": "3.0.0", "summary": "A sample Python project", "author": None,
            "author_email": None, "maintainer": None, "maintainer_email": None, "project_urls": None}
    base.update(info)
    return {"info": base, "urls": []}


@pytest.fixture
def online(monkeypatch):
    """Enable lookups (conftest runs the suite with INTEL_OFFLINE=true, PROVENANCE_ENABLED=false)."""
    monkeypatch.setattr(settings, "INTEL_OFFLINE", False)
    monkeypatch.setattr(settings, "PROVENANCE_ENABLED", True)


class _NoModel:
    available = False
    metadata: dict = {}

    def predict(self, features):
        return 0, 0.0


class _NullCache:
    def get_json(self, key):
        return None

    def set_json(self, key, value, ttl):
        return None


# --------------------------------------------------------------------------- fixtures / contract
def test_fixture_documents_follow_documented_shape_and_attest_fixture_bytes():
    for name, kind in (("integrity_provenance_github.json", "GitHub"), ("integrity_provenance_gitlab.json", "GitLab")):
        doc = load(name)
        assert doc["_fixture"].startswith("FIXTURE") and doc["version"] == 1
        assert _bundle(doc)["publisher"]["kind"] == kind
        att = _att(doc)
        assert att["version"] == 1 and att["verification_material"]["transparency_entries"]
        body = json.loads(base64.b64decode(att["envelope"]["statement"]))
        assert body["_type"] == "https://in-toto.io/Statement/v1"
        assert body["subject"] == [{"name": FILENAME, "digest": {"sha256": SHA}}]
        assert body["predicateType"] == "https://docs.pypi.org/attestations/publish/v1"


def test_analyzer_attributes_lazy_client_and_pipeline_wiring():
    a = ProvenanceAnalyzer(client_factory=never_construct)  # constructing performs no client setup
    assert isinstance(a, BaseAnalyzer)
    assert (a.name, a.version, a.requires_network) == ("provenance", "1.0.0", False)
    status = a.availability()
    assert status.available and "INTEL_OFFLINE=true" in status.detail  # the suite runs offline
    assert "provenance" in risk.DIMENSION_ANALYZERS[Dimension.PROVENANCE]
    assert prov.FETCH_STAGE_NAME == orch.FETCH_STAGE_NAME
    for code in (*ATTESTATION_CODES, Code.REPO_MISMATCH, Code.MAINTAINER_CHANGED, Code.DORMANT_REVIVAL):
        assert taxonomy.dimension_for(code) == Dimension.PROVENANCE
    assert ProvenanceState.VERIFIED not in ProvenanceState.EMITTED


def test_availability_reports_lookups_when_enabled(online):
    assert "Integrity API" in ProvenanceAnalyzer(client_factory=never_construct).availability().detail


def test_default_client_is_registry_only_bounded_and_refuses_downloads():
    client = prov.default_client()
    assert client.registry_http.allowed_hosts == frozenset(settings.REGISTRY_HOST_ALLOWLIST)
    assert 0 < client.registry_http.total_timeout <= settings.ANALYZER_TIMEOUT_SECONDS
    with respx.mock() as router, pytest.raises(OutboundHTTPError) as info:
        client.download(ArtifactInfo(filename=FILENAME, url=f"https://files.pythonhosted.org/{FILENAME}",
                                     packagetype="sdist"))
    assert info.value.kind == "host_not_allowed" and router.calls.call_count == 0


# --------------------------------------------------------------------------- Integrity API states
@respx.mock
def test_integrity_api_404_is_unknown(online):
    route = respx.get(PROV_URL).mock(return_value=httpx.Response(404))
    findings = run(make_ctx())
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED]
    f = findings[0]
    assert route.calls.last.request.headers["accept"] == "application/vnd.pypi.integrity.v1+json"
    assert (f.severity, f.weight, f.confidence) == (Severity.info, 0.0, 1.0)
    assert (f.evidence["state"], f.evidence["reason"], f.evidence["lookup"]) == ("unknown", "no_attestation",
                                                                                 "not_found")
    assert f.evidence["checks"] == {"maintainer": "no_previous_release", "dormancy": "insufficient_data"}
    assert f.evidence["provenance_summary"] == {"state": "unknown", "hash_verified": True,
                                                "attestation_present": False, "publisher": None,
                                                "checked_at": CHECKED_ISO}


@respx.mock
def test_matching_subject_digest_is_partially_verified_and_never_verified(online):
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load()))
    findings = run(make_ctx(metadata={"project_urls": {"Source": "https://github.com/pypa/sampleproject"}}))
    assert codes(findings) == [Code.PROVENANCE_ATTESTED]
    f = findings[0]
    ev = f.evidence
    assert (f.severity, f.weight, f.confidence) == (Severity.info, 0.0, 0.9)
    assert (ev["state"], ev["reason"]) == ("partially_verified", "subject_digest_bound")
    assert ev["signature_verified"] is False and ev["verification"] == "subject_binding_only"
    assert (ev["attestations_examined"], ev["attestations_bound"], ev["attestations_mismatched"]) == (1, 1, 0)
    assert ev["predicate_types"] == [prov.PYPI_PUBLISH_PREDICATE_V1] and "unrecognised_predicate_types" not in ev
    assert ev["publishers"] == [GITHUB_PUBLISHER] and "mismatch" not in ev
    assert ev["provenance_summary"] == {"state": "partially_verified", "hash_verified": True,
                                        "attestation_present": True, "publisher": GITHUB_PUBLISHER,
                                        "checked_at": CHECKED_ISO}
    assert "not cryptographically verified" in f.message


@respx.mock
def test_gitlab_publisher_fields_are_mapped(online):
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load("integrity_provenance_gitlab.json")))
    md = {"project_urls": {"Repository": "https://gitlab.com/example-group/tools/sampleproject/-/tree/main"}}
    findings = run(make_ctx(metadata=md))
    assert codes(findings) == [Code.PROVENANCE_ATTESTED]
    assert findings[0].evidence["provenance_summary"]["publisher"] == {
        "kind": "GitLab", "repository": "example-group/tools/sampleproject", "workflow": ".gitlab-ci.yml",
        "environment": "release"}


@respx.mock
def test_mismatching_subject_digest_fails(online):
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc_with(statement(sha=OTHER_SHA))))
    findings = run(make_ctx())
    assert codes(findings) == [Code.PROVENANCE_FAILED]
    f = findings[0]
    assert (f.severity, f.weight, f.confidence) == (Severity.critical, 10.0, 0.9)
    assert (f.evidence["state"], f.evidence["reason"]) == ("failed", "subject_mismatch")
    assert f.evidence["mismatch"] == {"subject_name": FILENAME, "name_matches": True, "digest_matches": False,
                                      "subject_digest_prefix": OTHER_SHA[:12], "artifact_digest_prefix": SHA[:12]}
    assert f.evidence["provenance_summary"]["attestation_present"] is True
    assert "sha256 digest" in f.message and "HASH_MISMATCH" not in f.message


@respx.mock
def test_subject_naming_another_distribution_fails(online):
    wheel = "sampleproject-4.0.0-py3-none-any.whl"
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc_with(statement(name=wheel))))
    f = only(run(make_ctx()), Code.PROVENANCE_FAILED)
    assert f.evidence["mismatch"]["name_matches"] is False and f.evidence["mismatch"]["digest_matches"] is True
    assert "distribution filename" in f.message


@respx.mock
def test_upper_case_hex_and_unpadded_urlsafe_statement_still_bind(online):
    raw = json.dumps(statement(sha=SHA.upper())).encode()
    urlsafe = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc_with(urlsafe)))
    assert codes(run(make_ctx())) == [Code.PROVENANCE_ATTESTED]


@respx.mock
@pytest.mark.parametrize(("response", "reason"), [
    (httpx.Response(200, content=b"<html>maintenance</html>"), "invalid_json"),
    (httpx.Response(200, json=[1, 2, 3]), "not_an_object"),
])
def test_malformed_integrity_response_fails(online, response, reason):
    respx.get(PROV_URL).mock(return_value=response)
    findings = run(make_ctx(metadata={"project_urls": {"Source": "https://github.com/someone-else/project"}}))
    assert codes(findings) == [Code.PROVENANCE_FAILED]  # no REPO_MISMATCH from an unusable document
    f = findings[0]
    assert (f.evidence["state"], f.evidence["reason"], f.evidence["malformed_reason"]) == (
        "failed", "malformed_document", reason)
    assert f.evidence["provenance_summary"]["attestation_present"] is True
    assert "malformed" in f.message


@respx.mock
@pytest.mark.parametrize(("mock", "kind", "http_status"), [
    ({"side_effect": httpx.ConnectError("connection refused")}, "network", None),
    ({"side_effect": httpx.ReadTimeout("slow")}, "network", None),
    ({"return_value": httpx.Response(503)}, "status", 503),
    ({"return_value": httpx.Response(403)}, "status", 403),  # "temporarily disabled by PyPI administrators"
    ({"return_value": httpx.Response(406)}, "status", 406),
    ({"return_value": httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/meta-data"})},
     "host_not_allowed", None),
], ids=["connect", "timeout", "503", "403", "406", "redirect-to-internal-host"])
def test_lookup_errors_are_unknown_with_error_kind_never_failed(online, mock, kind, http_status):
    respx.get(PROV_URL).mock(**mock)
    findings = run(make_ctx())
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED]
    f = findings[0]
    assert (f.evidence["state"], f.evidence["reason"], f.evidence["lookup"]) == ("unknown", "lookup_error", "error")
    assert f.evidence["error_kind"] == kind and f.evidence.get("http_status") == http_status
    assert f.evidence["provenance_summary"]["attestation_present"] is None
    assert f.evidence["provenance_summary"]["checked_at"] == CHECKED_ISO
    assert "not failed" in f.message


@respx.mock
def test_oversized_provenance_response_is_unknown_not_failed(online, monkeypatch):
    monkeypatch.setattr(pypi_module, "MAX_PROVENANCE_BYTES", 64)
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load()))
    f = only(run(make_ctx()), Code.PROVENANCE_UNVERIFIED)
    assert (f.evidence["reason"], f.evidence["error_kind"]) == ("lookup_error", "too_large")


@respx.mock
def test_invalid_coordinates_make_no_request_and_are_unknown(online):
    findings = run(make_ctx(name="../../admin"))
    f = only(findings, Code.PROVENANCE_UNVERIFIED)
    assert (f.evidence["reason"], f.evidence["error_kind"]) == ("invalid_coordinates", "invalid_coordinates")
    assert respx.calls.call_count == 0


# --------------------------------------------------------------------------- HASH_MISMATCH interplay
@respx.mock
def test_attested_published_bytes_vs_tampered_download_fails_and_references_hash_mismatch(online, monkeypatch):
    tampered = artifact(registry_sha=SHA, downloaded=OTHER_SHA, verified=False)
    hash_signal = _hash_mismatch(tampered)
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load()))  # attests SHA, the published bytes
    ctx = make_ctx(art=tampered, signals=[hash_signal])
    findings = run(ctx)
    assert codes(findings) == [Code.PROVENANCE_FAILED]  # HASH_MISMATCH is referenced, never re-emitted
    f = findings[0]
    stamped = hash_signal.with_defaults(analyzer=orch.FETCH_STAGE_NAME, analyzer_version=settings.ANALYZER_VERSION)
    assert f.related == (stamped.finding_id,)
    assert f.evidence["hash_mismatch_reported"] is True
    assert f.evidence["provenance_summary"]["hash_verified"] is False
    assert "HASH_MISMATCH" in f.message

    summary = orch.provenance_summary([stamped, *(x.with_defaults(analyzer="provenance") for x in findings)], ctx)
    assert summary["status"] == "failed" and summary["hash_verified"] is False
    assert stamped.finding_id in summary["finding_ids"]


@respx.mock
def test_attestation_binding_download_whose_registry_digest_differs_is_unknown(online):
    art = artifact(registry_sha=OTHER_SHA, downloaded=SHA, verified=False)
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load()))
    f = only(run(make_ctx(art=art, signals=[_hash_mismatch(art)])), Code.PROVENANCE_UNVERIFIED)
    assert f.evidence["reason"] == "registry_digest_mismatch" and f.evidence["hash_mismatch_reported"] is True
    assert f.evidence["provenance_summary"]["attestation_present"] is True
    assert f.evidence["provenance_summary"]["hash_verified"] is False


@respx.mock
@pytest.mark.parametrize(("art", "reason"), [
    (artifact(registry_sha=None, verified=None), "registry_digest_unavailable"),
    (artifact(downloaded=None, verified=None), "artifact_digest_unavailable"),
])
def test_attestation_without_a_verified_registry_digest_is_not_partially_verified(online, art, reason):
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=load()))
    f = only(run(make_ctx(art=art)), Code.PROVENANCE_UNVERIFIED)
    assert f.evidence["reason"] == reason
    assert f.evidence["provenance_summary"]["publisher"] == GITHUB_PUBLISHER


@respx.mock
def test_one_mismatching_attestation_among_matching_ones_fails(online):
    doc = load()
    bad = copy.deepcopy(_att(doc))
    bad["envelope"]["statement"] = encode_statement(statement(sha=OTHER_SHA))
    _bundle(doc)["attestations"].append(bad)
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    f = only(run(make_ctx()), Code.PROVENANCE_FAILED)
    assert (f.evidence["attestations_bound"], f.evidence["attestations_mismatched"]) == (1, 1)


# --------------------------------------------------------------------------- malformed documents
MALFORMED = [
    ("version-missing", lambda d: d.pop("version"), "document_version_invalid"),
    ("version-bool", lambda d: d.update(version=True), "document_version_invalid"),
    ("version-string", lambda d: d.update(version="1"), "document_version_invalid"),
    ("bundles-not-list", lambda d: d.update(attestation_bundles={"0": {}}), "attestation_bundles_not_list"),
    ("bundles-empty", lambda d: d.update(attestation_bundles=[]), "no_attestation_bundles"),
    ("bundle-not-object", lambda d: d.update(attestation_bundles=["bundle"]), "bundle_not_object"),
    ("publisher-missing", lambda d: _bundle(d).pop("publisher"), "publisher_not_object"),
    ("publisher-kind-blank", lambda d: _bundle(d)["publisher"].update(kind=" "), "publisher_kind_invalid"),
    ("publisher-repository-object", lambda d: _bundle(d)["publisher"].update(repository={"owner": "pypa"}),
     "publisher_repository_invalid"),
    ("github-publisher-workflow-list", lambda d: _bundle(d)["publisher"].update(workflow=["release.yml"]),
     "publisher_workflow_invalid"),
    ("attestations-not-list", lambda d: _bundle(d).update(attestations="x"), "attestations_not_list"),
    ("attestations-empty", lambda d: _bundle(d).update(attestations=[]), "no_attestations"),
    ("attestation-not-object", lambda d: _bundle(d).update(attestations=[42]), "attestation_not_object"),
    ("attestation-version-string", lambda d: _att(d).update(version="1"), "attestation_version_invalid"),
    ("attestation-version-missing", lambda d: _att(d).pop("version"), "attestation_version_invalid"),
    ("verification-material-missing", lambda d: _att(d).pop("verification_material"),
     "verification_material_missing"),
    ("certificate-empty", lambda d: _att(d)["verification_material"].update(certificate=""), "certificate_missing"),
    ("transparency-entries-empty", lambda d: _att(d)["verification_material"].update(transparency_entries=[]),
     "transparency_entries_missing"),
    ("envelope-not-object", lambda d: _att(d).update(envelope="x"), "envelope_missing"),
    ("signature-missing", lambda d: _att(d)["envelope"].pop("signature"), "signature_missing"),
    ("statement-empty", lambda d: _att(d)["envelope"].update(statement=""), "statement_missing"),
    ("statement-not-base64", lambda d: _put_statement(d, "!!! not base64 !!!"), "statement_not_base64"),
    ("statement-not-json", lambda d: _put_statement(d, base64.b64encode(b"not json").decode()),
     "statement_not_json"),
    ("statement-not-utf8", lambda d: _put_statement(d, base64.b64encode(b"\xff\xfe{}").decode()),
     "statement_not_json"),
    ("statement-nesting-bomb", lambda d: _put_statement(d, base64.b64encode(b"[" * 20000 + b"]" * 20000).decode()),
     "statement_not_json"),
    ("statement-huge-integer", lambda d: _put_statement(d, base64.b64encode(b"1" * 30000).decode()),
     "statement_not_json"),
    ("statement-array", lambda d: _put_statement(d, [statement()]), "statement_not_object"),
    ("statement-type-missing", lambda d: _put_statement(d, {k: v for k, v in statement().items() if k != "_type"}),
     "statement_type_missing"),
    ("statement-type-number", lambda d: _put_statement(d, statement(_type=1)), "statement_type_missing"),
    ("predicate-type-missing", lambda d: _put_statement(d, {k: v for k, v in statement().items()
                                                            if k != "predicateType"}), "predicate_type_missing"),
    ("two-subjects",
     lambda d: _put_statement(d, statement(subject=[{"name": FILENAME, "digest": {"sha256": SHA}}] * 2)),
     "subject_count_invalid"),
    ("no-subject", lambda d: _put_statement(d, statement(subject=[])), "subject_count_invalid"),
    ("subject-not-object", lambda d: _put_statement(d, statement(subject=["x"])), "subject_not_object"),
    ("subject-name-empty", lambda d: _put_statement(d, statement(name="")), "subject_name_invalid"),
    ("subject-sha512-only", lambda d: _put_statement(d, statement(subject=[{"name": FILENAME,
                                                                              "digest": {"sha512": "ab" * 64}}])),
     "subject_sha256_invalid"),
    ("subject-sha256-not-hex", lambda d: _put_statement(d, statement(sha="z" * 64)), "subject_sha256_invalid"),
    ("subject-sha256-truncated", lambda d: _put_statement(d, statement(sha=SHA[:40])), "subject_sha256_invalid"),
]


@pytest.mark.parametrize(("mutate", "reason"), [(m, r) for _, m, r in MALFORMED], ids=[i for i, _, _ in MALFORMED])
def test_malformed_provenance_documents_fail_with_a_reason(mutate, reason):
    doc = load()
    mutate(doc)
    started = time.monotonic()
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert time.monotonic() - started < 2.0
    assert (assessment.state, assessment.reason, assessment.malformed_reason) == (
        ProvenanceState.FAILED, "malformed_document", reason)
    assert not assessment.structurally_valid
    assert "attestations_bound" not in assessment.evidence()


@pytest.mark.parametrize("document", [None, [], "provenance", 1, {"attestation_bundles": []}])
def test_non_object_or_versionless_documents_are_malformed(document):
    assert assess_attestations(document, filename=FILENAME, downloaded_sha256=SHA,
                               hash_verified=True).state == ProvenanceState.FAILED


@respx.mock
def test_structurally_invalid_statement_suppresses_repo_mismatch(online):
    doc = doc_with("!!! not base64 !!!", doc=with_publisher(kind="GitHub", repository="attacker-org/sampleproject",
                                                             workflow="release.yml"))
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    md = {"project_urls": {"Source": "https://github.com/pypa/sampleproject"}}
    assert codes(run(make_ctx(metadata=md))) == [Code.PROVENANCE_FAILED]


UNSUPPORTED = [
    ("document-version-2", lambda d: d.update(version=2), "unsupported_format", "document_version_unsupported"),
    ("attestation-version-2", lambda d: _att(d).update(version=2), "attestation_not_examinable",
     "attestation_version_unsupported"),
    ("statement-v0.1", lambda d: _put_statement(d, statement(_type="https://in-toto.io/Statement/v0.1")),
     "attestation_not_examinable", "statement_type_unsupported"),
]


@pytest.mark.parametrize(("mutate", "reason", "detail"), [(m, r, x) for _, m, r, x in UNSUPPORTED],
                         ids=[i for i, _, _, _ in UNSUPPORTED])
def test_well_typed_but_unsupported_format_versions_are_unknown_not_failed(mutate, reason, detail):
    # A future PyPI format must not flip every attested package to a critical FAILED verdict.
    doc = load()
    mutate(doc)
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert (assessment.state, assessment.reason) == (ProvenanceState.UNKNOWN, reason)
    assert assessment.evidence()["not_examinable_reasons"] == [detail]


@respx.mock
def test_unsupported_document_version_through_the_analyzer_is_unknown_with_attestation_present(online):
    doc = load()
    doc["version"] = 2
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    f = only(run(make_ctx(metadata={"project_urls": {"Source": "https://github.com/someone-else/x"}})),
             Code.PROVENANCE_UNVERIFIED)
    assert (f.evidence["state"], f.evidence["reason"]) == ("unknown", "unsupported_format")
    assert f.evidence["provenance_summary"]["attestation_present"] is True
    assert "does not support" in f.message


def test_supported_attestation_still_binds_next_to_an_unsupported_one():
    doc = load()
    newer = copy.deepcopy(_att(doc))
    newer["version"] = 2
    _bundle(doc)["attestations"].append(newer)
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert (assessment.state, assessment.bound, assessment.not_examinable) == (
        ProvenanceState.PARTIALLY_VERIFIED, 1, 1)
    assert assessment.evidence()["not_examinable_reasons"] == ["attestation_version_unsupported"]


def test_other_publisher_kinds_may_carry_arbitrary_extra_fields():
    # PEP 740 Publisher: ``kind``, ``claims`` and any additional fields; only GitHub/GitLab fields are typed.
    doc = with_publisher(kind="ActiveState", organization="example-org", actor="release-bot", project="sample",
                         repository={"url": "https://example.invalid"}, workflow=["build"], claims=None)
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert assessment.state == ProvenanceState.PARTIALLY_VERIFIED
    assert assessment.publishers == [PublisherIdentity("ActiveState")]


def test_unknown_fields_and_unrecognised_predicate_types_are_recorded_not_failed():
    doc = doc_with(statement(predicateType="https://example.invalid/custom-predicate/v9"))
    doc["future_field"] = {"anything": True}
    _att(doc)["future_attestation_field"] = 1
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert assessment.state == ProvenanceState.PARTIALLY_VERIFIED
    assert assessment.evidence()["unrecognised_predicate_types"] == ["https://example.invalid/custom-predicate/v9"]


# --------------------------------------------------------------------------- bounds
def test_examination_is_bounded_for_huge_documents():
    doc = load()
    bundle = _bundle(doc)
    bundle["attestations"] = bundle["attestations"] * 50  # shared references: cheap to build
    doc["attestation_bundles"] = [bundle] * 1000
    started = time.monotonic()
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert time.monotonic() - started < 2.0
    assert assessment.examined == prov.MAX_ATTESTATIONS == 16 and assessment.bound == 16
    assert assessment.bundles_not_examined == 1000 - prov.MAX_BUNDLES
    assert assessment.not_examined == (50 - 8) * 2 + 50 * 6
    assert assessment.state == ProvenanceState.PARTIALLY_VERIFIED
    assert len(assessment.publishers) == 1  # de-duplicated


def test_oversized_statement_is_not_examined_and_reads_unknown():
    doc = doc_with("A" * (prov.MAX_STATEMENT_CHARS + 4))
    assessment = assess_attestations(doc, filename=FILENAME, downloaded_sha256=SHA, hash_verified=True)
    assert (assessment.state, assessment.reason, assessment.not_examinable) == (
        ProvenanceState.UNKNOWN, "attestation_not_examinable", 1)


@pytest.mark.parametrize(("subject", "expected"), [
    (FILENAME, True),
    ("SampleProject-4.0.0.tar.gz", True),  # project names compare normalised
    ("sampleproject-4.0.tar.gz", True),  # PEP 440: 4.0 == 4.0.0
    ("sampleproject-4.0.1.tar.gz", False),
    ("sampleproject-4.0.0.zip", False),
    ("sampleproject-4.0.0-py3-none-any.whl", False),
    ("othername-4.0.0.tar.gz", False),
    ("../sampleproject-4.0.0.tar.gz", False),
    ("sampleproject-4.0.0.tar.gz‮", False),
    ("x" * 300, False),
])
def test_same_distribution(subject, expected):
    assert same_distribution(subject, FILENAME) is expected


def test_same_distribution_compares_wheel_tags():
    assert same_distribution("SampleProject-4.0.0-py3-none-any.whl", "sampleproject-4.0.0-py3-none-any.whl")
    assert not same_distribution("sampleproject-4.0.0-py2.py3-none-any.whl", "sampleproject-4.0.0-py3-none-any.whl")
    assert not same_distribution("sampleproject-4.0.0-cp312-cp312-manylinux_2_17_x86_64.whl",
                                 "sampleproject-4.0.0-py3-none-any.whl")


# --------------------------------------------------------------------------- lookup gating (offline)
@pytest.mark.parametrize(("switch", "reason"), [
    ("scan_offline", "offline scan"),
    ("intel_offline_setting", "INTEL_OFFLINE=true"),
    ("provenance_disabled_setting", "PROVENANCE_ENABLED=false"),
    ("scan_option", "provenance lookups switched off for this scan"),
])
def test_no_client_and_no_request_when_lookups_are_switched_off(monkeypatch, switch, reason):
    monkeypatch.setattr(settings, "INTEL_OFFLINE", switch == "intel_offline_setting")
    monkeypatch.setattr(settings, "PROVENANCE_ENABLED", switch != "provenance_disabled_setting")
    options = ScanOptions(offline=switch == "scan_offline", provenance=switch != "scan_option")
    md = {"_days_since_previous_release": 800.0, "_age_days": 1.5, "_previous_version": "3.0.0",
          "author": "Jane Doe", "project_urls": {"Source": "https://github.com/someone-else/project"}}
    with respx.mock() as router:
        findings = run(make_ctx(metadata=md, options=options), offline_analyzer())
        assert router.calls.call_count == 0
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED, Code.DORMANT_REVIVAL]  # dormancy works offline
    f = findings[0]
    assert (f.evidence["reason"], f.evidence["lookup"], f.evidence["lookup_disabled_reason"]) == (
        "lookup_disabled", "not_attempted", reason)
    assert f.evidence["checks"] == {"maintainer": "lookup_disabled", "dormancy": "revival"}
    assert f.evidence["provenance_summary"] == {"state": "unknown", "hash_verified": True,
                                                "attestation_present": None, "publisher": None, "checked_at": None}


@respx.mock
@pytest.mark.parametrize(("ctx_kwargs", "reason", "hash_verified"), [
    ({"art": None}, "no_analyzed_artifact", None),
    ({"ecosystem": "npm"}, "unsupported_ecosystem", True),
])
def test_no_lookup_without_an_artifact_or_for_other_ecosystems(online, ctx_kwargs, reason, hash_verified):
    f = only(run(make_ctx(**ctx_kwargs), offline_analyzer()), Code.PROVENANCE_UNVERIFIED)
    assert f.evidence["reason"] == reason and f.evidence["provenance_summary"]["hash_verified"] is hash_verified
    assert respx.calls.call_count == 0


def test_default_suite_environment_is_offline_and_deterministic():
    md = {"_days_since_previous_release": 500.0, "_age_days": 3.0, "_previous_version": "3.0.0"}
    first = [f.to_dict() for f in run(make_ctx(metadata=md), offline_analyzer())]
    second = [f.to_dict() for f in run(make_ctx(metadata=md), offline_analyzer())]
    assert first == second and [f["code"] for f in first] == [Code.PROVENANCE_UNVERIFIED, Code.DORMANT_REVIVAL]


@respx.mock
def test_client_is_constructed_once_even_under_concurrent_scans(online):
    respx.get(PROV_URL).mock(return_value=httpx.Response(404))
    calls: list[int] = []
    lock = threading.Lock()

    def factory() -> PyPIClient:
        with lock:
            calls.append(1)
        time.sleep(0.05)  # widen the race window
        return pypi_client()

    a = ProvenanceAnalyzer(client_factory=factory, clock=lambda: CHECKED)
    assert calls == []
    results: list[list[Finding]] = []
    threads = [threading.Thread(target=lambda: results.append(a.analyze(make_ctx()))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(results) == 4 and len(calls) == 1
    assert all(codes(r) == [Code.PROVENANCE_UNVERIFIED] for r in results)


# --------------------------------------------------------------------------- repository normalisation
REPO_URLS = [
    ("https://github.com/pypa/sampleproject", ("github", "pypa/sampleproject")),
    ("https://github.com/PyPA/SampleProject.git", ("github", "pypa/sampleproject")),
    ("http://www.github.com/pypa/sampleproject/tree/main/src/", ("github", "pypa/sampleproject")),
    ("https://github.com/pypa/sampleproject/issues?q=is%3Aopen#top", ("github", "pypa/sampleproject")),
    ("git+https://github.com/pypa/sampleproject.git@v4.0.0#egg=sampleproject", ("github", "pypa/sampleproject")),
    ("git@github.com:pypa/sampleproject.git", ("github", "pypa/sampleproject")),
    ("ssh://git@github.com/pypa/sampleproject.git", ("github", "pypa/sampleproject")),
    ("github.com/pypa/sampleproject", ("github", "pypa/sampleproject")),
    ("  https://github.com/pypa/sampleproject  ", ("github", "pypa/sampleproject")),
    ("https://gitlab.com/example-group/tools/sampleproject/-/tree/main",
     ("gitlab", "example-group/tools/sampleproject")),
    ("https://gitlab.com/example-group/sampleproject.git", ("gitlab", "example-group/sampleproject")),
    ("git@gitlab.com:example-group/tools/sampleproject.git", ("gitlab", "example-group/tools/sampleproject")),
    # declared URLs that are not source repositories
    ("https://github.com/sponsors/pypa", None),
    ("https://github.com/pypa", None),
    ("https://pypa.github.io/sampleproject", None),
    ("https://raw.githubusercontent.com/pypa/sampleproject/main/README.md", None),
    ("https://gitlab.example.org/group/project", None),
    ("https://gitlab.com/explore/projects", None),
    ("https://packaging.python.org/en/latest/", None),
    # hostile
    ("https://github.com.evil.example/pypa/sampleproject", None),
    ("https://evil.example/github.com/pypa/sampleproject", None),
    ("https://github.com@evil.example/pypa/sampleproject", None),
    ("https://github.com/../../etc/passwd", None),
    ("https://github.com/pypa/sample%2Fproject", None),
    ("https://github.com/pypa/sampleproject‮gnp.exe", None),
    ("javascript:alert(document.domain)//github.com/pypa/x", None),
    ("ftp://github.com/pypa/sampleproject", None),
    ("https://[::1/pypa/sampleproject", None),
    ("https://github.com/" + "a/" * 5000, None),
    ("", None),
    (None, None),
    (42, None),
    (["https://github.com/pypa/sampleproject"], None),
]


@pytest.mark.parametrize(("url", "expected"), REPO_URLS, ids=[str(i) for i in range(len(REPO_URLS))])
def test_normalise_repository_url(url, expected):
    assert normalise_repository_url(url) == expected


@pytest.mark.parametrize(("publisher", "expected"), [
    (PublisherIdentity("GitHub", "pypa/sampleproject"), ("github", "pypa/sampleproject")),
    (PublisherIdentity("GitHub", "PyPA/SampleProject"), ("github", "pypa/sampleproject")),
    (PublisherIdentity("GitHub", "https://github.com/pypa/sampleproject"), ("github", "pypa/sampleproject")),
    (PublisherIdentity("GitHub", "https://gitlab.com/pypa/sampleproject"), None),
    (PublisherIdentity("GitHub", "pypa/sampleproject/extra"), None),
    (PublisherIdentity("GitHub", "pypa"), None),
    (PublisherIdentity("GitHub", "../etc"), None),
    (PublisherIdentity("GitLab", "example-group/tools/sampleproject"), ("gitlab", "example-group/tools/sampleproject")),
    (PublisherIdentity("Google", None), None),
    (PublisherIdentity("ActiveState", "org/project"), None),
])
def test_publisher_repository(publisher, expected):
    assert publisher_repository(publisher) == expected


def test_declared_repositories_are_deduplicated_sorted_and_bounded():
    urls = {f"Link{i}": "https://example.org/" for i in range(500)}
    urls.update({"Source": "https://github.com/pypa/sampleproject", "Tracker": "https://github.com/pypa/sampleproject/issues",
                 "Mirror": "https://gitlab.com/pypa/sampleproject", 7: "https://github.com/x/y", "Bad": ["x"]})
    assert declared_repositories({"home_page": "https://github.com/PyPA/SampleProject", "project_urls": urls}) == [
        DeclaredRepository("github", "pypa/sampleproject", "home_page")]  # entries past the first 64 are ignored
    small = {"Source": "https://github.com/pypa/sampleproject", "Mirror": "https://gitlab.com/pypa/sampleproject"}
    assert [r.to_dict() for r in declared_repositories({"project_urls": small})] == [
        {"forge": "github", "repository": "pypa/sampleproject", "source": "project_urls.Source"},
        {"forge": "gitlab", "repository": "pypa/sampleproject", "source": "project_urls.Mirror"},
    ]


def test_compare_repository_tiers():
    declared = [DeclaredRepository("github", "pypa/sampleproject", "project_urls.Source")]
    assert compare_repository(("github", "pypa/sampleproject"), declared) is None
    assert compare_repository(("github", "pypa/sampleproject"), []) is None
    assert compare_repository(("github", "pypa/other"), declared) == "same_owner"
    assert compare_repository(("gitlab", "pypa/sampleproject"), declared) == "same_path_other_forge"
    assert compare_repository(("github", "attacker/sampleproject"), declared) == "unrelated"
    legacy = [DeclaredRepository("gitlab", "group/project/issues", "project_urls.Issues")]
    assert compare_repository(("gitlab", "group/project"), legacy) is None


# --------------------------------------------------------------------------- REPO_MISMATCH through the analyzer
@respx.mock
@pytest.mark.parametrize(("publisher", "project_urls", "home_page", "expected"), [
    # benign: consistent or nothing comparable declared -> no finding
    (GITHUB_PUBLISHER, {"Source": "https://github.com/pypa/sampleproject"}, None, None),
    (GITHUB_PUBLISHER, {"Source": "git@github.com:PyPA/SampleProject.git"}, None, None),
    (GITHUB_PUBLISHER, {"Changelog": "https://github.com/pypa/sampleproject/blob/main/CHANGELOG.md"}, None, None),
    (GITHUB_PUBLISHER, {}, "https://github.com/pypa/sampleproject", None),
    (GITHUB_PUBLISHER, {"Homepage": "https://packaging.python.org", "Funding": "https://github.com/sponsors/pypa",
                        "Documentation": "https://pypa.github.io/sampleproject"}, None, None),
    (GITHUB_PUBLISHER, {}, None, None),
    (GITHUB_PUBLISHER, {"Source": "https://github.com/pypa/sampleproject",
                        "Upstream fork": "https://github.com/someone/sampleproject"}, None, None),
    ({"kind": "GitLab", "repository": "example-group/tools/sampleproject", "workflow_filepath": ".gitlab-ci.yml"},
     {"Issues": "https://gitlab.com/example-group/tools/sampleproject/issues"}, None, None),
    ({"kind": "Google", "email": "release@sampleproject.iam.gserviceaccount.com"},
     {"Source": "https://github.com/pypa/sampleproject"}, None, None),
    ({"kind": "GitHub", "repository": "../../etc", "workflow": "release.yml"},
     {"Source": "https://github.com/pypa/sampleproject"}, None, None),
    # suspicious
    ({**GITHUB_PUBLISHER, "repository": "attacker-org/sampleproject"},
     {"Source": "https://github.com/pypa/sampleproject"}, None, ("unrelated", Severity.high, 6.0, 0.7)),
    (GITHUB_PUBLISHER, {"Source": "https://github.com/pypa/sampleproject-legacy"}, None,
     ("same_owner", Severity.medium, 3.0, 0.5)),
    (GITHUB_PUBLISHER, {"Source": "https://gitlab.com/pypa/sampleproject"}, None,
     ("same_path_other_forge", Severity.medium, 3.0, 0.5)),
], ids=["same", "scp-case", "blob-link", "home-page", "no-repo-links", "nothing-declared", "fork-also-listed",
        "gitlab-legacy-route", "google-publisher", "invalid-publisher-repo", "unrelated", "same-owner", "other-forge"])
def test_repo_mismatch(online, publisher, project_urls, home_page, expected):
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=with_publisher(**publisher)))
    findings = run(make_ctx(metadata={"project_urls": project_urls, "home_page": home_page}))
    assert only(findings, Code.PROVENANCE_ATTESTED)
    if expected is None:
        assert Code.REPO_MISMATCH not in codes(findings)
        return
    tier, severity, weight, confidence = expected
    f = only(findings, Code.REPO_MISMATCH)
    assert (f.severity, f.weight, f.confidence) == (severity, weight, confidence)
    assert f.evidence["tier"] == tier and f.evidence["attestation_state"] == "partially_verified"
    assert codes(findings) == [Code.PROVENANCE_ATTESTED, Code.REPO_MISMATCH]


@respx.mock
def test_repo_mismatch_evidence_and_it_survives_a_subject_digest_failure(online):
    doc = doc_with(statement(sha=OTHER_SHA), doc=with_publisher(kind="GitHub", repository="attacker-org/sampleproject",
                                                                 workflow="publish.yml"))
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    findings = run(make_ctx(metadata={"project_urls": {"Source": "https://github.com/pypa/sampleproject"}}))
    assert codes(findings) == [Code.PROVENANCE_FAILED, Code.REPO_MISMATCH]
    f = findings[1]
    assert f.evidence["publisher_repository"] == "github:attacker-org/sampleproject"
    assert f.evidence["declared_repositories"] == [
        {"forge": "github", "repository": "pypa/sampleproject", "source": "project_urls.Source"}]
    assert f.evidence["attestation_state"] == "failed"


# --------------------------------------------------------------------------- dormancy
@pytest.mark.parametrize(("gap", "age", "expected"), [
    (365.0, 1.0, "not_dormant"),  # boundary: exactly the threshold is not dormant
    (365.0001, 29.9999, "revival"),
    (400.0, 30.0, "not_recent"),  # boundary: 30 days is no longer recent
    (1200.5, 0.0, "revival"),
    (45.0, 2.0, "not_dormant"),  # regular release cadence
    (200.0, 3.0, "not_dormant"),  # mature library pausing below the threshold
    (None, 1.0, "insufficient_data"),
    (True, 1.0, "insufficient_data"),
    (float("nan"), 1.0, "insufficient_data"),
    (float("inf"), 1.0, "insufficient_data"),
    (-400.0, 1.0, "insufficient_data"),
    ("400", 1.0, "insufficient_data"),
    (400.0, None, "insufficient_data"),
])
def test_dormancy_boundaries(gap, age, expected):
    status, evidence = assess_dormancy({"_days_since_previous_release": gap, "_age_days": age}, 365)
    assert status == expected and (evidence is not None) == (expected == "revival")


@pytest.mark.parametrize("threshold", [0, -1, True, None, "365", float("nan")])
def test_dormancy_disabled_by_non_positive_or_invalid_threshold(threshold):
    assert assess_dormancy({"_days_since_previous_release": 5000.0, "_age_days": 1.0}, threshold) == ("disabled", None)


def test_dormant_revival_finding_offline_and_threshold_from_settings(monkeypatch):
    md = {"_days_since_previous_release": 900.25, "_age_days": 2.5, "_previous_version": "3.0.0"}
    f = only(run(make_ctx(metadata=md), offline_analyzer()), Code.DORMANT_REVIVAL)
    assert (f.severity, f.weight, f.confidence) == (Severity.medium, 4.0, 0.5)
    assert f.evidence["days_since_previous_release"] == 900.25 and f.evidence["age_days"] == 2.5
    assert f.evidence["threshold_days"] == 365 and f.evidence["previous_version"] == "3.0.0"
    assert "900 days" in f.message and "3.0.0" in f.message

    shorter = {"_days_since_previous_release": 120.0, "_age_days": 1.0}
    assert Code.DORMANT_REVIVAL not in codes(run(make_ctx(metadata=shorter), offline_analyzer()))
    monkeypatch.setattr(settings, "DORMANCY_THRESHOLD_DAYS", 90)
    assert only(run(make_ctx(metadata=shorter), offline_analyzer()), Code.DORMANT_REVIVAL).evidence[
        "threshold_days"] == 90
    monkeypatch.setattr(settings, "DORMANCY_THRESHOLD_DAYS", 0)
    findings = run(make_ctx(metadata=shorter), offline_analyzer())
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED]
    assert findings[0].evidence["checks"]["dormancy"] == "disabled"


# --------------------------------------------------------------------------- maintainers
def maintainer_run(previous_info: dict, current_md: dict) -> list[Finding]:
    respx.get(PROV_URL).mock(return_value=httpx.Response(404))
    respx.get(PREV_URL).mock(return_value=httpx.Response(200, json=release_json(**previous_info)))
    return run(make_ctx(metadata={"_previous_version": "3.0.0", **current_md}))


@respx.mock
@pytest.mark.parametrize(("previous", "current", "status"), [
    ({"author": "Jane Doe", "author_email": "jane@example.org"},
     {"author": "Jane Doe, Sam Roe", "author_email": "jane@example.org, sam@example.org"}, "compared"),
    ({"author": "Jane Doe", "author_email": "jane@example.org"},
     {"author": None, "author_email": "Jane Doe <jane@example.org>"}, "compared"),
    ({"author_email": "Jane.Doe@Example.org"}, {"author_email": "jane.doe@example.org"}, "compared"),
    ({"maintainer": "Alice Liddell", "maintainer_email": "team@sampleproject.example"},
     {"maintainer": "Bob Stone", "maintainer_email": "team@sampleproject.example"}, "compared"),
    ({"author": "Python Packaging Authority", "author_email": "pypa-dev@googlegroups.com"},
     {"author": "The Python Packaging Authority", "author_email": "pypa-dev@googlegroups.com"}, "compared"),
    ({"author": "Python Packaging Authority"}, {"author": "The Python Packaging Authority"}, "compared"),
    ({"author": "Jane Doe"}, {"author": "J. Doe"}, "compared"),
    ({"author": "Django Software Foundation", "author_email": "foundation@djangoproject.com"},
     {"author": "Django Software Foundation", "author_email": "security@djangoproject.com"}, "compared"),
    ({"author": "Jane Doe", "author_email": "jane@example.org"},
     {"maintainer": "Jane Doe", "maintainer_email": "jdoe@example.org"}, "compared"),
    ({"author": "UNKNOWN", "author_email": "UNKNOWN"}, {"author": "Jane Doe", "author_email": "jane@example.org"},
     "insufficient_identity"),
    ({"author": "Jane Doe"}, {"author_email": "jane@example.org"}, "insufficient_identity"),
], ids=["co-maintainer-added", "pep621-migration", "email-case", "rotation-shared-team-address", "name-reworded",
        "name-reworded-no-email", "initial-abbreviated", "same-name-same-org-domain",
        "author-to-maintainer-same-domain", "placeholder-previous", "not-comparable"])
def test_benign_maintainer_metadata_changes_are_not_flagged(online, previous, current, status):
    findings = maintainer_run(previous, current)
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED]
    assert findings[0].evidence["checks"]["maintainer"] == status


@respx.mock
@pytest.mark.parametrize(("previous", "current", "tier", "grade", "removed", "added"), [
    ({"author": "Jane Doe", "author_email": "jane@example.org"},
     {"author": "Release Bot", "author_email": "releases@mail.example.net"},
     "identity_replaced", (Severity.high, 5.0, 0.6), ["j***@example.org"], ["r***@mail.example.net"]),
    ({"author": "Jane Doe", "author_email": "jane@example.org"},
     {"author": "Jane Doe", "author_email": "jane.doe@mail.example.net"},
     "email_replaced", (Severity.medium, 2.0, 0.4), ["j***@example.org"], ["j***@mail.example.net"]),
    ({"author": "Jane Doe", "author_email": "jane@example.org",
      "ownership": {"roles": [{"role": "Owner", "user": "janedoe"}], "organization": None}},
     {"author": "Jane Doe", "author_email": "jane@example.org",
      "ownership": {"roles": [{"role": "Owner", "user": "mallory"}], "organization": None}},
     "ownership_replaced", (Severity.high, 5.0, 0.6), [], []),
    ({"author": "Jane Doe", "author_email": "jane.doe@gmail.com"},
     {"author": "Mallory Moe", "author_email": "mallory.moe@gmail.com"},
     "identity_replaced", (Severity.high, 5.0, 0.6), ["j***@gmail.com"], ["m***@gmail.com"]),  # freemail: no org
    ({"author": "Jane Doe"}, {"author": "Release Bot"}, "names_replaced", (Severity.medium, 2.0, 0.4), [], []),
    ({"author": "Alice Liddell", "author_email": "alice@sampleproject.example"},
     {"author": "Bob Stone", "author_email": "bob@sampleproject.example"},
     "same_domain_replaced", (Severity.medium, 2.0, 0.4), ["a***@sampleproject.example"],
     ["b***@sampleproject.example"]),
], ids=["identity-replaced", "email-replaced", "ownership-replaced", "freemail-identity-replaced", "names-replaced",
        "same-domain-replaced"])
def test_maintainer_transitions_are_flagged_with_masked_evidence(online, previous, current, tier, grade, removed,
                                                                  added):
    findings = maintainer_run(previous, current)
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED, Code.MAINTAINER_CHANGED]
    f = findings[1]
    assert (f.severity, f.weight, f.confidence) == grade
    assert (f.evidence["tier"], f.evidence["previous_version"]) == (tier, "3.0.0")
    assert (f.evidence["removed_emails"], f.evidence["added_emails"]) == (removed, added)
    assert findings[0].evidence["checks"]["maintainer"] == "changed"
    rendered = json.dumps(f.to_dict())
    for value in (*previous.values(), *current.values()):
        if isinstance(value, str) and "@" in value:
            assert value not in rendered  # raw addresses never leave the analyzer
    if tier == "ownership_replaced":
        assert (f.evidence["removed_owners"], f.evidence["added_owners"]) == (["janedoe"], ["mallory"])
    if tier == "same_domain_replaced":
        assert f.evidence["shared_domains"] == ["sampleproject.example"]
    else:
        assert "shared_domains" not in f.evidence


def test_no_previous_release_request_when_the_analysed_release_has_no_identity_data(online):
    with respx.mock() as router:
        router.get(PROV_URL).mock(return_value=httpx.Response(404))
        findings = run(make_ctx(metadata={"_previous_version": "3.0.0", "author": "UNKNOWN"}))
        assert [str(c.request.url) for c in router.calls] == [PROV_URL]
    assert findings[0].evidence["checks"]["maintainer"] == "insufficient_identity"


@pytest.mark.parametrize(("previous", "current", "expected"), [
    ({"python packaging authority"}, {"the python packaging authority"}, True),
    ({"jane doe"}, {"j. doe"}, True),
    ({"jane doe"}, {"doe"}, True),
    ({"jane doe"}, {"jane smith"}, False),  # a shared first name is not the same person
    ({"python software foundation"}, {"django software foundation"}, False),  # generic words do not count
    ({"the team"}, {"team"}, False),  # nothing distinctive
    ({"al li"}, {"al bo"}, False),  # shared words must be at least 3 characters
    ({"jane doe", "sam roe"}, {"release bot", "sam roe"}, True),
    (set(), {"jane doe"}, False),
])
def test_names_overlap(previous, current, expected):
    assert names_overlap(frozenset(previous), frozenset(current)) is expected


def test_shared_organisation_domains_ignore_shared_mailbox_providers():
    assert shared_organisation_domains(frozenset({"a@gmail.com", "a@corp.example"}),
                                       frozenset({"b@gmail.com", "b@corp.example"})) == ["corp.example"]
    assert shared_organisation_domains(frozenset({"1+jane@users.noreply.github.com"}),
                                       frozenset({"2+bob@users.noreply.github.com"})) == []


@respx.mock
@pytest.mark.parametrize(("mock", "status"), [
    ({"return_value": httpx.Response(404)}, "previous_release_not_found"),
    ({"return_value": httpx.Response(503)}, "error:registry_unavailable"),
    ({"side_effect": httpx.ConnectError("down")}, "error:registry_unavailable"),
    ({"return_value": httpx.Response(200, content=b"{not json")}, "error:registry_malformed"),
    ({"return_value": httpx.Response(200, json={"urls": []})}, "error:registry_malformed"),
])
def test_previous_release_lookup_failures_are_recorded_not_flagged(online, mock, status):
    respx.get(PROV_URL).mock(return_value=httpx.Response(404))
    respx.get(PREV_URL).mock(**mock)
    findings = run(make_ctx(metadata={"_previous_version": "3.0.0", "author": "Jane Doe"}))
    assert codes(findings) == [Code.PROVENANCE_UNVERIFIED]
    assert findings[0].evidence["checks"]["maintainer"] == status


def test_invalid_previous_version_is_rejected_before_any_request(online):
    with respx.mock() as router:
        router.get(PROV_URL).mock(return_value=httpx.Response(404))
        findings = run(make_ctx(metadata={"_previous_version": "3.0/../../admin", "author": "Jane Doe"}))
        assert [str(c.request.url) for c in router.calls] == [PROV_URL]
    assert findings[0].evidence["checks"]["maintainer"] == "error:invalid_version"


def test_extract_identities_parses_display_names_and_ignores_placeholders():
    ids = extract_identities({
        "author": "Jane Doe, Sam Roe and Kim Lee",
        "author_email": '"A. Random Developer" <author@example.com>, Jane@Example.org',
        "maintainer": "UNKNOWN",
        "maintainer_email": None,
        "ownership": {"roles": [{"role": "Owner", "user": "JaneDoe"}, {"role": "Maintainer", "user": " pypa-bot "},
                                "junk", {"role": "Owner", "user": 5}]},
    })
    assert ids.names == {"jane doe", "sam roe", "kim lee", "a. random developer"}
    assert ids.emails == {"author@example.com", "jane@example.org"}
    assert ids.owners == {"janedoe", "pypa-bot"}
    assert extract_identities({"author": 123, "author_email": ["x@y.z"], "ownership": "x"}).empty


def test_identity_parsing_is_bounded_against_hostile_metadata():
    hostile = {
        "author": ("x" * 63 + "@" + "a." * 40) * 5000,
        "author_email": "," * 100_000 + "a@b.co",
        "maintainer": " and ".join(["n"] * 50_000),
        "maintainer_email": "<" * 100_000,
        "ownership": {"roles": [{"role": "Owner", "user": "u" * 10_000}] * 10_000},
    }
    started = time.monotonic()
    ids = extract_identities(hostile)
    change = diff_maintainers(hostile, {"author": "Jane Doe", "author_email": "jane@example.org"})
    assert time.monotonic() - started < 2.0
    assert len(ids.names) <= prov.MAX_IDENTITIES and len(ids.emails) <= prov.MAX_IDENTITIES
    assert len(ids.owners) <= prov.MAX_OWNERSHIP_ROLES and all(len(n) <= 200 for n in ids.names)
    assert all(len(o) <= 100 for o in ids.owners)
    assert change is not None and change.tier == "identity_replaced"


def test_mask_email():
    assert mask_email("jane@example.org") == "j***@example.org"
    assert mask_email("x@y.co") == "x***@y.co"


# --------------------------------------------------------------------------- PyPIClient extensions
@respx.mock
@pytest.mark.parametrize(("mock", "status", "kind", "http_status"), [
    ({"return_value": httpx.Response(200, json={"version": 1, "attestation_bundles": []})}, LOOKUP_FOUND, None, 200),
    ({"return_value": httpx.Response(404)}, LOOKUP_NOT_FOUND, None, 404),
    ({"return_value": httpx.Response(500)}, LOOKUP_ERROR, "status", 500),
    ({"return_value": httpx.Response(406)}, LOOKUP_ERROR, "status", 406),
    ({"return_value": httpx.Response(200, content=b"nope")}, LOOKUP_MALFORMED, "invalid_json", 200),
    ({"return_value": httpx.Response(200, json=[1, 2])}, LOOKUP_MALFORMED, "not_an_object", 200),
    ({"side_effect": httpx.ConnectError("down")}, LOOKUP_ERROR, "network", None),
])
def test_pypi_provenance_lookup_statuses(mock, status, kind, http_status):
    route = respx.get(PROV_URL).mock(**mock)
    lookup = pypi_client().provenance_lookup("sampleproject", "4.0.0", FILENAME)
    assert (lookup.status, lookup.error_kind, lookup.http_status) == (status, kind, http_status)
    assert (lookup.document is not None) == (status == LOOKUP_FOUND)
    assert route.calls.last.request.headers["accept"] == INTEGRITY_ACCEPT


def test_pypi_provenance_lookup_invalid_input_makes_no_request():
    with respx.mock() as router:
        assert pypi_client().provenance_lookup("../x", "4.0.0", FILENAME).status == LOOKUP_INVALID_INPUT
        bad_file = pypi_client().provenance_lookup("sampleproject", "4.0.0", "../../x/provenance")
        assert (bad_file.status, bad_file.error_kind) == (LOOKUP_INVALID_INPUT, "invalid_filename")
        assert router.calls.call_count == 0


@respx.mock
def test_previous_release_metadata_is_bounded_and_reports_absence():
    info = {"author": "A" * 5000, "author_email": 123, "maintainer": "Sam Roe", "maintainer_email": "sam@example.org",
            "project_urls": {"Source": "https://github.com/pypa/sampleproject", "bad": 1},
            "ownership": {"roles": [{"role": "Owner", "user": "janedoe"}] * 300, "organization": "pypa"}}
    respx.get(PREV_URL).mock(return_value=httpx.Response(200, json=release_json(**info)))
    md = pypi_client().previous_release_metadata("sampleproject", "3.0.0")
    assert len(md["author"]) == 2000 and md["author_email"] is None and md["maintainer_email"] == "sam@example.org"
    assert md["project_urls"] == {"Source": "https://github.com/pypa/sampleproject"} and md["version"] == "3.0.0"
    assert len(md["ownership"]["roles"]) == 200 and md["_maintainer_count"] == 2

    respx.get(PREV_URL).mock(return_value=httpx.Response(404))
    assert pypi_client().previous_release_metadata("sampleproject", "3.0.0") is None
    respx.get(PREV_URL).mock(return_value=httpx.Response(503))
    with pytest.raises(AnalysisError) as info_exc:
        pypi_client().previous_release_metadata("sampleproject", "3.0.0")
    assert info_exc.value.code == "registry_unavailable"


# --------------------------------------------------------------------------- pipeline compatibility
@respx.mock
def test_every_finding_carries_the_same_summary_in_a_full_online_scan(online):
    doc = with_publisher(**{**GITHUB_PUBLISHER, "repository": "attacker-org/sampleproject"})
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    respx.get(PREV_URL).mock(return_value=httpx.Response(200, json=release_json(
        author="Jane Doe", author_email="jane@example.org")))
    md = {"project_urls": {"Source": "https://github.com/pypa/sampleproject"}, "_previous_version": "3.0.0",
          "_days_since_previous_release": 1100.0, "_age_days": 0.5, "author": "Release Bot",
          "author_email": "releases@mail.example.net"}
    findings = run(make_ctx(metadata=md))
    assert codes(findings) == [Code.PROVENANCE_ATTESTED, Code.REPO_MISMATCH, Code.MAINTAINER_CHANGED,
                               Code.DORMANT_REVIVAL]
    summary = findings[0].evidence["provenance_summary"]
    assert summary["publisher"]["repository"] == "attacker-org/sampleproject" and summary["checked_at"] == CHECKED_ISO
    again = [f.to_dict() for f in analyzer().analyze(make_ctx(metadata=md))]
    assert again == [f.to_dict() for f in findings]  # deterministic for identical inputs


@respx.mock
def test_orchestrator_exposes_provenance_and_scores_the_provenance_dimension(online, monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _NoModel())
    doc = with_publisher(**{**GITHUB_PUBLISHER, "repository": "attacker-org/sampleproject"})
    respx.get(PROV_URL).mock(return_value=httpx.Response(200, json=doc))
    ctx = make_ctx(metadata={"project_urls": {"Source": "https://github.com/pypa/sampleproject"}})

    class Fetcher:
        def build_context(self, name, version, options=None):
            return ctx

    result = orch.Orchestrator(Fetcher(), analyzers=[analyzer()], cache_backend=_NullCache()).analyze(
        "pypi", "sampleproject", "4.0.0", ScanOptions())
    assert result.provenance["status"] == "attested" and result.provenance["repo_mismatch"] is True
    assert result.provenance["hash_verified"] is True
    assert result.provenance["evidence"]["provenance_summary"]["state"] == "partially_verified"
    dimension = result.risk["dimensions"]["provenance"]
    assert dimension["score"] > 0 and len(dimension["contributors"]) == 2
    assert [r["status"] for r in result.analyzer_runs if r["name"] == "provenance"] == ["ok"]
    assert {s["analyzer"] for s in result.signals} == {"provenance"}
