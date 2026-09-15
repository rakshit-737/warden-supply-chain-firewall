"""PyPIClient tests. All HTTP is mocked with respx; registry JSON below is a hand-written FIXTURE."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import httpx
import pytest
import respx

from app.analysis.acquisition.pypi import PyPIClient, validate_name
from app.analysis.analyzers.base import ArtifactInfo
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import OutboundHTTPError, SafeHttpClient

JSON = "https://pypi.org/pypi"
FILES = "https://files.pythonhosted.org/packages"
NOW = datetime(2024, 3, 1, tzinfo=timezone.utc)
SDIST = b"fixture sdist bytes"
SDIST_SHA = hashlib.sha256(SDIST).hexdigest()


def _file(filename: str, uploaded: str | None, **extra) -> dict:
    entry = {
        "filename": filename,
        "url": f"{FILES}/ab/cd/{filename}",
        "packagetype": "sdist" if filename.endswith(".tar.gz") else "bdist_wheel",
        "size": 100,
        "digests": {"sha256": SDIST_SHA, "md5": "0" * 32},
        "upload_time_iso_8601": uploaded,
        "yanked": False,
        "yanked_reason": None,
        "requires_python": ">=3.8",
    }
    entry.update(extra)
    return entry


def _project(**info_overrides) -> dict:
    """FIXTURE: shape of https://pypi.org/pypi/<name>/json, trimmed to the keys Warden reads."""
    info = {
        "name": "demo", "version": "1.1", "summary": "Demo package", "home_page": "",
        "project_urls": {"Source": "https://github.com/example/demo"},
        "author": "Alice, Bob", "author_email": "a@example.com", "maintainer": None, "maintainer_email": None,
        "license": "MIT", "license_expression": None, "requires_python": ">=3.8",
        "requires_dist": ["requests>=2"], "classifiers": ["Programming Language :: Python :: 3"],
        "keywords": "demo", "yanked": False, "yanked_reason": None,
    }
    info.update(info_overrides)
    return {
        "info": info,
        "releases": {
            "0.9": [_file("demo-0.9.tar.gz", "2023-01-01T00:00:00Z")],
            "1.0": [_file("demo-1.0.tar.gz", "2024-01-01T00:00:00.000Z")],
            "1.1": [_file("demo-1.1.tar.gz", "2024-02-27T00:00:00Z"),
                    _file("demo-1.1-py3-none-any.whl", "2024-02-28T00:00:00Z")],
            "0.1": [],
        },
        "urls": [
            _file("demo-1.1.tar.gz", "2024-02-27T00:00:00Z"),
            _file("demo-1.1-py3-none-any.whl", "2024-02-28T00:00:00Z"),
        ],
    }


def _client(**kwargs) -> PyPIClient:
    registry = SafeHttpClient(name="t-registry", allowed_hosts=["pypi.org"], retries=0, sleep=lambda s: None)
    artifacts = SafeHttpClient(name="t-artifacts", allowed_hosts=["files.pythonhosted.org"], retries=0,
                               sleep=lambda s: None)
    return PyPIClient(registry_http=registry, artifact_http=artifacts, clock=lambda: NOW, **kwargs)


# --------------------------------------------------------------------------- validation / URLs
@pytest.mark.parametrize("name", ["../evil", "a/b", "demo?x=1", "", " ", "-demo", "demo-", "a" * 215, "dé mo",
                                  "demo#frag", "%2e%2e"])
def test_invalid_names_rejected_before_any_request(name):
    with respx.mock() as router:
        with pytest.raises(AnalysisError) as info:
            _client().project(name)
        assert router.calls.call_count == 0
    assert info.value.code == "invalid_package_name" and info.value.status_code == 400


def test_valid_pep508_names_accepted():
    for name in ("a", "A1", "zope.interface", "typing_extensions", "python-dateutil"):
        assert validate_name(name) == name


def test_version_path_segment_is_quoted():
    with respx.mock() as router:
        route = router.get(url__regex=r"https://pypi\.org/pypi/demo/.+/json").mock(return_value=httpx.Response(404))
        assert _client().release("demo", "1.0+local.1") is None
    assert route.calls.last.request.url.raw_path == b"/pypi/demo/1.0%2Blocal.1/json"


def test_invalid_version_rejected():
    with respx.mock() as router, pytest.raises(AnalysisError) as info:
        _client().release("demo", "1.0/../../admin")
    assert info.value.code == "invalid_version" and router.calls.call_count == 0


# --------------------------------------------------------------------------- registry errors
@respx.mock
def test_project_not_found():
    respx.get(f"{JSON}/nope/json").mock(return_value=httpx.Response(404))
    with pytest.raises(AnalysisError) as info:
        _client().project("nope")
    assert info.value.code == "package_not_found" and info.value.status_code == 404


@respx.mock
def test_registry_server_error_and_network_error():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(503))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert info.value.code == "registry_unavailable"
    respx.get(f"{JSON}/demo/json").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert info.value.code == "registry_unavailable"


@respx.mock
def test_malformed_registry_json():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, content=b"<html>"))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert info.value.code == "registry_malformed"
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=["not", "a", "project"]))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert info.value.code == "registry_malformed"


@respx.mock
def test_redirect_to_internal_host_is_refused():
    respx.get(f"{JSON}/demo/json").mock(
        return_value=httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/meta-data"}))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert info.value.code == "registry_unavailable"


@respx.mock
def test_oversized_registry_response_refused(monkeypatch):
    monkeypatch.setattr(settings, "MAX_METADATA_BYTES", 1024)
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, content=b"{" + b" " * 5000 + b"}"))
    with pytest.raises(AnalysisError) as info:
        _client().project("demo")
    assert "too_large" in info.value.message


# --------------------------------------------------------------------------- resolution + metadata
@respx.mock
def test_resolve_latest_and_derived_metadata():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=_project()))
    client = _client()
    release = client.resolve("demo", None)
    assert release.version == "1.1" and release.version_found
    md = client.build_metadata(release)
    assert md["name"] == "demo" and md["version"] == "1.1" and md["requires_dist"] == ["requests>=2"]
    assert md["_maintainer_count"] == 2 and md["_version_found"] is True
    assert md["_release_count"] == 4
    assert md["_first_release_at"] == "2023-01-01T00:00:00+00:00"
    assert md["_previous_version"] == "1.0"
    assert md["_previous_release_at"] == "2024-01-01T00:00:00+00:00"
    assert md["_days_since_previous_release"] == 57.0
    assert md["_age_days"] == 3.0  # earliest upload of 1.1 is 2024-02-27
    assert md["_releases_last_7d"] == 1
    assert {a.filename for a in client.artifacts(release.files)} == {"demo-1.1.tar.gz", "demo-1.1-py3-none-any.whl"}


@respx.mock
def test_resolve_older_version_uses_version_specific_json():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=_project()))
    old = {"info": dict(_project()["info"], version="0.9", summary="old summary", requires_dist=None),
           "urls": [_file("demo-0.9.tar.gz", "2023-01-01T00:00:00Z")]}
    version_route = respx.get(f"{JSON}/demo/0.9/json").mock(return_value=httpx.Response(200, json=old))
    client = _client()
    release = client.resolve("demo", "0.9")
    md = client.build_metadata(release)
    assert version_route.called and release.version_found
    assert md["summary"] == "old summary" and md["requires_dist"] is None
    assert md["_previous_version"] is None and md["_first_release_at"] == "2023-01-01T00:00:00+00:00"
    assert [a.filename for a in client.artifacts(release.files)] == ["demo-0.9.tar.gz"]


@respx.mock
def test_resolve_matches_canonically_equal_version():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=_project()))
    respx.get(f"{JSON}/demo/1.0/json").mock(return_value=httpx.Response(200, json={
        "info": dict(_project()["info"], version="1.0"), "urls": [_file("demo-1.0.tar.gz", "2024-01-01T00:00:00Z")]}))
    release = _client().resolve("demo", "1.0.0")
    assert release.version == "1.0" and release.version_found


@respx.mock
def test_resolve_missing_version_is_reported_not_silently_replaced():
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=_project()))
    respx.get(f"{JSON}/demo/9.9/json").mock(return_value=httpx.Response(404))
    release = _client().resolve("demo", "9.9")
    assert release.version_found is False and release.requested_version == "9.9" and release.version == "1.1"


@respx.mock
def test_resolve_version_absent_from_project_releases_map_falls_back_to_version_json():
    project = _project()
    del project["releases"]
    respx.get(f"{JSON}/demo/json").mock(return_value=httpx.Response(200, json=project))
    respx.get(f"{JSON}/demo/0.5/json").mock(return_value=httpx.Response(200, json={
        "info": dict(project["info"], version="0.5"), "urls": [_file("demo-0.5.tar.gz", "2022-01-01T00:00:00Z")]}))
    release = _client().resolve("demo", "0.5")
    assert release.version_found and release.version == "0.5" and release.releases == []


def test_metadata_is_bounded_against_hostile_registry_values():
    info = dict(
        _project()["info"],
        summary="S" * 10_000,
        requires_dist=[f"dep{i}" for i in range(500)] + [123],
        classifiers=[f"C{i}" for i in range(80)],
        project_urls={"Home": "https://x", "Evil": {"nested": 1}, 5: "https://y"},
        author=12345,
        keywords=["k"] * 300,
        ownership={"roles": [{"role": "Owner", "user": "u" * 5000}] * 300, "deep": {"a": {"b": {"c": {"d": 1}}}}},
    )
    from app.analysis.acquisition.pypi import ResolvedRelease

    md = _client().build_metadata(ResolvedRelease("demo", None, "1.1", True, info, [], [], info))
    assert len(md["summary"]) == 2000
    assert len(md["requires_dist"]) == 200 and all(isinstance(d, str) for d in md["requires_dist"])
    assert len(md["classifiers"]) == 50
    assert md["project_urls"] == {"Home": "https://x"}
    assert md["author"] is None and md["_maintainer_count"] == 0
    assert len(md["keywords"]) == 200
    assert len(md["ownership"]["roles"]) == 200 and len(md["ownership"]["roles"][0]["user"]) == 2000
    assert md["ownership"]["deep"]["a"]["b"]["c"] is None  # nesting bounded


def test_releases_sorted_by_upload_time_untimed_last_and_yanked():
    project = {"info": {}, "releases": {
        "2.0": [_file("d-2.0.tar.gz", "2024-01-01T00:00:00Z")],
        "1.5": [_file("d-1.5.tar.gz", "2024-02-01T00:00:00Z", yanked=True)],  # backport published later
        "1.0": [_file("d-1.0.tar.gz", "2023-01-01T00:00:00"), _file("d-1.0.zip", "2022-12-31T00:00:00")],
        "0.0.1": [],
        "../bad": [_file("x.tar.gz", "2020-01-01T00:00:00Z")],
    }}
    releases = _client().releases(project)
    assert [r.version for r in releases] == ["1.0", "2.0", "1.5", "0.0.1"]
    assert releases[0].upload_time == "2022-12-31T00:00:00+00:00" and releases[0].file_count == 2
    assert releases[2].yanked and not releases[1].yanked and releases[3].upload_time is None


def test_artifacts_parsing_drops_malformed_entries():
    files = [
        _file("demo-1.0.tar.gz", "2024-01-01T00:00:00Z", digests={"sha256": SDIST_SHA.upper(), "md5": "zz"}),
        _file("../../demo.tar.gz", "2024-01-01T00:00:00Z"),
        dict(_file("demo-1.0-py3-none-any.whl", None), url=None),
        _file("demo-1.0-py2-none-any.whl", None, size=True, digests={"sha256": "abc123"}, yanked="yes"),
        "not a dict",
    ]
    artifacts = _client().artifacts(files)
    assert [a.filename for a in artifacts] == ["demo-1.0.tar.gz", "demo-1.0-py2-none-any.whl"]
    assert artifacts[0].digests == {"sha256": SDIST_SHA} and artifacts[0].upload_time == "2024-01-01T00:00:00+00:00"
    assert artifacts[1].size is None and artifacts[1].digests == {} and artifacts[1].yanked is False


# --------------------------------------------------------------------------- download
def _artifact(url=f"{FILES}/ab/cd/demo-1.0.tar.gz", sha=SDIST_SHA, size=len(SDIST)) -> ArtifactInfo:
    return ArtifactInfo(filename="demo-1.0.tar.gz", url=url, packagetype="sdist", size=size,
                        digests={"sha256": sha} if sha else {})


@respx.mock
def test_download_verifies_hash():
    respx.get(f"{FILES}/ab/cd/demo-1.0.tar.gz").mock(return_value=httpx.Response(200, content=SDIST))
    ok = _artifact()
    assert _client().download(ok) == SDIST and ok.hash_verified is True and ok.downloaded_sha256 == SDIST_SHA
    tampered = _artifact(sha="0" * 64)
    _client().download(tampered)
    assert tampered.hash_verified is False and tampered.downloaded_sha256 == SDIST_SHA
    unknown = _artifact(sha=None)
    _client().download(unknown)
    assert unknown.hash_verified is None


def test_download_refuses_non_allowlisted_artifact_host():
    with respx.mock() as router, pytest.raises(OutboundHTTPError) as info:
        _client().download(_artifact(url="https://evil.example/demo-1.0.tar.gz"))
    assert info.value.kind == "host_not_allowed" and router.calls.call_count == 0


def test_download_refuses_declared_oversize_without_request(monkeypatch):
    monkeypatch.setattr(settings, "MAX_DOWNLOAD_BYTES", 10)
    with respx.mock() as router, pytest.raises(OutboundHTTPError) as info:
        _client().download(_artifact(size=11))
    assert info.value.kind == "too_large" and router.calls.call_count == 0


@respx.mock
def test_download_enforces_streaming_cap_when_size_lies(monkeypatch):
    monkeypatch.setattr(settings, "MAX_DOWNLOAD_BYTES", 1024)
    respx.get(f"{FILES}/ab/cd/demo-1.0.tar.gz").mock(return_value=httpx.Response(200, content=b"A" * 4096))
    with pytest.raises(OutboundHTTPError) as info:
        _client().download(_artifact(size=10))
    assert info.value.kind == "too_large"


# --------------------------------------------------------------------------- provenance
PROV_URL = "https://pypi.org/integrity/demo/1.0/demo-1.0.tar.gz/provenance"


@respx.mock
def test_provenance_found_uses_integrity_accept_header():
    route = respx.get(PROV_URL).mock(return_value=httpx.Response(200, json={"version": 1, "attestation_bundles": []}))
    assert _client().provenance("demo", "1.0", "demo-1.0.tar.gz") == {"version": 1, "attestation_bundles": []}
    assert route.calls.last.request.headers["accept"] == "application/vnd.pypi.integrity.v1+json"


@respx.mock
@pytest.mark.parametrize("response", [httpx.Response(404), httpx.Response(500), httpx.Response(200, content=b"nope"),
                                      httpx.Response(200, json=[1, 2])])
def test_provenance_absent_or_failed_returns_none(response):
    respx.get(PROV_URL).mock(return_value=response)
    assert _client().provenance("demo", "1.0", "demo-1.0.tar.gz") is None


@respx.mock
def test_provenance_network_error_returns_none():
    respx.get(PROV_URL).mock(side_effect=httpx.ReadTimeout("slow"))
    assert _client().provenance("demo", "1.0", "demo-1.0.tar.gz") is None


def test_provenance_invalid_filename_makes_no_request():
    with respx.mock() as router:
        assert _client().provenance("demo", "1.0", "../../x/provenance") is None
        assert _client().provenance("../x", "1.0", "demo-1.0.tar.gz") is None
        assert router.calls.call_count == 0
