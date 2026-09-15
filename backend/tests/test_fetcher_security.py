"""Security tests for the archive-extraction guards (Zip-Slip, bombs, symlinks)."""

import hashlib
import io
import tarfile
import zipfile

import httpx
import pytest
import respx

from app.analysis.acquisition.pypi import PyPIClient
from app.analysis.analyzers.base import ArtifactInfo, ScanOptions
from app.analysis.fetcher import RegistryFetcher, _is_unsafe_path, choose_artifact, choose_wheel
from app.analysis.signals import Code
from app.core.config import settings
from app.core.errors import AnalysisError
from app.core.http import SafeHttpClient


def _tar_with(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_path_traversal_helper():
    assert _is_unsafe_path("../../etc/passwd")
    assert _is_unsafe_path("/abs/path")
    assert not _is_unsafe_path("pkg-1.0/mod.py")


def test_tar_path_traversal_rejected():
    fetcher = RegistryFetcher()
    archive = _tar_with([("pkg/../../evil.py", b"import os\n")])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_tar_file_count_bomb_rejected(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_EXTRACTED_FILES", 5)
    fetcher = RegistryFetcher()
    archive = _tar_with([(f"pkg/f{i}.py", b"x=1\n") for i in range(20)])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_tar_size_bomb_rejected(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "MAX_EXTRACTED_BYTES", 100)
    fetcher = RegistryFetcher()
    archive = _tar_with([("pkg/big.py", b"A" * 5000)])
    with pytest.raises(AnalysisError):
        fetcher._extract_tar(archive)


def test_only_interesting_files_kept():
    fetcher = RegistryFetcher()
    archive = _tar_with([
        ("pkg/mod.py", b"x=1\n"),
        ("pkg/data.bin", b"\x00\x01\x02"),
        ("pkg/README.md", b"# hi"),
    ])
    files = fetcher._extract_tar(archive)
    names = {f.relpath for f in files}
    assert "mod.py" in names
    assert "data.bin" not in names  # binary ignored


def test_zip_extraction_and_traversal():
    fetcher = RegistryFetcher()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("pkg/../evil.py", "import os")
    with pytest.raises(AnalysisError):
        fetcher._extract_zip(buf.getvalue())


def test_unsafe_path_helper_covers_windows_forms():
    assert _is_unsafe_path("C:\\Windows\\x.dll")
    assert _is_unsafe_path("\\\\srv\\share\\x.py")
    assert _is_unsafe_path("pkg\\..\\..\\x.py")
    assert _is_unsafe_path("~/.bashrc")
    assert not _is_unsafe_path("pkg-1.0/..data/x.py")


def test_zip_declared_size_bomb_via_compat_shim(monkeypatch):
    monkeypatch.setattr(settings, "MAX_DECLARED_ARCHIVE_BYTES", 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/zeros.bin", b"\x00" * 100_000)
    with pytest.raises(AnalysisError) as info:
        RegistryFetcher()._extract_zip(buf.getvalue())
    assert info.value.code == "extraction_aborted"


# --------------------------------------------------------------------------- build_context
# All HTTP is mocked with respx; the registry JSON below is a hand-written FIXTURE.
JSON_BASE = "https://pypi.org/pypi"
FILES_BASE = "https://files.pythonhosted.org/packages/aa/bb"
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 64


def _tgz(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _whl(members: list[tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


SDIST_BYTES = _tgz([
    ("demo-1.0/setup.py", b"from setuptools import setup\nsetup(name='demo')\n"),
    ("demo-1.0/demo/__init__.py", b"VERSION = '1.0'\n"),
    ("demo-1.0/demo/_speedups.so", ELF),
])
WHEEL_BYTES = _whl([
    ("demo/__init__.py", "VERSION = '1.0'\n"),
    ("demo_hook.pth", "import os\n"),
    ("demo-1.0.dist-info/METADATA", "Name: demo\n"),
])


def _file_entry(filename: str, data: bytes, packagetype: str, *, sha: str | None = None,
                size: int | None = None) -> dict:
    return {
        "filename": filename, "url": f"{FILES_BASE}/{filename}", "packagetype": packagetype,
        "size": len(data) if size is None else size,
        "digests": {"sha256": sha or hashlib.sha256(data).hexdigest()},
        "upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": False, "yanked_reason": None,
    }


def _project_fixture(files: list[dict]) -> dict:
    """FIXTURE: trimmed PyPI project JSON for a single-release package."""
    info = {"name": "demo", "version": "1.0", "summary": "demo", "author": "Alice",
            "project_urls": {"Source": "https://github.com/example/demo"}, "requires_dist": None,
            "classifiers": [], "yanked": False}
    return {"info": info, "releases": {"1.0": files}, "urls": files}


DEFAULT_FILES = [
    _file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist"),
    _file_entry("demo-1.0-py3-none-any.whl", WHEEL_BYTES, "bdist_wheel"),
]


def _fetcher() -> RegistryFetcher:
    registry = SafeHttpClient(name="t-registry", allowed_hosts=["pypi.org"], retries=0, sleep=lambda s: None)
    artifacts = SafeHttpClient(name="t-artifacts", allowed_hosts=["files.pythonhosted.org"], retries=0,
                               sleep=lambda s: None)
    return RegistryFetcher(pypi=PyPIClient(registry_http=registry, artifact_http=artifacts))


def _mock_registry(files: list[dict], sdist: bytes = SDIST_BYTES, wheel: bytes = WHEEL_BYTES):
    respx.get(f"{JSON_BASE}/demo/json").mock(return_value=httpx.Response(200, json=_project_fixture(files)))
    respx.get(f"{FILES_BASE}/demo-1.0.tar.gz").mock(return_value=httpx.Response(200, content=sdist))
    return respx.get(f"{FILES_BASE}/demo-1.0-py3-none-any.whl").mock(return_value=httpx.Response(200, content=wheel))


@respx.mock
def test_build_context_populates_context_from_sdist_and_wheel():
    _mock_registry(DEFAULT_FILES)
    options = ScanOptions(offline=True)
    ctx = _fetcher().build_context("demo", "1.0", options)
    assert ctx.version == "1.0" and ctx.options is options and ctx.context_signals == []
    assert ctx.metadata["_version_found"] is True and ctx.metadata["name"] == "demo"
    assert [r.version for r in ctx.releases] == ["1.0"]
    assert {a.filename for a in ctx.artifacts} == {"demo-1.0.tar.gz", "demo-1.0-py3-none-any.whl"}
    assert ctx.analyzed_artifact.filename == "demo-1.0.tar.gz" and ctx.analyzed_artifact.hash_verified is True
    assert {f.relpath for f in ctx.files} == {"setup.py", "demo/__init__.py"}
    assert ctx.binaries == {"demo/_speedups.so": ELF}
    assert any(e.is_executable_binary for e in ctx.inventory)
    assert {e.relpath for e in ctx.wheel_inventory} >= {"demo_hook.pth", "demo/__init__.py"}
    assert {f.relpath for f in ctx.wheel_files} == {"demo/__init__.py", "demo_hook.pth"}


@respx.mock
def test_missing_version_fails_closed():
    _mock_registry(DEFAULT_FILES)
    respx.get(f"{JSON_BASE}/demo/9.9/json").mock(return_value=httpx.Response(404))
    with pytest.raises(AnalysisError) as info:
        _fetcher().build_context("demo", "9.9")
    assert info.value.code == "version_not_found" and info.value.status_code == 404


@respx.mock
def test_missing_version_legacy_fallback_when_fail_closed_disabled(monkeypatch):
    monkeypatch.setattr(settings, "FAIL_ON_VERSION_NOT_FOUND", False)
    _mock_registry(DEFAULT_FILES)
    respx.get(f"{JSON_BASE}/demo/9.9/json").mock(return_value=httpx.Response(404))
    ctx = _fetcher().build_context("demo", "9.9", ScanOptions(analyze_wheels=False))
    assert ctx.version == "1.0" and ctx.metadata["_version_found"] is False


@respx.mock
def test_unknown_package_propagates_not_found():
    respx.get(f"{JSON_BASE}/demo/json").mock(return_value=httpx.Response(404))
    with pytest.raises(AnalysisError) as info:
        _fetcher().build_context("demo")
    assert info.value.code == "package_not_found"


@respx.mock
def test_hash_mismatch_is_critical_context_finding_and_analysis_continues():
    _mock_registry([_file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist", sha="f" * 64)])
    ctx = _fetcher().build_context("demo", "1.0")
    [finding] = [s for s in ctx.context_signals if s.code == Code.HASH_MISMATCH]
    assert finding.severity.value == "critical" and finding.confidence == 0.98
    assert finding.evidence["expected_digest_prefix"] == "f" * 12
    assert finding.evidence["actual_digest_prefix"] == hashlib.sha256(SDIST_BYTES).hexdigest()[:12]
    assert all(len(str(v)) < 64 for v in finding.evidence.values())  # prefixes only, never full digests
    assert ctx.analyzed_artifact.hash_verified is False and ctx.files


@respx.mock
def test_no_artifacts_yields_fetch_failed():
    respx.get(f"{JSON_BASE}/demo/json").mock(return_value=httpx.Response(200, json=_project_fixture([])))
    ctx = _fetcher().build_context("demo")
    assert [s.code for s in ctx.context_signals] == [Code.FETCH_FAILED] and ctx.analyzed_artifact is None


@respx.mock
def test_oversized_sdist_falls_back_to_wheel(monkeypatch):
    monkeypatch.setattr(settings, "MAX_DOWNLOAD_BYTES", 10_000)
    files = [_file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist", size=50_000),
             _file_entry("demo-1.0-py3-none-any.whl", WHEEL_BYTES, "bdist_wheel")]
    _mock_registry(files)
    ctx = _fetcher().build_context("demo", "1.0")
    assert ctx.analyzed_artifact.filename.endswith(".whl") and ctx.wheel_inventory == []
    assert "demo_hook.pth" in {f.relpath for f in ctx.files}


@respx.mock
def test_hostile_sdist_extraction_abort_is_finding_not_error():
    evil = _tgz([("demo-1.0/setup.py", b"x=1\n"), ("demo-1.0/../../../etc/cron.d/evil", b"* * * * * root sh\n")])
    _mock_registry([_file_entry("demo-1.0.tar.gz", evil, "sdist")], sdist=evil)
    ctx = _fetcher().build_context("demo", "1.0")
    [finding] = ctx.context_signals
    assert finding.code == Code.EXTRACTION_ABORTED and finding.severity.value == "high"
    assert finding.evidence["reason"] == "unsafe_path"
    assert [f.relpath for f in ctx.files] == ["setup.py"]


@respx.mock
def test_wheel_failures_are_non_fatal():
    wheel_route = _mock_registry(DEFAULT_FILES)
    wheel_route.mock(return_value=httpx.Response(500))
    ctx = _fetcher().build_context("demo", "1.0")
    assert ctx.files and ctx.wheel_inventory == [] and ctx.context_signals == []


@respx.mock
def test_wheel_inventory_skipped_when_disabled(monkeypatch):
    wheel_route = _mock_registry(DEFAULT_FILES)
    _fetcher().build_context("demo", "1.0", ScanOptions(analyze_wheels=False))
    monkeypatch.setattr(settings, "ANALYZE_WHEELS", False)
    _fetcher().build_context("demo", "1.0")
    assert not wheel_route.called


@respx.mock
def test_artifact_on_non_allowlisted_host_is_refused():
    entry = dict(_file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist"), url="https://attacker.example/demo-1.0.tar.gz")
    respx.get(f"{JSON_BASE}/demo/json").mock(return_value=httpx.Response(200, json=_project_fixture([entry])))
    attacker = respx.get("https://attacker.example/demo-1.0.tar.gz")
    ctx = _fetcher().build_context("demo", "1.0")
    assert [s.code for s in ctx.context_signals] == [Code.FETCH_FAILED]
    assert ctx.context_signals[0].evidence["reason"] == "host_not_allowed" and not attacker.called


@respx.mock
def test_large_benign_sdist_cannot_switch_off_the_wheel_divergence_check(monkeypatch):
    """Regression: an sdist that used the whole text budget left the wheel reader a budget of 0."""
    from app.analysis.analyzers.inventory import InventoryAnalyzer

    monkeypatch.setattr(settings, "MAX_EXTRACTED_BYTES", 8192)
    monkeypatch.setattr(settings, "MAX_ANALYZED_FILE_BYTES", 2048)
    padded = _tgz([
        ("demo-1.0/setup.py", b"from setuptools import setup\nsetup(name='demo')\n"),
        ("demo-1.0/demo/__init__.py", b"VERSION = '1.0'\n"),
        *[(f"demo-1.0/docs/pad{i}.txt", b"p" * 2048) for i in range(3)],
        ("demo-1.0/docs/pad3.txt", b"p" * 2032),  # sdist text now fills the budget exactly
    ])
    wheel = _whl([("demo/__init__.py", "VERSION = '1.0'\n"), ("zz_evil.pth", "import os\n"),
                  ("demo-1.0.dist-info/METADATA", "Name: demo\n")])
    _mock_registry([_file_entry("demo-1.0.tar.gz", padded, "sdist"),
                    _file_entry("demo-1.0-py3-none-any.whl", wheel, "bdist_wheel")], sdist=padded, wheel=wheel)
    ctx = _fetcher().build_context("demo", "1.0")
    assert ctx.context_signals == []
    assert sum(len(f.text) for f in ctx.files if f.relpath != "setup.py") == 8192
    assert "zz_evil.pth" in {e.relpath for e in ctx.wheel_inventory}
    assert "zz_evil.pth" in {f.relpath for f in ctx.wheel_files}
    mismatches = [f for f in InventoryAnalyzer().analyze(ctx) if f.code == Code.SDIST_WHEEL_MISMATCH]
    assert [f.location.file for f in mismatches] == ["zz_evil.pth"]


@respx.mock
def test_transient_download_failure_raises():
    _mock_registry([_file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist")])
    respx.get(f"{FILES_BASE}/demo-1.0.tar.gz").mock(side_effect=httpx.ConnectError("reset"))
    with pytest.raises(AnalysisError) as info:
        _fetcher().build_context("demo", "1.0")
    assert info.value.code == "artifact_unavailable"


def test_injected_httpx_client_still_enforces_allowlists():
    entry = dict(_file_entry("demo-1.0.tar.gz", SDIST_BYTES, "sdist"), url="https://127.0.0.1/demo-1.0.tar.gz")
    project = _project_fixture([entry])
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=project)

    fetcher = RegistryFetcher(client=httpx.Client(transport=httpx.MockTransport(handler)))
    ctx = fetcher.build_context("demo", "1.0", ScanOptions(analyze_wheels=False))
    assert seen == ["https://pypi.org/pypi/demo/json"]
    assert ctx.context_signals[0].evidence["reason"] == "host_not_allowed"


def _art(filename: str, packagetype: str, size: int | None = 100) -> ArtifactInfo:
    return ArtifactInfo(filename=filename, url=f"{FILES_BASE}/{filename}", packagetype=packagetype, size=size)


def test_artifact_choice_prefers_sdist_then_pure_py3_wheel(monkeypatch):
    wheels = [
        _art("demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "bdist_wheel"),
        _art("demo-1.0-py2-none-any.whl", "bdist_wheel"),
        _art("demo-1.0-py2.py3-none-any.whl", "bdist_wheel"),
    ]
    sdists = [_art("demo-1.0.zip", "sdist"), _art("demo-1.0.tar.gz", "sdist")]
    assert choose_artifact([*wheels, *sdists]).filename == "demo-1.0.tar.gz"
    assert choose_wheel(wheels).filename == "demo-1.0-py2.py3-none-any.whl"
    assert choose_artifact(wheels[:1]).filename.startswith("demo-1.0-cp312")
    monkeypatch.setattr(settings, "MAX_DOWNLOAD_BYTES", 50)
    assert choose_artifact([*wheels, *sdists]) is None
    assert choose_artifact([_art("demo-1.0.tar.gz", "sdist", size=None)]).filename == "demo-1.0.tar.gz"
