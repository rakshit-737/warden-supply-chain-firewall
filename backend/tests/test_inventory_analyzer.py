"""InventoryAnalyzer tests: unit cases on hand-built inventories plus end-to-end runs on real archives."""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile

from app.analysis.analyzers.base import ArtifactInfo, InventoryEntry, PackageContext, ReleaseInfo
from app.analysis.analyzers.inventory import MAX_FINDINGS_PER_CODE, InventoryAnalyzer
from app.analysis.extraction.safe_archive import SafeArchiveReader
from app.analysis.findings import Finding, Severity
from app.analysis.signals import Code

SDIST = ArtifactInfo(filename="demo-1.0.tar.gz", url="https://files.pythonhosted.org/x", packagetype="sdist")
PURE_WHEEL_NAME = "demo-1.0-py3-none-any.whl"
PLATFORM_WHEEL_NAME = "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"


def _wheel(filename: str, *, downloaded: bool = True) -> ArtifactInfo:
    return ArtifactInfo(filename=filename, url="https://files.pythonhosted.org/w", packagetype="bdist_wheel",
                        downloaded_sha256="a" * 64 if downloaded else None)


def _e(relpath: str, *, magic: str | None = None, kind: str = "file", skipped: str | None = None) -> InventoryEntry:
    return InventoryEntry(relpath=relpath, size=10, kind=kind, sha256="b" * 64 if kind == "file" else None,
                          magic=magic, is_executable_binary=magic in {"elf", "pe", "macho"}, skipped_reason=skipped)


def _ctx(inventory=(), *, artifact=SDIST, artifacts=None, wheel_inventory=(), metadata=None, releases=(),
         context_signals=()) -> PackageContext:
    return PackageContext(
        ecosystem="pypi", name="demo", version="1.0", metadata=dict(metadata or {}),
        inventory=list(inventory), analyzed_artifact=artifact,
        artifacts=list(artifacts) if artifacts is not None else ([artifact] if artifact else []),
        wheel_inventory=list(wheel_inventory), releases=list(releases), context_signals=list(context_signals),
    )


def run(ctx: PackageContext) -> list[Finding]:
    return InventoryAnalyzer().analyze(ctx)


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


# --------------------------------------------------------------------------- BINARY_EXECUTABLE
def test_executable_in_sdist_is_flagged_with_location():
    [finding] = run(_ctx([_e("demo/_native.so", magic="elf"), _e("demo/__init__.py")]))
    assert finding.code == Code.BINARY_EXECUTABLE and finding.severity is Severity.medium
    assert finding.confidence == 0.6 and finding.location.file == "demo/_native.so"
    assert finding.capability == "native_code" and finding.evidence["magic"] == "elf"


def test_disguised_executable_has_high_confidence():
    [finding] = run(_ctx([_e("demo/utils.py", magic="elf")]))
    assert finding.severity is Severity.high and finding.confidence == 0.85 and finding.evidence["disguised"] is True


def test_known_launcher_stub_is_low_confidence():
    [finding] = run(_ctx([_e("setuptools/cli-64.exe", magic="pe")]))
    assert finding.severity is Severity.low and finding.confidence == 0.35


def test_platform_wheel_binaries_are_expected():
    wheel = _wheel(PLATFORM_WHEEL_NAME)
    assert run(_ctx([_e("demo/_native.so", magic="elf")], artifact=wheel)) == []


def test_pure_wheel_binaries_are_flagged():
    wheel = _wheel(PURE_WHEEL_NAME)
    [finding] = run(_ctx([_e("demo/payload.bin", magic="macho")], artifact=wheel))
    assert finding.code == Code.BINARY_EXECUTABLE and finding.confidence == 0.7


def test_binaries_in_inventoried_pure_wheel_are_flagged_alongside_sdist():
    ctx = _ctx([_e("demo/__init__.py")], artifacts=[SDIST, _wheel(PURE_WHEEL_NAME)],
               wheel_inventory=[_e("demo/__init__.py"), _e("demo/helper.dll", magic="pe")])
    findings = run(ctx)
    assert codes(findings) == [Code.BINARY_EXECUTABLE]
    assert findings[0].evidence["artifact"] == PURE_WHEEL_NAME


# --------------------------------------------------------------------------- NESTED_ARCHIVE / SUSPICIOUS_FILE
def test_nested_archives_flagged_low():
    [finding] = run(_ctx([_e("tests/fixtures/data.zip", magic="zip")]))
    assert finding.code == Code.NESTED_ARCHIVE and finding.severity is Severity.low
    assert finding.location.file == "tests/fixtures/data.zip"


def test_windows_payload_types_in_pure_package():
    findings = run(_ctx([_e("demo/readme.scr"), _e("scripts/install.ps1"), _e("demo/tool.exe", magic=None)]))
    by_path = {f.location.file: f for f in findings}
    assert by_path["demo/readme.scr"].severity is Severity.medium and by_path["demo/readme.scr"].confidence == 0.6
    assert by_path["scripts/install.ps1"].confidence == 0.3
    assert by_path["demo/tool.exe"].evidence["reason"] == "extension_content_mismatch"
    assert set(codes(findings)) == {Code.SUSPICIOUS_FILE}


def test_real_pe_exe_reported_once_as_binary_not_as_suspicious_extension():
    findings = run(_ctx([_e("demo/tool.exe", magic="pe")]))
    assert codes(findings) == [Code.BINARY_EXECUTABLE]


def test_extension_heuristics_skipped_for_native_packages():
    native_sdist = [_e("demo/_speedups.c"), _e("scripts/build.bat"), _e("demo/readme.scr")]
    assert run(_ctx(native_sdist)) == []
    platform_wheel = _wheel(PLATFORM_WHEEL_NAME, downloaded=False)
    with_platform_wheels = _ctx([_e("scripts/build.bat")], artifacts=[SDIST, platform_wheel])
    assert run(with_platform_wheels) == []


def test_skipped_unsafe_members_devices_and_duplicates_are_suspicious():
    inventory = [
        _e("evil\\x1b[31m.py", kind="file", skipped="control_character"),
        _e("a/b/c", kind="file", skipped="path_too_deep"),
        _e("dev/tty0", kind="device", skipped="device"),
        _e("pipe", kind="other", skipped="fifo"),
        _e("demo/__init__.py"),
        _e("demo/__init__.py"),
        _e("demo/link", kind="symlink", skipped="symlink"),
    ]
    findings = run(_ctx(inventory))
    reasons = sorted(f.evidence["reason"] for f in findings)
    assert reasons == ["control_character", "device", "duplicate_member_name", "fifo", "path_too_deep"]
    assert all(f.code == Code.SUSPICIOUS_FILE for f in findings)


# --------------------------------------------------------------------------- YANKED_RELEASE
def test_yanked_release_severity_depends_on_reason():
    [security] = run(_ctx(metadata={"yanked": True, "yanked_reason": "Compromised maintainer account"}))
    assert security.code == Code.YANKED_RELEASE and security.severity is Severity.medium
    assert security.provenance == "registry-metadata" and security.evidence["security_related_reason"] is True
    [plain] = run(_ctx(releases=[ReleaseInfo(version="1.0", upload_time=None, yanked=True)]))
    assert plain.severity is Severity.low and plain.evidence["yanked_reason"] is None
    assert run(_ctx(metadata={"yanked": False})) == []


# --------------------------------------------------------------------------- SDIST_WHEEL_MISMATCH
def _mismatch_ctx(sdist_paths, wheel_paths, **kwargs) -> PackageContext:
    return _ctx([_e(p) for p in sdist_paths], artifacts=[SDIST, _wheel(PURE_WHEEL_NAME)],
                wheel_inventory=[_e(p) for p in wheel_paths], **kwargs)


def test_wheel_only_code_is_reported():
    ctx = _mismatch_ctx(
        ["setup.py", "src/demo/__init__.py", "src/demo/core.py"],
        ["demo/__init__.py", "demo/core.py", "demo/_version.py", "demo/extra.py", "demo_startup.pth",
         "demo-1.0.dist-info/RECORD", "demo-1.0.dist-info/evil.py", "demo-1.0.data/purelib/demo/core.py"],
    )
    findings = [f for f in run(ctx) if f.code == Code.SDIST_WHEEL_MISMATCH]
    by_path = {f.location.file: f for f in findings}
    assert set(by_path) == {"demo/extra.py", "demo_startup.pth"}
    assert by_path["demo_startup.pth"].severity is Severity.high and by_path["demo_startup.pth"].confidence == 0.8
    assert by_path["demo/extra.py"].severity is Severity.medium and by_path["demo/extra.py"].confidence == 0.65


def test_same_basename_decoy_elsewhere_in_the_sdist_does_not_hide_wheel_only_pth():
    """Regression: every trailing path suffix of every sdist member used to count as 'present'."""
    ctx = _mismatch_ctx(["setup.py", "tests/data/zz_evil.pth", "tests/zz_evil.pth", "demo/__init__.py"],
                        ["zz_evil.pth", "demo/__init__.py"])
    [finding] = [f for f in run(ctx) if f.code == Code.SDIST_WHEEL_MISMATCH]
    assert finding.location.file == "zz_evil.pth" and finding.severity is Severity.high
    # The documented, bounded layout rewrites still match.
    for root in ("src", "lib", "python"):
        assert Code.SDIST_WHEEL_MISMATCH not in codes(run(_mismatch_ctx([f"{root}/demo/core.py"], ["demo/core.py"])))
    assert Code.SDIST_WHEEL_MISMATCH in codes(run(_mismatch_ctx(["vendor/demo/core.py"], ["demo/core.py"])))


def test_wheel_extraction_abort_does_not_switch_off_the_divergence_check():
    wheel_abort = Finding(Code.EXTRACTION_ABORTED, Severity.high, 6.0, "aborted", {"artifact": PURE_WHEEL_NAME})
    ctx = _mismatch_ctx(["setup.py"], ["demo/evil.py"], context_signals=[wheel_abort])
    assert Code.SDIST_WHEEL_MISMATCH in codes(run(ctx))
    sdist_abort = Finding(Code.EXTRACTION_ABORTED, Severity.high, 6.0, "aborted", {"artifact": SDIST.filename})
    assert run(_mismatch_ctx(["setup.py"], ["demo/evil.py"], context_signals=[sdist_abort])) == []


def test_zip_member_type_mismatch_is_suspicious():
    wheel = _wheel(PURE_WHEEL_NAME)
    entries = [InventoryEntry("evilpkg/__init__.py", 40, "file", sha256="c" * 64, declared_kind="symlink"),
               InventoryEntry("evilpkg/notes", 12, "file", sha256="d" * 64, declared_kind="dir")]
    findings = {f.location.file: f for f in run(_ctx(entries, artifact=wheel))}
    code_file, data_file = findings["evilpkg/__init__.py"], findings["evilpkg/notes"]
    assert code_file.code == Code.SUSPICIOUS_FILE and code_file.severity is Severity.high
    assert code_file.evidence["reason"] == "member_type_mismatch" and code_file.evidence["declared_kind"] == "symlink"
    assert data_file.severity is Severity.medium and data_file.confidence == 0.6


def test_budget_skipped_members_are_reported_once_per_artifact():
    skip = "text_budget_exceeded"
    inventory = [_e("demo/core.py", skipped=skip), _e("docs/a.txt", skipped=skip), _e("docs/b.txt", skipped=skip),
                 _e("setup.py")]
    [finding] = run(_ctx(inventory))
    assert finding.code == Code.SUSPICIOUS_FILE and finding.severity is Severity.high and finding.weight == 6.0
    assert finding.evidence["skipped_members"] == 3 and finding.evidence["skipped_code_members"] == 1
    assert finding.evidence["examples"] == ["demo/core.py"] and finding.location.file == "demo/core.py"
    [data_only] = run(_ctx([_e("docs/a.txt", skipped=skip)]))
    assert data_only.severity is Severity.medium and data_only.evidence["skipped_code_members"] == 0


def test_mismatch_not_reported_from_partial_inventory_or_wheel_only_scan():
    aborted = Finding(Code.EXTRACTION_ABORTED, Severity.medium, 4.0, "aborted", {})
    assert run(_mismatch_ctx(["setup.py"], ["demo/evil.py"], context_signals=[aborted])) == []
    wheel = _wheel(PURE_WHEEL_NAME)
    ctx = _ctx([_e("demo/evil.py")], artifact=wheel, wheel_inventory=[_e("demo/other.py")])
    assert Code.SDIST_WHEEL_MISMATCH not in codes(run(ctx))


# --------------------------------------------------------------------------- caps / contract
def test_findings_are_capped_per_code():
    inventory = [_e(f"tests/data/archive{i}.zip", magic="zip") for i in range(40)]
    findings = run(_ctx(inventory))
    nested = [f for f in findings if f.code == Code.NESTED_ARCHIVE]
    assert len(nested) == MAX_FINDINGS_PER_CODE + 1
    assert nested[-1].severity is Severity.info and nested[-1].evidence["omitted"] == 40 - MAX_FINDINGS_PER_CODE


def test_empty_context_and_taxonomy_defaults():
    assert run(_ctx(artifact=None)) == []
    [finding] = run(_ctx([_e("demo/_native.so", magic="elf")]))
    stamped = finding.with_defaults(analyzer="inventory", analyzer_version=InventoryAnalyzer.version)
    assert stamped.category == "suspicious_artifact" and stamped.cwe == ("CWE-912",)


# --------------------------------------------------------------------------- end to end with real archives
def _tgz(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def test_end_to_end_disguised_binary_and_wheel_only_pth():
    pe = bytearray(b"MZ" + b"\x00" * 0x100)
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    sdist = SafeArchiveReader().read(_tgz([
        ("demo-1.0/setup.py", b"from setuptools import setup\nsetup()\n"),
        ("demo-1.0/demo/__init__.py", b"x = 1\n"),
        ("demo-1.0/demo/helpers.py", b"\x7fELF\x02\x01\x01" + b"\x00" * 64),
        ("demo-1.0/tests/fixture.tar.gz", _tgz([("inner/evil.py", b"import os\n")])),
    ]), "demo-1.0.tar.gz")
    wheel = SafeArchiveReader().read(_zip([
        ("demo/__init__.py", b"x = 1\n"),
        ("demo/helpers.py", b"\x7fELF\x02\x01\x01" + b"\x00" * 64),
        ("zz_hook.pth", b"import demo.helpers\n"),
        ("demo/launcher.exe", bytes(pe)),
        ("demo-1.0.dist-info/METADATA", b"Name: demo\n"),
    ]), PURE_WHEEL_NAME)
    ctx = _ctx(sdist.inventory, artifacts=[SDIST, _wheel(PURE_WHEEL_NAME)], wheel_inventory=wheel.inventory)
    findings = run(ctx)
    summary = sorted((f.code, f.location.file if f.location else None) for f in findings)
    assert summary == [
        (Code.BINARY_EXECUTABLE, "demo/helpers.py"),  # sdist
        (Code.BINARY_EXECUTABLE, "demo/helpers.py"),  # pure wheel
        (Code.BINARY_EXECUTABLE, "demo/launcher.exe"),
        (Code.NESTED_ARCHIVE, "tests/fixture.tar.gz"),
        (Code.SDIST_WHEEL_MISMATCH, "zz_hook.pth"),  # .exe files are not code-divergence candidates
    ]
