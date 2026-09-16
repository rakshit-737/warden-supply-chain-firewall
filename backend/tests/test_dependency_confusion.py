"""Dependency-confusion detection: namespace globbing, public-index snapshot, package analyzer, project findings.

All inputs are synthetic (see ``tests/data/depconf/README.md``): ``examplecorp-*`` names a fictional
organisation's internal packages and the snapshot fixtures say nothing about the real PyPI. No test
touches the network: HTTP is mocked with respx, and the privacy tests run under respx routers that
have no routes for the calls in question, so any request would be recorded and fail.
"""

from __future__ import annotations

import fnmatch
import gzip
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import respx
from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from app.analysis.analyzers.base import PackageContext, ReleaseInfo, ScanOptions
from app.analysis.analyzers.dependency_confusion import (
    DependencyConfusionAnalyzer,
    plausible_calver,
    version_squatting_evidence,
)
from app.analysis.depconf import (
    IndexClassifier,
    PatternError,
    PrivateNamespaces,
    canonical_name,
    compile_pattern,
    resolve_private_namespaces,
)
from app.analysis.depconf import index_snapshot as snapshots
from app.analysis.depconf import project as depconf_project
from app.analysis.depconf.index_snapshot import (
    SIMPLE_JSON_ACCEPT,
    PublicIndexSnapshot,
    SnapshotError,
    SnapshotHeader,
    load_configured_snapshot,
    load_snapshot,
)
from app.analysis.depconf.project import PublicIndexLookup, project_confusion_findings
from app.analysis.findings import Finding, Location, Provenance, Severity
from app.analysis.signals import Capability, Code
from app.core.config import settings
from app.core.http import SafeHttpClient
from app.sbom import hygiene_findings, parse_project

DATA = Path(__file__).parent / "data" / "depconf"
BACKEND = Path(__file__).resolve().parent.parent
PRIVATE_INDEX = "https://pkgs.examplecorp.example/simple"
SIMPLE = "https://pypi.org/simple"
BASE = datetime(2026, 9, 1, tzinfo=timezone.utc)
HASH = "a" * 64
DC, NC = Code.DEPENDENCY_CONFUSION, Code.NAMESPACE_COLLISION


@pytest.fixture(autouse=True)
def _depconf_settings(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", [])
    monkeypatch.setattr(settings, "PRIVATE_INDEX_URLS", [])
    monkeypatch.setattr(settings, "DEPCONF_ALLOW_PUBLIC_LOOKUP", False)
    monkeypatch.setattr(settings, "PUBLIC_INDEX_SNAPSHOT_PATH", None)
    monkeypatch.setattr(settings, "PYPI_JSON_BASE", "https://pypi.org/pypi")
    monkeypatch.setattr(settings, "PYPI_SIMPLE_BASE", SIMPLE)
    snapshots.clear_snapshot_cache()
    yield
    snapshots.clear_snapshot_cache()


def namespaces(*patterns: str, scan: tuple[str, ...] = ()) -> PrivateNamespaces:
    return PrivateNamespaces.from_sources({"settings": list(patterns), "scan_options": list(scan)})


def line_of(content: bytes | str, needle: str) -> int:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    hits = [i for i, line in enumerate(text.splitlines(), start=1) if needle in line]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def test_http_client(**kwargs) -> SafeHttpClient:
    return SafeHttpClient(name="test-depconf", allowed_hosts=["pypi.org"], retries=0, sleep=lambda s: None, **kwargs)


test_http_client.__test__ = False  # a helper, not a test


# ====================================================================================== namespace globbing
@pytest.mark.parametrize(("pattern", "name", "expected"), [
    ("examplecorp-*", "examplecorp-auth", True),
    ("examplecorp-*", "ExampleCorp_Auth", True),  # case and separator spelling cannot evade
    ("examplecorp-*", "EXAMPLECORP.AUTH", True),
    ("ExampleCorp_*", "examplecorp-auth", True),  # the pattern is canonicalised too
    ("examplecorp.internal.*", "examplecorp_internal__tools", True),
    ("examplecorp--*", "examplecorp-auth", True),  # separator runs collapse
    ("examplecorp-*", "examplecorp", False),  # anchored: the separator is required
    ("examplecorp-*", "examplecorpauth", False),
    ("examplecorp-*", "not-examplecorp-auth", False),  # anchored at the start
    ("examplecorp*", "examplecorp", True),
    ("examplecorp*", "examplecorp-auth", True),
    ("*-internal", "billing_internal", True),
    ("*-internal", "billing-internals", False),  # anchored at the end
    ("svc-?", "svc-a", True),
    ("svc-?", "svc-ab", False),
    ("svc-[0-9]*", "svc-7-api", True),
    ("svc-[0-9]*", "svc-x-api", False),
    ("svc-[!0-9]*", "svc-x-api", True),
    ("svc[_]api", "svc-api", True),  # a separator inside a class matches the canonical separator
    ("SVC-[A-C]", "svc-b", True),
    ("examplecorp-auth", "examplecorp.auth", True),  # a pattern without wildcards is an exact name
    ("examplecorp-auth", "examplecorp-auth2", False),
])
def test_namespace_glob_semantics(pattern, name, expected):
    assert (namespaces(pattern).match(name) is not None) is expected


@pytest.mark.parametrize(("pattern", "reason"), [
    ("*", "too_broad"),
    ("?*", "too_broad"),
    ("a*", "too_broad"),
    ("*-*", "too_broad"),
    ("[ab][cd]*", "too_broad"),
    ("examplecorp[", "invalid_class"),
    ("svc-[]", "invalid_class"),
    ("svc-[z-a]", "invalid_class"),
    ("svc-[0-z]", "invalid_class"),
    ("example corp*", "invalid_character"),
    ("examplecorp/*", "invalid_character"),
    ("exämplecorp-*", "invalid_character"),
    ("x" * 129, "too_long"),
    ("!", "empty"),
])
def test_unusable_patterns_are_rejected_reported_and_do_not_disable_valid_ones(pattern, reason):
    with pytest.raises(PatternError) as info:
        compile_pattern(pattern)
    assert info.value.reason == reason
    compiled = namespaces(pattern, "examplecorp-*")
    assert [(r["source"], r["reason"]) for r in compiled.rejected] == [("settings", reason)]
    assert compiled.match("examplecorp-auth") is not None


def test_pattern_count_is_bounded():
    many = [f"team{i:03d}-*" for i in range(300)]
    compiled = namespaces(*many, scan=("svc-*",))
    assert len(compiled.includes) == 256
    assert list(compiled.rejected) == [
        {"pattern": "<44 more>", "source": "settings", "reason": "too_many"},
        {"pattern": "<1 more>", "source": "scan_options", "reason": "too_many"},
    ]


def test_scan_option_patterns_given_as_a_string_are_split_not_exploded_and_compiled_sets_are_shared():
    resolved = resolve_private_namespaces(ScanOptions(private_namespaces="examplecorp-*,*-internal"))  # type: ignore
    assert {p.glob for p in resolved.includes} == {"examplecorp-*", "*-internal"} and not resolved.rejected
    options = ScanOptions(private_namespaces=("examplecorp-*",))
    assert resolve_private_namespaces(options) is resolve_private_namespaces(options)
    odd = resolve_private_namespaces(ScanOptions(private_namespaces=("examplecorp-*", 42)))  # type: ignore
    assert [r["reason"] for r in odd.rejected] == ["not_a_string"] and odd.match("examplecorp-auth")


def test_exclusions_from_settings_win_but_scan_options_cannot_switch_protection_off():
    compiled = namespaces("examplecorp-*", "!examplecorp-public-sdk")
    assert compiled.match("ExampleCorp_Public.SDK") is None
    assert compiled.match("examplecorp-auth") is not None
    evasion = namespaces("examplecorp-*", scan=("!examplecorp-*",))
    assert evasion.match("examplecorp-auth") is not None
    assert evasion.rejected == (
        {"pattern": "!examplecorp-*", "source": "scan_options", "reason": "exclusion_not_allowed"},
    )


def test_first_sorted_pattern_wins_and_duplicates_collapse_deterministically():
    compiled = namespaces("examplecorp-*", "ExampleCorp_*", scan=("examplecorp-auth", "examplecorp-*"))
    assert [(p.glob, p.source) for p in compiled.includes] == [("examplecorp-*", "settings"),
                                                              ("examplecorp-auth", "scan_options")]
    match = compiled.match("examplecorp-auth")
    assert (match.pattern, match.source, match.raw) == ("examplecorp-*", "settings", "examplecorp-*")


def test_resolve_private_namespaces_reads_settings_at_call_time(monkeypatch):
    assert not resolve_private_namespaces(ScanOptions())
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    resolved = resolve_private_namespaces(ScanOptions(private_namespaces=("*-internal",)))
    assert {(p.glob, p.source) for p in resolved.includes} == {("examplecorp-*", "settings"),
                                                               ("*-internal", "scan_options")}


@pytest.mark.parametrize("name", [
    "", "   ", "../examplecorp-auth", "examplecorp auth", "examplecorp-auth\x1b[2J", "examplecorp‮-auth",
    "-examplecorp-auth", "examplecorp-auth-", "examplecorp-" + "e" * 210, None, 42,
])
def test_invalid_or_hostile_names_never_match(name):
    assert namespaces("examplecorp*", "*auth*").match(name) is None
    assert canonical_name(name) is None


def test_matching_is_bounded_on_adversarial_patterns_and_names():
    pattern = compile_pattern("a" + "*a" * 20 + "*b")
    hostile = "a" * 214
    start = time.perf_counter()
    for _ in range(500):
        assert not pattern.matches(hostile)
    assert time.perf_counter() - start < 2.0  # linear-time wildcard segments, no exponential backtracking
    assert pattern.matches("a" * 30 + "b")


@hypothesis_settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    pattern=st.lists(st.sampled_from(["a", "b", "c", "-", "*", "?"]), min_size=1, max_size=12).map("".join),
    name=st.from_regex(r"[abc](?:[abc-]{0,10}[abc])?", fullmatch=True),
)
def test_glob_matching_agrees_with_fnmatch_on_canonical_input(pattern, name):
    canonical = canonical_name(name)
    try:
        compiled = compile_pattern(pattern)
    except PatternError:
        return
    assert compiled.matches(canonical) == fnmatch.fnmatchcase(canonical, compiled.glob)


# ====================================================================================== index classification
@pytest.mark.parametrize(("url", "expected"), [
    ("https://pkgs.examplecorp.example/simple", "private"),
    ("https://pkgs.examplecorp.example/simple/", "private"),
    ("https://ci-bot:tok@pkgs.examplecorp.example/simple", "private"),
    ("https://[REDACTED]@PKGS.examplecorp.example:443/simple/team/?[REDACTED]", "private"),
    ("https://pkgs.examplecorp.example/simple-proxy", "other"),  # path prefix is segment-wise
    ("https://pkgs.examplecorp.example:8443/simple", "other"),
    ("https://pypi.org/simple", "public"),  # listed as "private" below, still public
    ("https://test.pypi.org/simple/", "public"),
    ("https://mirror.example/simple", "other"),
    ("./wheels", "local"),
])
def test_index_classification(url, expected):
    classifier = IndexClassifier([PRIVATE_INDEX, "https://pypi.org/simple", "not a url"])
    assert classifier.classify(url) == expected
    assert classifier.invalid_count == 1


# ====================================================================================== snapshot loading
@pytest.mark.parametrize("filename", ["public_index_snapshot.txt", "public_index_snapshot.txt.gz"])
def test_snapshot_fixture_loads_header_names_and_skips_malformed_lines(filename):
    snapshot = load_snapshot(DATA / filename)
    assert snapshot.compressed is filename.endswith(".gz")
    assert snapshot.header == SnapshotHeader(format="warden-public-index-snapshot v1", source="https://pypi.org/simple/",
                                             generated_at="2026-09-01T00:00:00Z", count=8)
    assert (len(snapshot), snapshot.names_read, snapshot.skipped_lines, snapshot.complete) == (8, 8, 5, True)
    for present in ("requests", "Requests", "requests-oauthlib", "Requests.OAuthlib", "urllib3",
                    "examplecorp_shared_utils", "EXAMPLECORP-AUTH"):
        assert present in snapshot and snapshot.presence(present) == "present", present
    for absent in ("examplecorp-ledger", "not-a-valid-name", "leading-dash", "bad-slash", "numpy"):
        assert absent not in snapshot and snapshot.presence(absent) == "absent", absent
    assert "not a valid name" not in snapshot and "../requests" not in snapshot


def test_gzip_is_detected_by_magic_bytes_not_file_name(tmp_path):
    disguised = tmp_path / "snapshot.txt"
    disguised.write_bytes((DATA / "public_index_snapshot.txt.gz").read_bytes())
    snapshot = load_snapshot(disguised)
    assert snapshot.compressed and "examplecorp-billing-sdk" in snapshot


def test_truncated_snapshot_answers_unknown_instead_of_absent(tmp_path):
    path = tmp_path / "truncated.txt"
    path.write_text("# count: 5\nrequests\nflask\n", encoding="ascii")
    snapshot = load_snapshot(path)
    assert not snapshot.complete
    assert snapshot.presence("flask") == "present"
    assert snapshot.presence("examplecorp-auth") == "unknown"


def test_headerless_snapshot_with_duplicates_loads(tmp_path):
    path = tmp_path / "plain.txt"
    path.write_text("requests\nRequests\nflask\n", encoding="ascii")
    snapshot = load_snapshot(path)
    assert (len(snapshot), snapshot.names_read, snapshot.header.count, snapshot.complete) == (2, 3, None, True)


def test_snapshot_load_errors_are_typed(tmp_path):
    cases = {}
    cases["not_found"] = tmp_path / "missing.txt"
    (tmp_path / "a-directory").mkdir()
    cases["not_a_file"] = tmp_path / "a-directory"
    empty = tmp_path / "empty.txt"
    empty.write_text("# warden-public-index-snapshot v1\n# count: 0\nnot a name\n-bad\n", encoding="ascii")
    cases["empty"] = empty
    truncated_gzip = tmp_path / "truncated.gz"
    truncated_gzip.write_bytes(gzip.compress(b"requests\n" * 1000, mtime=0)[:40])
    cases["corrupt"] = truncated_gzip
    fake_gzip = tmp_path / "fake.gz"
    fake_gzip.write_bytes(b"\x1f\x8b" + b"not really gzip")
    for kind, path in cases.items():
        with pytest.raises(SnapshotError) as info:
            load_snapshot(path)
        assert info.value.kind == kind, (kind, info.value.kind)
    with pytest.raises(SnapshotError) as info:
        load_snapshot(fake_gzip)
    assert info.value.kind == "corrupt"


def test_gzip_bomb_name_flood_and_oversized_file_are_bounded(tmp_path):
    bomb = tmp_path / "bomb.gz"
    bomb.write_bytes(gzip.compress(b"requests\n" * 1_000_000, mtime=0))  # ~9 MiB decompressed, tiny on disk
    assert bomb.stat().st_size < 64 * 1024
    with pytest.raises(SnapshotError) as info:
        load_snapshot(bomb, max_bytes=1024 * 1024)
    assert info.value.kind == "too_large"

    flood = tmp_path / "flood.txt"
    flood.write_text("\n".join(f"pkg{i}" for i in range(101)) + "\n", encoding="ascii")
    with pytest.raises(SnapshotError) as info:
        load_snapshot(flood, max_names=100)
    assert info.value.kind == "too_large"

    big = tmp_path / "big.txt"
    big.write_bytes(b"requests\n" * 200)
    with pytest.raises(SnapshotError) as info:
        load_snapshot(big, max_bytes=1000)
    assert info.value.kind == "too_large"


def test_overlong_line_is_skipped_without_buffering_it(tmp_path):
    path = tmp_path / "long-line.txt"
    path.write_bytes(b"requests\n" + b"x" * (5 * 1024 * 1024) + b"\nflask\n")
    snapshot = load_snapshot(path)
    assert (len(snapshot), snapshot.skipped_lines) == (2, 1)
    assert "flask" in snapshot


def test_snapshot_membership_is_compact():
    names = [f"project-{i}" for i in range(20000)]
    snapshot = PublicIndexSnapshot.from_names(names)
    assert len(snapshot) == 20000 and "project-19999" in snapshot and "project-20000" not in snapshot
    assert snapshot._digests.itemsize == 8  # 8 bytes per name, not a set of Python strings


@pytest.mark.parametrize("suffix", [".txt", ".txt.gz"])
def test_write_snapshot_round_trip_is_canonical_sorted_atomic_and_deterministic(tmp_path, suffix):
    names = ["Requests", "requests", "zope.interface", "Flask", "bad name", ""]
    out = tmp_path / f"names{suffix}"
    kwargs = {"source": "https://pypi.org/simple/", "generated_at": "2026-09-15T00:00:00Z"}
    assert snapshots.write_snapshot(names, out, **kwargs) == 3
    first = out.read_bytes()
    snapshots.write_snapshot(list(reversed(names)), out, **kwargs)
    assert out.read_bytes() == first
    text = gzip.decompress(first) if suffix.endswith(".gz") else first
    assert text.decode("ascii").splitlines() == [
        "# warden-public-index-snapshot v1", "# source: https://pypi.org/simple/",
        "# generated_at: 2026-09-15T00:00:00Z", "# count: 3", "flask", "requests", "zope-interface",
    ]
    loaded = load_snapshot(out)
    assert loaded.complete and len(loaded) == 3 and loaded.compressed is suffix.endswith(".gz")
    assert not list(tmp_path.glob(".snapshot-*"))


def test_header_values_cannot_inject_lines(tmp_path):
    out = tmp_path / "names.txt"
    snapshots.write_snapshot(["requests"], out, source="https://pypi.org/simple/\nevil-injected", generated_at="now")
    lines = out.read_text(encoding="ascii").splitlines()
    assert lines[1].startswith("# source: ") and "evil-injected" in lines[1] and lines[4] == "requests"
    assert "evil-injected" not in load_snapshot(out)


def test_configured_snapshot_status_cache_and_safe_errors(tmp_path, monkeypatch):
    status = load_configured_snapshot()
    assert (status.status, status.snapshot) == ("not_configured", None)

    path = tmp_path / "configured.txt"
    path.write_text("requests\n", encoding="ascii")
    monkeypatch.setattr(settings, "PUBLIC_INDEX_SNAPSHOT_PATH", str(path))
    first = load_configured_snapshot()
    assert first.status == "ok" and "requests" in first.snapshot
    assert load_configured_snapshot().snapshot is first.snapshot  # cached while size/mtime are unchanged

    path.write_text("requests\nflask\n", encoding="ascii")
    assert "flask" in load_configured_snapshot().snapshot  # reloaded after the file changed

    path.write_bytes(b"\x1f\x8b broken")
    broken = load_configured_snapshot()
    assert (broken.status, broken.detail) == ("error", "snapshot corrupt")
    assert str(tmp_path) not in json.dumps(broken.to_dict())


# ====================================================================================== snapshot builder
def _index_response(content: bytes | None = None, content_type: str = SIMPLE_JSON_ACCEPT) -> httpx.Response:
    body = content if content is not None else (DATA / "simple_index_pep691.json").read_bytes()
    return httpx.Response(200, content=body, headers={"Content-Type": content_type})


def test_build_snapshot_from_pep691_root_index(tmp_path):
    out = tmp_path / "pypi-names.txt.gz"
    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://pypi.org/simple/").mock(return_value=_index_response())
        result = snapshots.build_snapshot(
            out, max_bytes=1024 * 1024, clock=lambda: datetime(2026, 9, 15, 12, 0, 0, 123456, tzinfo=timezone.utc))
    assert route.calls.last.request.headers["Accept"] == SIMPLE_JSON_ACCEPT
    assert (result.count, result.skipped, result.source, result.generated_at) == \
        (4, 4, "https://pypi.org/simple/", "2026-09-15T12:00:00Z")
    snapshot = load_snapshot(out)
    assert snapshot.header == SnapshotHeader(format="warden-public-index-snapshot v1", source="https://pypi.org/simple/",
                                             generated_at="2026-09-15T12:00:00Z", count=4)
    assert all(n in snapshot for n in ("requests", "examplecorp-auth", "flask", "zope.interface"))
    assert "bad-name" not in snapshot


def _json(data: dict) -> bytes:
    return json.dumps(data).encode("utf-8")


@pytest.mark.parametrize(("response", "kind"), [
    (httpx.Response(200, content=b"<html><body>index</body></html>", headers={"Content-Type": "text/html"}),
     "invalid_response"),
    (_index_response(_json({"meta": {"api-version": "2.0"}, "projects": [{"name": "requests"}]})), "invalid_response"),
    (_index_response(b"{not json"), "invalid_response"),
    (_index_response(_json({"meta": {"api-version": "1.0"}, "projects": {"name": "requests"}})), "invalid_response"),
    (_index_response(_json({"meta": {"api-version": "1.0"}, "projects": [{"name": "bad name"}, 7]})), "empty"),
    (httpx.Response(404), "invalid_response"),
])
def test_build_snapshot_rejects_unexpected_responses_and_writes_nothing(tmp_path, response, kind):
    out = tmp_path / "names.txt"
    with respx.mock() as router:
        router.get("https://pypi.org/simple/").mock(return_value=response)
        with pytest.raises(SnapshotError) as info:
            snapshots.build_snapshot(out, http=test_http_client())
    assert info.value.kind == kind
    assert not out.exists()


def test_build_snapshot_enforces_size_cap_and_host_allowlist(tmp_path):
    out = tmp_path / "names.txt"
    with respx.mock() as router:
        router.get("https://pypi.org/simple/").mock(return_value=_index_response())
        with pytest.raises(SnapshotError) as info:
            snapshots.build_snapshot(out, http=test_http_client(), max_bytes=64)
    assert info.value.kind == "too_large" and not out.exists()

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        with pytest.raises(SnapshotError) as info:
            snapshots.build_snapshot(out, simple_base="https://evil.example/simple")
        assert router.calls.call_count == 0
    assert info.value.kind == "refused"

    with pytest.raises(ValueError):
        snapshots.build_snapshot(out, max_bytes=0)


def test_cli_build_and_info(tmp_path, capsys):
    out = tmp_path / "names.txt"
    with respx.mock() as router:
        router.get("https://pypi.org/simple/").mock(return_value=_index_response())
        assert snapshots.main(["build", "--out", str(out), "--max-bytes", "1048576"], http=test_http_client()) == 0
    assert "wrote 4 project names" in capsys.readouterr().out
    assert snapshots.main(["info", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "loaded: 4" in printed and "complete: True" in printed and "source: https://pypi.org/simple/" in printed
    assert snapshots.main(["info", str(tmp_path / "missing.txt")]) == 1
    assert "not_found" in capsys.readouterr().err
    assert snapshots.main(["build", "--out", str(out), "--max-bytes", "0"]) == 2


def test_module_entry_point_runs_offline():
    completed = subprocess.run(
        [sys.executable, "-m", "app.analysis.depconf.index_snapshot", "info", str(DATA / "public_index_snapshot.txt")],
        cwd=BACKEND, capture_output=True, text=True, timeout=120, env={**os.environ, "INTEL_OFFLINE": "true"},
    )
    assert completed.returncode == 0, completed.stderr
    assert "header_count: 8" in completed.stdout and "skipped_lines: 5" in completed.stdout


# ====================================================================================== package analyzer
def release(version: str, day: float = 0.0) -> ReleaseInfo:
    return ReleaseInfo(version=version, upload_time=(BASE + timedelta(days=day)).isoformat(), file_count=1)


def make_ctx(name: str = "examplecorp-auth", version: str = "1.0.0", *, releases: list[ReleaseInfo] | None = None,
             age_days: object = 2.0, private: tuple[str, ...] = (), ecosystem: str = "pypi") -> PackageContext:
    metadata = {} if age_days is None else {"_age_days": age_days}
    return PackageContext(
        ecosystem=ecosystem, name=name, version=version, metadata=metadata,
        releases=[release(version)] if releases is None else releases,
        options=ScanOptions(private_namespaces=tuple(private)),
    )


ESTABLISHED = [release(f"2.{i}.0", -900 + i * 30) for i in range(20)]


def analyze(ctx: PackageContext) -> list[Finding]:
    return DependencyConfusionAnalyzer().analyze(ctx)


def test_analyzer_contract():
    analyzer = DependencyConfusionAnalyzer()
    assert (analyzer.name, analyzer.version, analyzer.requires_network) == ("dependency_confusion", "1.0.0", False)
    assert analyzer.availability().available


def test_public_package_under_private_namespace_is_critical(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    [finding] = analyze(make_ctx("ExampleCorp_Auth", "2.19.0", releases=ESTABLISHED, age_days=300.0))
    assert (finding.code, finding.severity, finding.weight, finding.confidence) == (DC, Severity.critical, 12.0, 0.9)
    assert finding.capability == Capability.DEPENDENCY_CONFUSION
    assert finding.provenance == Provenance.REGISTRY and finding.location is None
    evidence = finding.evidence
    assert evidence["normalized_name"] == "examplecorp-auth"
    assert (evidence["matched_pattern"], evidence["pattern_source"]) == ("examplecorp-*", "settings")
    assert (evidence["registry"], evidence["registry_classification"]) == ("https://pypi.org/pypi", "public")
    assert (evidence["release_count"], evidence["context"]) == (20, "resolution-time")
    assert "version_squatting" not in evidence

    stamped = finding.with_defaults(analyzer="dependency_confusion", analyzer_version="1.0.0")
    assert (stamped.category, stamped.title) == ("dependency_confusion", "Dependency confusion risk")
    assert Finding.from_dict(json.loads(json.dumps(stamped.to_dict()))).finding_id == stamped.finding_id


def test_scan_option_namespaces_are_honoured():
    [finding] = analyze(make_ctx("examplecorp-auth", "2.19.0", releases=ESTABLISHED, private=("examplecorp-*",)))
    assert finding.evidence["pattern_source"] == "scan_options" and finding.severity == Severity.critical


def test_private_or_unverifiable_registry_changes_the_verdict(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    ctx = make_ctx("examplecorp-auth", "2.19.0", releases=ESTABLISHED)
    monkeypatch.setattr(settings, "PYPI_JSON_BASE", "https://pkgs.examplecorp.example/pypi")
    monkeypatch.setattr(settings, "PRIVATE_INDEX_URLS", ["https://pkgs.examplecorp.example/"])
    assert analyze(ctx) == []  # fetched from the private index itself: expected to be there
    monkeypatch.setattr(settings, "PRIVATE_INDEX_URLS", [])
    [finding] = analyze(ctx)
    assert finding.confidence == 0.6 and finding.evidence["registry_classification"] == "other"


def test_internal_package_on_the_private_registry_is_not_reported_even_with_a_build_number_version(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    monkeypatch.setattr(settings, "PYPI_JSON_BASE", "https://pkgs.examplecorp.example/pypi")
    monkeypatch.setattr(settings, "PRIVATE_INDEX_URLS", ["https://pkgs.examplecorp.example/"])
    # A brand-new internal package whose internal version scheme is a CI build number.
    assert analyze(make_ctx("examplecorp-auth", "1234.0.0", age_days=1.0)) == []
    # Names outside the private namespace keep the version heuristic whatever the registry is.
    [finding] = analyze(make_ctx("fresh-tool", "1234.0.0", age_days=1.0))
    assert (finding.severity, finding.confidence) == (Severity.medium, 0.5)


def test_findings_are_resolution_time_so_they_cannot_corroborate_runtime_behaviour(monkeypatch):
    """False-positive guard: the correlation engine treats install-time context as corroboration."""
    from app.analysis.correlation.engine import correlate

    # A benign SDK pattern: cloud credentials read from the environment at runtime, not at install time.
    env = Finding(Code.ENV_HARVEST, Severity.high, 6.0, "reads AWS_ACCESS_KEY_ID", {"variables": ["AWS_ACCESS_KEY_ID"]},
                  confidence=0.9, location=Location(file="fresh_tool/credentials.py", line=12),
                  ).with_defaults(analyzer="static_code", analyzer_version="test")
    [squat] = analyze(make_ctx("fresh-tool", "99.0.0", age_days=1.0))
    assert not squat.evidence["context"].startswith(("install", "build", "setup"))
    squat = squat.with_defaults(analyzer="dependency_confusion", analyzer_version="1.0.0")
    assert not correlate([squat, env]).chains  # a 0.5 version heuristic must not vouch for itself

    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    [namespace] = analyze(make_ctx("examplecorp-auth", "2.19.0", releases=ESTABLISHED, age_days=300.0))
    namespace = namespace.with_defaults(analyzer="dependency_confusion", analyzer_version="1.0.0")
    # Strong evidence on both sides still correlates (true positive).
    assert any(c.chain_id == "dependency_confusion_payload" for c in correlate([namespace, env]).chains)


@pytest.mark.parametrize(("name", "patterns"), [
    ("requests", []),
    ("requests", ["examplecorp-*"]),
    ("examplecorpse", ["examplecorp-*"]),
    ("examplecorp", ["examplecorp-*"]),
    ("example-corp-auth", ["examplecorp-*"]),
    ("examplecorp-public-sdk", ["examplecorp-*", "!examplecorp-public-sdk"]),
    ("examplecorp-auth", ["*", "a*"]),  # refused as too broad rather than flagging all of PyPI
])
def test_no_finding_for_established_packages_outside_the_private_namespace(monkeypatch, name, patterns):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", patterns)
    assert analyze(make_ctx(name, "2.19.0", releases=ESTABLISHED, age_days=300.0)) == []


def test_established_projects_with_high_major_versions_are_not_flagged():
    setuptools_like = [release(f"{60 + i}.0.0", -700 + i * 30) for i in range(20)]
    assert analyze(make_ctx("setuptools", "79.0.0", releases=setuptools_like, age_days=10.0)) == []
    chromedriver_like = [release("128.0.6613.84", -400), release("129.0.6668.58", -300), release("140.0.7339.80", -3)]
    assert analyze(make_ctx("chromedriver-mirror", "140.0.7339.80", releases=chromedriver_like, age_days=3.0)) == []


@pytest.mark.parametrize("version", [
    "2026.9.1", "2025.12", "2027.1.0", "2016.1", "20260915", "202609", "2026091512", "26.9.0", "49.0.0", "0.0.1",
    "1.0.0rc1", "3.1.4.post2",
])
def test_new_projects_with_plausible_or_calendar_versions_are_not_flagged(version):
    ctx = make_ctx("fresh-tool", version, age_days=1.0)
    assert version_squatting_evidence(ctx) is None
    assert analyze(ctx) == []


@pytest.mark.parametrize(("version", "reason"), [
    ("50.0.0", "high_major"),
    ("99.0.0", "high_major"),
    ("9000.0.0", "high_major"),
    ("9000", "high_major"),
    ("100.0.0.dev1", "high_major"),
    ("2028.1.0", "high_major"),  # beyond the calendar-version window for a 2026 upload
    ("2015.1", "high_major"),
    ("20261301", "high_major"),  # not a date: month 13
    ("1!0.0.1", "epoch"),
    ("99!1.0", "epoch"),
])
def test_version_squatting_pattern_is_a_medium_low_confidence_signal(version, reason):
    [finding] = analyze(make_ctx("fresh-tool", version, age_days=1.0))
    assert (finding.code, finding.severity, finding.weight, finding.confidence) == (DC, Severity.medium, 4.0, 0.5)
    assert finding.capability is None and finding.location is None and finding.provenance == Provenance.REGISTRY
    assert finding.confidence < 0.7  # below the policy engine's default min_confidence: cannot hard-block alone
    assert (finding.evidence["reason"], finding.evidence["pattern"], finding.evidence["context"]) == \
        (reason, "version-squatting", "resolution-time")


def test_version_heuristic_major_boundary():
    assert analyze(make_ctx("fresh-tool", "49.9.9", age_days=1.0)) == []
    assert analyze(make_ctx("fresh-tool", "50.0.0", age_days=1.0))


def test_version_heuristic_age_boundary_includes_the_gap_to_the_first_release():
    assert analyze(make_ctx("fresh-tool", "9000.0.0", age_days=29.99))
    assert analyze(make_ctx("fresh-tool", "9000.0.0", age_days=30.0)) == []
    history = [release("0.0.1", 0), release("9000.0.0", 25)]
    [finding] = analyze(make_ctx("fresh-tool", "9000.0.0", releases=history, age_days=4.99))
    assert finding.evidence["project_age_days"] == 29.99 and finding.evidence["release_count"] == 2
    assert analyze(make_ctx("fresh-tool", "9000.0.0", releases=history, age_days=5.0)) == []


def test_version_heuristic_release_count_boundary():
    three = [release("0.1.0", 0), release("0.2.0", 1), release("9000.0.0", 2)]
    assert analyze(make_ctx("fresh-tool", "9000.0.0", releases=three, age_days=1.0))
    four = [release("0.0.1", 0), release("0.1.0", 1), release("0.2.0", 2), release("9000.0.0", 3)]
    assert analyze(make_ctx("fresh-tool", "9000.0.0", releases=four, age_days=1.0)) == []


@pytest.mark.parametrize("kwargs", [
    {"age_days": None},
    {"age_days": float("nan")},
    {"age_days": True},
    {"age_days": -1.0},
    {"age_days": "1"},
    {"releases": []},
    {"releases": [ReleaseInfo(version="9000.0.0", upload_time=None)]},
    {"releases": [ReleaseInfo(version="9000.0.0", upload_time="not-a-date")]},
    {"releases": [release("0.0.1", 0)]},  # the scanned version is not in the history
])
def test_unknown_age_or_history_is_never_treated_as_new(kwargs):
    assert analyze(make_ctx("fresh-tool", "9000.0.0", **kwargs)) == []


def test_non_pep440_versions_hostile_strings_and_other_ecosystems_are_ignored(monkeypatch):
    assert analyze(make_ctx("fresh-tool", "9000-final-hax", age_days=1.0)) == []
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    assert analyze(make_ctx("examplecorp-auth‮\x1b[2J", "9000.0.0\x1b", age_days=1.0)) == []
    assert analyze(make_ctx("examplecorp-auth", "9000.0.0", age_days=1.0, ecosystem="npm")) == []


def test_calver_helper():
    uploaded = datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert plausible_calver((2026, 9), uploaded) and plausible_calver((20260901,), uploaded)
    assert not plausible_calver((9000, 0), uploaded) and not plausible_calver((), uploaded)


def test_namespace_match_and_version_squat_are_reported_once(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    [finding] = analyze(make_ctx("examplecorp-auth", "9000.0.0", age_days=1.0))
    assert finding.severity == Severity.critical and finding.weight == 12.0
    assert finding.evidence["version_squatting"]["reason"] == "high_major"


def test_package_analyzer_makes_no_http_requests_even_when_lookups_are_allowed(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    monkeypatch.setattr(settings, "DEPCONF_ALLOW_PUBLIC_LOOKUP", True)
    # respx clears ``router.calls`` when the context exits, so call counts are asserted inside it.
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        findings = analyze(make_ctx("examplecorp-auth", "9000.0.0", age_days=1.0))
        findings += analyze(make_ctx("fresh-tool", "9000.0.0", age_days=1.0))
        assert router.calls.call_count == 0
    assert [f.severity for f in findings] == [Severity.critical, Severity.medium]


def test_analyzer_output_is_deterministic(monkeypatch):
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    first = [f.finding_id for f in analyze(make_ctx("examplecorp-auth", "9000.0.0", age_days=1.0))]
    second = [f.finding_id for f in analyze(make_ctx("examplecorp-auth", "9000.0.0", age_days=1.0))]
    assert first == second and len(first) == 1


# ====================================================================================== project findings
PROJECT_SNAPSHOT = PublicIndexSnapshot.from_names(
    ["requests", "flask", "examplecorp-auth", "examplecorp-billing-sdk", "examplecorp-ledger"],
    SnapshotHeader(source="fixture", generated_at="2026-09-01T00:00:00Z"),
)


def requirements_inventory():
    content = (DATA / "requirements-private.txt.fixture").read_bytes()
    return parse_project({"requirements.txt": content}, "demo"), content


def keyed(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    out = {(f.code, f.evidence.get("normalized_name")): f for f in findings}
    assert len(out) == len(findings)
    return out


def test_project_findings_for_private_index_with_pypi_extra_index(monkeypatch):
    inventory, content = requirements_inventory()
    hygiene = hygiene_findings(inventory)
    findings = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                          private_index_urls=[PRIVATE_INDEX], related_findings=hygiene)
    by_key = keyed(findings)
    assert sorted(by_key) == [
        (DC, "examplecorp-auth"), (DC, "examplecorp-billing-sdk"), (DC, "examplecorp-newtool"),
        (NC, "examplecorp-auth"), (NC, "examplecorp-billing-sdk"), (NC, "examplecorp-ledger"),
    ]
    extra_line = line_of(content, "--extra-index-url")
    [ambiguity] = [f for f in hygiene if f.code == Code.INDEX_SOURCE_AMBIGUITY]

    auth = by_key[(DC, "examplecorp-auth")]
    assert (auth.severity, auth.weight, auth.confidence, auth.capability) == \
        (Severity.critical, 12.0, 0.9, Capability.DEPENDENCY_CONFUSION)
    assert auth.location == Location(file="requirements.txt", line=line_of(content, "examplecorp-auth>=1.2"))
    assert auth.evidence["exposure"] == [{
        "reason": "extra-index-url", "url": "https://pypi.org/simple", "file": "requirements.txt", "line": extra_line,
        "index_classification": "public", "see_also": "INDEX_SOURCE_AMBIGUITY",
    }]
    assert (auth.evidence["public_presence"], auth.evidence["presence_source"]) == ("present", "snapshot")
    assert auth.related == (ambiguity.finding_id,)  # referenced, not duplicated
    assert Code.INDEX_SOURCE_AMBIGUITY not in {f.code for f in findings}

    billing = by_key[(DC, "examplecorp-billing-sdk")]
    assert (billing.severity, billing.confidence) == (Severity.critical, 0.85)  # exact pin without hashes
    assert billing.location.line == line_of(content, "examplecorp_billing_sdk==4.0.1")

    latent = by_key[(DC, "examplecorp-newtool")]
    assert (latent.severity, latent.weight, latent.confidence, latent.capability) == (Severity.high, 6.0, 0.6, None)
    assert latent.evidence["public_presence"] == "absent"
    assert latent.location.line == line_of(content, "examplecorp-newtool")

    ledger = by_key[(NC, "examplecorp-ledger")]
    assert (ledger.severity, ledger.weight, ledger.confidence) == (Severity.high, 6.0, 0.8)
    assert ledger.evidence["mitigations"] == ["hash-pinned"]  # substitution would fail hash checking
    assert ledger.provenance == "intel:public-index-snapshot"
    assert ledger.evidence["snapshot"] == {"source": "fixture", "generated_at": "2026-09-01T00:00:00Z"}
    assert ledger.location.line == line_of(content, "examplecorp-ledger==2.1.0")

    for finding in findings:
        assert finding.analyzer == "dependency_confusion" and finding.category == "dependency_confusion"
        assert finding.evidence["context"] == "resolution-time"
        assert Finding.from_dict(json.loads(json.dumps(finding.to_dict()))).finding_id == finding.finding_id
    dumped = json.dumps([f.to_dict() for f in findings])
    assert "fixture-token-456" not in dumped and "ci-bot" not in dumped
    assert "examplecorp-cli" not in dumped and '"requests"' not in dumped  # direct URL / public names: no finding


def test_single_private_index_yields_only_namespace_collision():
    content = "--index-url https://pkgs.examplecorp.example/simple\nexamplecorp-auth>=1.2\nrequests==2.32.3\n"
    inventory = parse_project({"requirements.txt": content}, "p")
    for private in ([PRIVATE_INDEX], []):  # an unrecognised single index is not treated as exposure either
        findings = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                              private_index_urls=private)
        assert [(f.code, f.location.line) for f in findings] == [(NC, 2)]


def test_extra_index_urls_that_are_all_private_are_not_exposure():
    content = ("--index-url https://pkgs.examplecorp.example/simple\n"
               "--extra-index-url https://pkgs.examplecorp.example/simple/team\nexamplecorp-auth\n")
    findings = project_confusion_findings(parse_project({"requirements.txt": content}, "p"),
                                          patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                          private_index_urls=[PRIVATE_INDEX])
    assert [f.code for f in findings] == [NC]


def test_private_extra_index_keeps_pip_default_pypi_as_primary():
    content = "--extra-index-url https://pkgs.examplecorp.example/simple\nexamplecorp-auth\n"
    findings = project_confusion_findings(parse_project({"requirements.txt": content}, "p"),
                                          patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                          private_index_urls=[PRIVATE_INDEX])
    dc = keyed(findings)[(DC, "examplecorp-auth")]
    assert dc.evidence["exposure"][0]["primary_index"] == "https://pypi.org/simple (pip default)"
    assert dc.evidence["exposure"][0]["index_classification"] == "private"


def test_no_index_switches_off_a_files_index_reasons():
    content = "--no-index\n--find-links ./wheels\n--extra-index-url https://pypi.org/simple\nexamplecorp-auth\n"
    findings = project_confusion_findings(parse_project({"requirements.txt": content}, "p"),
                                          patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                          private_index_urls=[PRIVATE_INDEX])
    assert [f.code for f in findings] == [NC]


def test_benign_public_only_project_produces_no_findings():
    content = ("--index-url https://pypi.org/simple\nrequests==2.32.3\nnumpy>=2.0\ndjango==5.1.1\n"
               "example-corp-utils==1.0\nflask[async]>=3.0 ; python_version >= '3.9'\n")
    inventory = parse_project({"requirements.txt": content}, "p")
    snapshot = PublicIndexSnapshot.from_names(["requests", "numpy", "django", "example-corp-utils", "flask"])
    assert project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=snapshot,
                                      private_index_urls=[PRIVATE_INDEX]) == []


def test_inventory_without_index_sources_falls_back_to_flat_index_url_lists():
    inventory, content = requirements_inventory()
    inventory.index_sources = []  # e.g. an inventory restored from stored data
    assert inventory.index_urls and inventory.extra_index_urls == [SIMPLE]
    unlocated = Finding(Code.INDEX_SOURCE_AMBIGUITY, Severity.medium, 3.0, "extra index", {"extra_index_url": SIMPLE},
                        confidence=0.8)
    kwargs = {"patterns": ["examplecorp-*"], "snapshot": PROJECT_SNAPSHOT, "private_index_urls": [PRIVATE_INDEX]}
    findings = keyed(project_confusion_findings(inventory, related_findings=[unlocated], **kwargs))
    assert sorted(findings) == [
        (DC, "examplecorp-auth"), (DC, "examplecorp-billing-sdk"), (DC, "examplecorp-newtool"),
        (NC, "examplecorp-auth"), (NC, "examplecorp-billing-sdk"), (NC, "examplecorp-ledger"),
    ]
    auth = findings[(DC, "examplecorp-auth")]
    assert (auth.severity, auth.confidence) == (Severity.critical, 0.9)
    [exposure] = auth.evidence["exposure"]
    assert (exposure["reason"], exposure["url"], exposure["index_classification"]) == \
        ("extra-index-url", SIMPLE, "public")
    assert exposure.get("file") is None and exposure.get("line") is None  # no manifest position is invented
    assert auth.location == Location(file="requirements.txt", line=line_of(content, "examplecorp-auth>=1.2"))
    assert auth.related == ()  # an unlocated hygiene finding cannot be tied to this exposure

    inventory.extra_index_urls = []  # only the private --index-url remains: no exposure
    assert [f.code for f in project_confusion_findings(inventory, **kwargs)] == [NC, NC, NC]


POETRY_PYPROJECT = """[tool.poetry]
name = "svc"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
examplecorp-auth = { version = "^1.2", source = "corp" }
examplecorp-billing-sdk = "^4.0"

[[tool.poetry.source]]
name = "corp"
url = "https://pkgs.examplecorp.example/simple"
priority = "supplemental"
"""

POETRY_LOCK = f"""[[package]]
name = "examplecorp-auth"
version = "1.2.0"
description = ""
optional = false
python-versions = "*"
files = [{{file = "examplecorp_auth-1.2.0-py3-none-any.whl", hash = "sha256:{HASH}"}}]

[package.source]
type = "legacy"
url = "https://pkgs.examplecorp.example/simple"
reference = "corp"

[[package]]
name = "examplecorp-billing-sdk"
version = "4.0.1"
description = ""
optional = false
python-versions = "*"
files = [{{file = "examplecorp_billing_sdk-4.0.1-py3-none-any.whl", hash = "sha256:{HASH}"}}]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "fixture"
"""


def test_poetry_source_routing_mitigates_and_sourceless_lock_entry_is_exposed_despite_hashes():
    inventory = parse_project({"pyproject.toml": POETRY_PYPROJECT, "poetry.lock": POETRY_LOCK}, "svc")
    findings = keyed(project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                                private_index_urls=[PRIVATE_INDEX]))
    assert sorted(findings) == [(DC, "examplecorp-billing-sdk"), (NC, "examplecorp-auth"),
                                (NC, "examplecorp-billing-sdk")]
    routed = findings[(NC, "examplecorp-auth")]
    assert routed.evidence["mitigations"] == ["source-pinned", "hash-pinned"]
    billing = findings[(DC, "examplecorp-billing-sdk")]
    assert (billing.severity, billing.confidence) == (Severity.critical, 0.85)
    assert [r["reason"] for r in billing.evidence["exposure"]] == ["locked-without-source"]
    expected_line = line_of(POETRY_LOCK, 'name = "examplecorp-billing-sdk"')
    assert billing.location == Location(file="poetry.lock", line=expected_line)


def test_pipfile_lock_entry_from_the_public_index_is_critical_even_when_hashed():
    lock = json.dumps({
        "_meta": {"hash": {"sha256": "fixture"}, "pipfile-spec": 6, "requires": {},
                  "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True},
                              {"name": "corp", "url": PRIVATE_INDEX, "verify_ssl": True}]},
        "default": {
            "examplecorp-auth": {"hashes": [f"sha256:{HASH}"], "index": "pypi", "version": "==1.2.0"},
            "examplecorp-ledger": {"hashes": [f"sha256:{HASH}"], "index": "corp", "version": "==2.1.0"},
        },
        "develop": {},
    }, indent=4)
    findings = keyed(project_confusion_findings(parse_project({"Pipfile.lock": lock}, "p"), patterns=["examplecorp-*"],
                                                snapshot=PROJECT_SNAPSHOT, private_index_urls=[PRIVATE_INDEX]))
    assert sorted(findings) == [(DC, "examplecorp-auth"), (NC, "examplecorp-auth"), (NC, "examplecorp-ledger")]
    auth = findings[(DC, "examplecorp-auth")]
    assert (auth.severity, auth.confidence) == (Severity.critical, 0.9)
    assert [r["reason"] for r in auth.evidence["exposure"]] == ["declared-public-index", "public-index-configured"]
    assert auth.location == Location(file="Pipfile.lock", line=line_of(lock, '"examplecorp-auth"'))
    assert findings[(NC, "examplecorp-ledger")].evidence["mitigations"] == ["source-pinned", "hash-pinned"]


def test_no_public_request_is_made_for_private_names_by_default():
    inventory, _ = requirements_inventory()
    injected = PublicIndexLookup(http=test_http_client())
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        without_snapshot = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=None,
                                                      private_index_urls=[PRIVATE_INDEX])
        configured_default = project_confusion_findings(inventory, patterns=["examplecorp-*"],
                                                        private_index_urls=[PRIVATE_INDEX])
        with_lookup = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=None,
                                                 private_index_urls=[PRIVATE_INDEX], lookup=injected)
        assert router.calls.call_count == 0  # inside the context: respx clears calls on exit
    assert injected.lookups == 0
    for findings in (without_snapshot, configured_default, with_lookup):
        by_key = keyed(findings)
        assert NC not in {code for code, _ in by_key}  # presence unknown is never reported as a collision
        assert sorted(name for code, name in by_key if code == DC) == \
            ["examplecorp-auth", "examplecorp-billing-sdk", "examplecorp-newtool"]
        assert all(by_key[(DC, n)].confidence == 0.6 for n in ("examplecorp-auth", "examplecorp-newtool"))
        tool = by_key[(Code.TOOL_UNAVAILABLE, None)]
        assert (tool.severity, tool.weight) == (Severity.info, 0.0)
        assert tool.evidence["public_lookup"] == "disabled" and tool.evidence["unknown_components"] == 5
    assert keyed(configured_default)[(Code.TOOL_UNAVAILABLE, None)].evidence["detail"] == \
        "PUBLIC_INDEX_SNAPSHOT_PATH is not set"


def test_public_lookup_happens_only_when_enabled_and_only_for_private_names(monkeypatch):
    monkeypatch.setattr(settings, "DEPCONF_ALLOW_PUBLIC_LOOKUP", True)
    inventory, _ = requirements_inventory()
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        router.get(f"{SIMPLE}/examplecorp-auth/").mock(return_value=httpx.Response(
            200, content=_json({"meta": {"api-version": "1.1"}, "name": "examplecorp-auth", "files": []}),
            headers={"Content-Type": SIMPLE_JSON_ACCEPT}))
        router.get(url__regex=r"^https://pypi\.org/simple/examplecorp-[a-z-]+/$").mock(return_value=httpx.Response(404))
        findings = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=None,
                                              private_index_urls=[PRIVATE_INDEX],
                                              lookup=PublicIndexLookup(http=test_http_client()))
        requested = sorted(call.request.url.path for call in router.calls)
    # Only names matching the private patterns are looked up; requests / flask never are.
    assert requested == ["/simple/examplecorp-auth/", "/simple/examplecorp-billing-sdk/", "/simple/examplecorp-cli/",
                         "/simple/examplecorp-ledger/", "/simple/examplecorp-newtool/"]
    by_key = keyed(findings)
    collision = by_key[(NC, "examplecorp-auth")]
    assert collision.provenance == Provenance.REGISTRY and collision.evidence["presence_source"] == "public-lookup"
    assert by_key[(DC, "examplecorp-auth")].confidence == 0.9
    assert (Code.TOOL_UNAVAILABLE, None) not in by_key


def test_public_lookup_is_bounded_and_status_mapping_is_conservative(monkeypatch):
    monkeypatch.setattr(settings, "DEPCONF_ALLOW_PUBLIC_LOOKUP", True)
    inventory, _ = requirements_inventory()
    lookup = PublicIndexLookup(http=test_http_client(), max_lookups=2)
    with respx.mock() as router:
        router.get(url__regex=r"^https://pypi\.org/simple/.+/$").mock(return_value=httpx.Response(404))
        findings = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=None,
                                              private_index_urls=[PRIVATE_INDEX], lookup=lookup)
        assert router.calls.call_count == 2
    assert lookup.lookups == 2 and lookup.limit_reached
    tool = keyed(findings)[(Code.TOOL_UNAVAILABLE, None)]
    assert "public lookup limit (2) reached" in tool.evidence["detail"] and tool.evidence["unknown_components"] == 3

    monkeypatch.setattr(depconf_project, "LOOKUP_MAX_BYTES", 16)
    probe = PublicIndexLookup(http=test_http_client())
    with respx.mock() as router:
        router.get(f"{SIMPLE}/big-project/").mock(return_value=httpx.Response(200, content=b"x" * 64))
        router.get(f"{SIMPLE}/flaky/").mock(return_value=httpx.Response(503))
        assert probe.presence("Big_Project") == "present"  # oversized 200 page: the name exists
        assert probe.presence("flaky") == "unknown"
        assert probe.presence("flaky") == "unknown" and router.calls.call_count == 2  # memoised
        assert probe.presence("../etc/passwd") == "unknown" and router.calls.call_count == 2


def test_project_findings_use_settings_and_the_configured_snapshot_by_default(monkeypatch):
    inventory, _ = requirements_inventory()
    assert project_confusion_findings(inventory, snapshot=PROJECT_SNAPSHOT) == []  # no patterns configured
    monkeypatch.setattr(settings, "PRIVATE_PACKAGE_PATTERNS", ["examplecorp-*"])
    monkeypatch.setattr(settings, "PRIVATE_INDEX_URLS", [PRIVATE_INDEX])
    monkeypatch.setattr(settings, "PUBLIC_INDEX_SNAPSHOT_PATH", str(DATA / "public_index_snapshot.txt.gz"))
    by_key = keyed(project_confusion_findings(inventory))
    assert sorted(name for code, name in by_key if code == NC) == ["examplecorp-auth", "examplecorp-billing-sdk"]
    assert by_key[(NC, "examplecorp-auth")].evidence["snapshot"]["generated_at"] == "2026-09-01T00:00:00Z"
    # examplecorp-ledger is hash-pinned and absent from this snapshot: nothing to report for it.
    assert not any(name == "examplecorp-ledger" for _, name in by_key)


def test_project_findings_are_deterministic_regardless_of_input_order():
    inventory, _ = requirements_inventory()
    first = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                       private_index_urls=[PRIVATE_INDEX])
    inventory.components.reverse()
    inventory.dependencies.reverse()
    inventory.index_sources.reverse()
    second = project_confusion_findings(inventory, patterns=["examplecorp-*"], snapshot=PROJECT_SNAPSHOT,
                                        private_index_urls=[PRIVATE_INDEX])
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert len({f.finding_id for f in first}) == len(first)
