"""Observability tests: Prometheus metrics, the /metrics endpoint, tracing, and cache degradation.

Label-cardinality tests drive real requests whose paths contain package-name-like values and
assert those values never appear in the exposition output.
"""

from __future__ import annotations

import re
import types
import uuid
from contextlib import contextmanager

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from app.api.middleware import RequestContextMiddleware
from app.core import cache as cache_module
from app.core import metrics, tracing
from app.core.cache import CacheClient
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.main import create_app, metrics_token_valid
from tests.conftest import auth


def value(name: str, **labels: str) -> float:
    return metrics.REGISTRY.get_sample_value(name, labels) or 0.0


class Explosive:
    def __str__(self) -> str:
        raise RuntimeError("boom")


# --------------------------------------------------------------------------- helpers
def test_observe_scan_counts_blocks_and_bounds_labels() -> None:
    blocked = value("blocked_packages_total")
    scans = value("scans_total", decision="block", ecosystem="pypi")
    durations = value("scan_duration_seconds_count")
    metrics.observe_scan("BLOCK", "PyPI", 1.5)
    assert value("scans_total", decision="block", ecosystem="pypi") == scans + 1
    assert value("blocked_packages_total") == blocked + 1
    assert value("scan_duration_seconds_count") == durations + 1

    other = value("scans_total", decision="other", ecosystem="other")
    metrics.observe_scan("<script>", "evil-package-name", None)
    assert value("scans_total", decision="other", ecosystem="other") == other + 1


def test_observe_analyzer_and_invalid_label_values() -> None:
    before = value("analyzer_runs_total", analyzer="static_code", status="ok")
    metrics.observe_analyzer("static_code", "ok", 0.2)
    assert value("analyzer_runs_total", analyzer="static_code", status="ok") == before + 1
    count = value("analyzer_duration_seconds_count", analyzer="static_code")
    metrics.observe_analyzer("static_code", "timeout", float("nan"))  # NaN duration dropped
    assert value("analyzer_duration_seconds_count", analyzer="static_code") == count
    weird = value("analyzer_runs_total", analyzer="other", status="other")
    metrics.observe_analyzer("bad name\nwith newline", "exploded", 1.0)
    assert value("analyzer_runs_total", analyzer="other", status="other") == weird + 1


def test_bounded_label_caps_distinct_values() -> None:
    label = metrics.BoundedLabel(3)
    assert [label(v) for v in ("a", "b", "c", "d", "a", "e")] == ["a", "b", "c", "other", "a", "other"]
    assert label("has space") == "other" and label("x" * 100) == "other"


def test_other_helpers_record_expected_series() -> None:
    cases = [
        (lambda: metrics.inc_cache("verdict", "hit"), "cache_requests_total", {"cache": "verdict", "result": "hit"}),
        (lambda: metrics.inc_intel("osv", "ok"), "intel_requests_total", {"source": "osv", "status": "ok"}),
        (lambda: metrics.inc_policy("warn", None), "policy_decisions_total", {"decision": "warn",
                                                                             "environment": "default"}),
        (lambda: metrics.inc_policy("allow", "production"), "policy_decisions_total", {"decision": "allow",
                                                                                      "environment": "production"}),
        (lambda: metrics.inc_event("PACKAGE_BLOCKED", "critical"), "security_events_total",
         {"type": "PACKAGE_BLOCKED", "severity": "critical"}),
    ]
    for call, name, labels in cases:
        before = value(name, **labels)
        call()
        assert value(name, **labels) == before + 1, name


def test_gauges_reject_invalid_values() -> None:
    metrics.set_queue_depth("scan-jobs", 5)
    assert value("queue_depth", queue="scan-jobs") == 5
    for bad in (-1, float("nan"), float("inf"), "many"):
        metrics.set_queue_depth("scan-jobs", bad)  # type: ignore[arg-type]
    assert value("queue_depth", queue="scan-jobs") == 5
    metrics.set_monitored_packages(12)
    assert value("monitored_packages") == 12
    metrics.set_tool_available("semgrep", False)
    assert value("tool_available", tool="semgrep") == 0
    metrics.set_tool_available("semgrep", True)
    assert value("tool_available", tool="semgrep") == 1


def test_time_ml_records_even_when_the_block_raises() -> None:
    before = value("ml_inference_seconds_count")
    with pytest.raises(KeyError):
        with metrics.time_ml():
            raise KeyError("model failure")
    with metrics.time_ml():
        pass
    assert value("ml_inference_seconds_count") == before + 2


def test_helpers_never_raise() -> None:
    calls = [
        lambda: metrics.observe_scan(Explosive(), "pypi", 1.0),
        lambda: metrics.observe_analyzer(Explosive(), "ok", 1.0),
        lambda: metrics.observe_http(Explosive(), "/x", 200, 0.1),
        lambda: metrics.inc_cache(Explosive(), "hit"),
        lambda: metrics.inc_intel(None, None),
        lambda: metrics.inc_policy(Explosive(), None),
        lambda: metrics.inc_event(object(), 3),
        lambda: metrics.set_tool_available(Explosive(), True),
        lambda: metrics.set_queue_depth(Explosive(), 1),
    ]
    for call in calls:
        assert call() is None


def test_render_latest_exposition() -> None:
    body, content_type = metrics.render_latest()
    assert content_type.startswith("text/plain")
    assert b"http_requests_total" in body
    # No *_created series (label values such as type="exception_created" are fine).
    assert not re.search(rb"^[a-z_]+_created[{ ]", body, re.MULTILINE)


# --------------------------------------------------------------------------- HTTP labels
def test_route_label_is_the_prefixed_template_for_included_routers() -> None:
    router = APIRouter(prefix="/things")

    @router.get("/{name}")
    def get_thing(name: str) -> dict:
        return {"name": name}

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(router, prefix="/api/v1")
    app.add_middleware(RequestContextMiddleware)
    hostile = "evil-pkg-" + uuid.uuid4().hex
    with TestClient(app) as tc:
        assert tc.get(f"/api/v1/things/{hostile}").status_code == 200
        assert tc.get(f"/nowhere/{hostile}").status_code == 404
    routes = {labels["route"] for labels in metrics.label_values("http_requests_total")}
    assert "/api/v1/things/{name}" in routes and metrics.UNMATCHED_ROUTE in routes
    assert not any(hostile in route for route in routes)


def test_real_app_metrics_never_contain_raw_paths(client: TestClient, admin_token: str) -> None:
    hostile = "typosquat-reqeusts-" + uuid.uuid4().hex
    scan_id = uuid.uuid4()
    client.get(f"/api/v1/no-such-endpoint/{hostile}")
    client.get(f"/api/v1/scans/{scan_id}", headers=auth(admin_token))
    client.get(f"/api/v1/scans/{hostile}", headers=auth(admin_token))
    client.post("/api/v1/auth/login", json={"email": f"{hostile}@example.com", "password": hostile})
    body = client.get("/metrics").text
    assert hostile not in body and str(scan_id) not in body
    assert 'route="/api/v1/scans/{scan_id}"' in body
    assert f'route="{metrics.UNMATCHED_ROUTE}"' in body


# --------------------------------------------------------------------------- /metrics endpoint
def test_metrics_endpoint_open_when_no_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "METRICS_TOKEN", None)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"


def test_metrics_endpoint_requires_valid_bearer_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = "metrics-" + uuid.uuid4().hex
    monkeypatch.setattr(settings, "METRICS_TOKEN", token)
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {token}"},
                    {"Authorization": token}, {"Authorization": f"Bearer {token}x"}):
        response = client.get("/metrics", headers=headers)
        assert response.status_code == 401, headers
        assert response.json()["error"]["code"] == "unauthorized"
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert token not in response.text
    ok = client.get("/metrics", headers={"Authorization": f"bearer  {token} "})
    assert ok.status_code == 200 and "http_requests_total" in ok.text


def test_metrics_token_uses_constant_time_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.main as main_module

    calls = []
    real = main_module.hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(main_module.hmac, "compare_digest", spy)
    assert metrics_token_valid("Bearer s3cret", "s3cret")
    assert not metrics_token_valid("Bearer nope", "s3cret")
    assert len(calls) == 2
    assert not metrics_token_valid(None, "s3cret") and not metrics_token_valid("Bearer x", "")
    assert metrics_token_valid("Bearer pässwörd", "pässwörd")


def test_metrics_endpoint_absent_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "METRICS_ENABLED", False)
    assert TestClient(create_app()).get("/metrics").status_code == 404


# --------------------------------------------------------------------------- tracing
class FakeSpan:
    def __init__(self, name: str, attributes: dict | None) -> None:
        self.name = name
        self.attributes = dict(attributes or {})
        self.status = None
        self.ended = False

    def set_attribute(self, key, val) -> None:
        self.attributes[key] = val

    def set_status(self, status) -> None:
        self.status = status


class FakeTracer:
    def __init__(self, fail: bool = False) -> None:
        self.spans: list[FakeSpan] = []
        self.options: dict = {}
        self.fail = fail

    @contextmanager
    def start_as_current_span(self, name, attributes=None, **options):
        if self.fail:
            raise RuntimeError("exporter broken")
        span = FakeSpan(name, attributes)
        self.options = options
        self.spans.append(span)
        try:
            yield span
        finally:
            span.ended = True


def fake_trace_api(tracer: FakeTracer) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        get_tracer=lambda name: tracer,
        Status=lambda code, description: ("status", code, description),
        StatusCode=types.SimpleNamespace(ERROR="ERROR"),
    )


def test_span_is_a_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "OTEL_ENABLED", False)
    monkeypatch.setattr(tracing, "_load_trace_api", lambda: pytest.fail("must not import opentelemetry"))
    with tracing.span("scan", package="x") as handle:
        handle.set_attribute("package", "y")
    assert handle.recording is False
    assert tracing.is_enabled() is False


def test_span_is_a_noop_when_opentelemetry_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(tracing, "_load_trace_api", lambda: None)
    with tracing.span("scan") as handle:
        pass
    assert handle.recording is False and tracing.is_enabled() is False


def test_span_attributes_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = FakeTracer()
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(tracing, "_load_trace_api", lambda: fake_trace_api(tracer))
    token = "ghp_" + "a1B2" * 9
    attrs = {
        "package.name": "requests", "version": "2.0", "count": 5, "ratio": 0.5, "flags": [1, 2],
        "password": "hunter2", "file_content": "import os", "evidence_text": "x", "data": b"\x00bytes",
        "meta": {"a": 1}, "token_count": 3, "mixed": [1, "a"], "note": f"saw {token}", "long": "z" * 5000,
        "Bad Key": 1, "big": 2**70, "nan": float("nan"),
    }
    with tracing.span("scan\n‮package", **attrs) as handle:
        handle.set_attribute("source_code", "print(1)")
        handle.set_attributes(stage="fetch", payload="secret")
    (span,) = tracer.spans
    assert "\n" not in span.name and "‮" not in span.name
    assert set(span.attributes) == {"package.name", "version", "count", "ratio", "flags", "note", "long", "stage"}
    assert token not in span.attributes["note"]
    assert len(span.attributes["long"]) <= tracing.MAX_STRING_LENGTH
    assert tracer.options == {"record_exception": False, "set_status_on_exception": False}
    assert span.ended


def test_span_marks_errors_with_type_only_and_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    tracer = FakeTracer()
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(tracing, "_load_trace_api", lambda: fake_trace_api(tracer))
    with pytest.raises(ValueError, match="package payload"):
        with tracing.span("analyze"):
            raise ValueError("package payload: rm -rf /")
    (span,) = tracer.spans
    assert span.status == ("status", "ERROR", "ValueError")
    assert span.attributes == {"error.type": "ValueError"}
    assert span.ended


def test_broken_tracer_never_breaks_the_traced_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "OTEL_ENABLED", True)
    monkeypatch.setattr(tracing, "_load_trace_api", lambda: fake_trace_api(FakeTracer(fail=True)))
    ran = []
    with tracing.span("x") as handle:
        ran.append(True)
    assert ran and handle.recording is False


# --------------------------------------------------------------------------- cache
class FakeClock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class BrokenRedis:
    """Every Redis call fails, with a credential in the error message."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise ConnectionError("cannot reach redis://:hunter2secretpw@cache:6379/0")

        return fail


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis, self.ops = redis, []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.ops.append((name, args, kwargs))
            return self

        return record

    def execute(self):
        return [getattr(self.redis, name)(*args, **kwargs) for name, args, kwargs in self.ops]


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttl: dict[str, int] = {}
        self.xadds: list[tuple] = []

    def pipeline(self, transaction: bool = True) -> FakePipeline:
        return FakePipeline(self)

    def set(self, key, val, nx=False, px=None, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = str(val)
        self.ttl[key] = ex if ex is not None else px
        return True

    def incrby(self, key, amount):
        self.store[key] = str(int(self.store.get(key, "0")) + amount)
        return int(self.store[key])

    def get(self, key):
        return self.store.get(key)

    def eval(self, script, numkeys, key, token):
        # Emulates the Redis EVAL *command* (server-side Lua compare-and-delete used to release a
        # lock); nothing is evaluated here and the script text is ignored.
        if self.store.get(key) == token:
            del self.store[key]
            return 1
        return 0

    def xadd(self, stream, fields, maxlen=None, approximate=False):
        self.xadds.append((stream, fields, maxlen, approximate))
        return "1-0"

    def xlen(self, stream):
        return len(self.xadds)


def test_get_json_records_hit_miss_error_without_using_keys_as_labels() -> None:
    c = CacheClient(connect=False)
    key = "verdict:pypi:evil-package-" + uuid.uuid4().hex
    miss, hit, err = (value("cache_requests_total", cache="verdict", result=r) for r in ("miss", "hit", "error"))
    assert c.get_json(key) is None
    c.set_json(key, {"risk": 91}, ttl=60)
    assert c.get_json(key) == {"risk": 91}
    c._fallback.setex(key, 60, "{corrupt")
    assert c.get_json(key) is None
    assert value("cache_requests_total", cache="verdict", result="miss") == miss + 1
    assert value("cache_requests_total", cache="verdict", result="hit") == hit + 1
    assert value("cache_requests_total", cache="verdict", result="error") == err + 1

    other = value("cache_requests_total", cache="other", result="miss")
    c.get_json("requests==2.31.0")
    assert value("cache_requests_total", cache="other", result="miss") == other + 1
    labels = {labels["cache"] for labels in metrics.label_values("cache_requests_total")}
    assert not any("evil-package" in label or "requests" in label for label in labels)


class RecordingLog:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict]] = []

    def __getattr__(self, level: str):
        return lambda event, **kw: self.records.append((level, event, kw))


def test_redis_failures_degrade_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = RecordingLog()
    monkeypatch.setattr(cache_module, "log", recorder)
    c = CacheClient(redis_client=BrokenRedis())
    assert c.backend == "redis" and c.healthy is False
    assert c.get_json("verdict:x") is None
    c.set_json("verdict:x", {"a": 1}, ttl=5)
    assert c.delete("verdict:x") is False
    assert c.incr("counter", ttl=5) is None
    assert c.xadd("warden:events", {"type": "x"}) is False
    assert c.xlen("warden:events") is None
    with c.lock("monitor") as acquired:
        assert acquired is False  # fail closed: never run a singleton job without the lock
    result = c.rate_limit("ratelimit:api:ip:1.2.3.4", limit=1)
    assert result.allowed  # counted in-process instead
    assert not c.rate_limit("ratelimit:api:ip:1.2.3.4", limit=1).allowed
    assert recorder.records and all("hunter2secretpw" not in repr(kw) for _, _, kw in recorder.records)


def test_in_process_delete_incr_and_ttl() -> None:
    clock = FakeClock()
    c = CacheClient(connect=False, clock=clock)
    assert c.incr("jobs", ttl=10) == 1
    assert c.incr("jobs", ttl=10, amount=4) == 5
    clock.now += 11
    assert c.incr("jobs", ttl=10) == 1
    c.set_json("sbom:x", [1], ttl=30)
    assert c.delete("sbom:x") is True and c.delete("sbom:x") is False
    assert c.xadd("warden:events", {"a": "b"}) is False
    assert c.xlen("warden:events") is None


def test_in_process_lock_excludes_and_expires() -> None:
    clock = FakeClock()
    c = CacheClient(connect=False, clock=clock)
    with c.lock("monitor-run", ttl=30) as first:
        assert first is True
        with c.lock("monitor-run", ttl=30) as second:
            assert second is False
    with c.lock("monitor-run", ttl=30) as again:
        assert again is True  # released on exit
        clock.now += 31
        with c.lock("monitor-run", ttl=30) as after_expiry:
            assert after_expiry is True


def test_redis_lock_uses_set_nx_px_and_compare_and_delete() -> None:
    redis = FakeRedis()
    c = CacheClient(redis_client=redis)
    with c.lock("monitor", ttl=2.5) as acquired:
        assert acquired is True
        key = next(iter(redis.store))
        assert key == "warden:lock:monitor" and redis.ttl[key] == 2500
        with c.lock("monitor") as nested:
            assert nested is False
        redis.store[key] = "someone-else"  # our lock expired and another replica took it
    assert redis.store == {"warden:lock:monitor": "someone-else"}  # not deleted by the stale holder


def test_redis_incr_sets_ttl_only_on_creation_and_xadd_trims() -> None:
    redis = FakeRedis()
    c = CacheClient(redis_client=redis)
    assert c.incr("jobs", ttl=60) == 1
    assert c.incr("jobs", ttl=999) == 2
    assert redis.ttl["jobs"] == 60
    assert c.xadd("warden:events", {"type": "PACKAGE_BLOCKED", "score": 97}, maxlen=500) is True  # type: ignore[dict-item]
    assert redis.xadds == [("warden:events", {"type": "PACKAGE_BLOCKED", "score": "97"}, 500, True)]
    assert c.xadd("warden:events", {}) is False
    assert c.xlen("warden:events") == 1


def test_known_series_exist_at_zero_after_app_start():
    create_app()
    text = metrics.render_latest()[0].decode()
    assert 'scans_total{decision="block",ecosystem="pypi"}' in text
    assert 'policy_decisions_total{decision="warn",environment="production"}' in text
    assert 'analyzer_runs_total{analyzer="install_vectors",status="timeout"}' in text
    assert 'security_events_total{severity="critical",type="package_blocked"}' in text


def test_scrape_reports_watched_packages_from_the_database(client: TestClient) -> None:
    from app.db.models import MonitoredPackage
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        before = db.query(MonitoredPackage).filter(MonitoredPackage.enabled.is_(True)).count()
        db.add(MonitoredPackage(id=uuid.uuid4(), ecosystem="pypi", name=f"gauge-{uuid.uuid4().hex[:8]}", enabled=True))
        db.commit()
    body = client.get("/metrics").text
    assert f"monitored_packages {float(before + 1)}" in body
