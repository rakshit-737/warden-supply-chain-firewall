"""API platform hardening: request ids, body limits, rate limiting, security headers, error envelopes.

Middleware is exercised both through the real application (``TestClient``) and by driving the
ASGI callable directly, which gives exact control over the peer address, raw header bytes and
streamed (chunked) request bodies.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import threading
import time
import types
import uuid
import warnings
from datetime import datetime

import jwt
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator, model_validator

from app.analysis.analyzers.base import ToolStatus
from app.api import middleware
from app.api.middleware import (
    API_CSP,
    HSTS_VALUE,
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    client_ip,
    docs_csp,
    ip_rate_key,
    is_rate_limit_exempt,
    jwt_subject,
    parse_ip,
    rate_limit_identity,
    resolve_request_id,
)
from app.api.routers import system as system_router
from app.core import errors, metrics
from app.core.cache import (
    RATE_LIMIT_BREAKER_SECONDS,
    CacheClient,
    RateLimitResult,
    _InProcessBackend,
    retry_after_seconds,
)
from app.core.config import settings
from app.core.errors import format_validation_errors, register_exception_handlers
from app.core.logging import _add_request_id, request_id_ctx
from app.core.permissions import Permission
from app.core.security import create_access_token
from app.main import create_app
from tests.conftest import auth

UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2" * 9


# --------------------------------------------------------------------------- ASGI driver
class Reply:
    def __init__(self, messages: list[dict]) -> None:
        start = next(m for m in messages if m["type"] == "http.response.start")
        self.status = start["status"]
        self.raw_headers = start.get("headers", [])
        self.headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in self.raw_headers}
        self.body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")

    def json(self):
        return json.loads(self.body)


def call_asgi(app, method: str = "GET", path: str = "/", *, headers=(), chunks=None,
              client=("198.51.100.20", 40000), root_path: str = "") -> Reply:
    """Run one request through ``app``; ``chunks`` are sent as separate body messages (streamed)."""
    body = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks or [])]
    body = body or [{"type": "http.request", "body": b"", "more_body": False}]
    raw_headers = [(k.lower().encode("latin-1") if isinstance(k, str) else k,
                    v.encode("latin-1") if isinstance(v, str) else v) for k, v in headers]
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1", "method": method,
        "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": root_path,
        "headers": raw_headers, "client": client, "server": ("testserver", 80),
    }

    async def run() -> list[dict]:
        pending, sent = list(body), []

        async def receive():
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent

    return Reply(asyncio.run(run()))


def envelope(reply) -> dict:
    data = reply.json()
    assert set(data) == {"error"} and set(data["error"]) == {"code", "message", "request_id"}
    return data["error"]


# --------------------------------------------------------------------------- request ids
@pytest.mark.parametrize("candidate", ["abcdefgh", "req-123.ABC_def", "a" * 64, "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"])
def test_well_formed_request_ids_are_accepted(candidate: str) -> None:
    assert resolve_request_id(candidate) == candidate


@pytest.mark.parametrize(
    "candidate",
    [None, "", "short", "a" * 65, "abc def ghi", "abcdefgh\r\nX-Injected: 1", 'abcdefgh"},{"admin":true',
     "abcdefgh<script>", "abcdéfghij", "abcdefgh\x00", "abcdefgh‮", "../../../etc/passwd"],
)
def test_malformed_request_ids_are_replaced(candidate: str | None) -> None:
    rid = resolve_request_id(candidate)
    assert UUID4_RE.match(rid) and rid != candidate


def test_client_request_id_is_honoured_only_from_a_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: any internet client could choose the id bound into logs, envelopes and the audit chain."""
    app = create_app()
    rid = "client-supplied-id-001"
    direct = call_asgi(app, path="/api/v1/does-not-exist", headers=[("X-Request-ID", rid)], client=("10.0.0.2", 1))
    assert direct.status == 404 and UUID4_RE.match(direct.headers["x-request-id"])
    assert envelope(direct)["request_id"] == direct.headers["x-request-id"]
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", ["10.0.0.0/8"])
    proxied = call_asgi(app, path="/api/v1/does-not-exist", headers=[("X-Request-ID", rid)], client=("10.0.0.2", 1))
    assert proxied.headers["x-request-id"] == rid and envelope(proxied)["request_id"] == rid
    spoofed = call_asgi(app, path="/api/v1/does-not-exist", headers=[("X-Request-ID", rid)],
                        client=("198.51.100.20", 1))
    assert spoofed.headers["x-request-id"] != rid


def test_injected_request_id_is_never_reflected(client: TestClient) -> None:
    hostile = 'x"><script>alert(1)</script>'
    response = client.get("/api/v1/does-not-exist", headers={"X-Request-ID": hostile})
    assert UUID4_RE.match(response.headers["x-request-id"])
    assert "<script>" not in response.text
    assert envelope(response)["request_id"] == response.headers["x-request-id"]


def test_raw_crlf_request_id_cannot_inject_response_headers() -> None:
    app = create_app()
    reply = call_asgi(app, path="/api/v1/health/live", headers=[(b"x-request-id", b"abcdefgh\r\nSet-Cookie: pwn=1")])
    assert UUID4_RE.match(reply.headers["x-request-id"])
    assert "set-cookie" not in reply.headers
    assert all(b"\r" not in v and b"\n" not in v for _, v in reply.raw_headers)


def test_request_id_is_bound_for_logging_during_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", ["198.51.100.20/32"])  # call_asgi's default peer
    app = FastAPI()

    @app.get("/rid")
    async def rid(request: Request) -> dict:
        return {
            "ctx": request_id_ctx.get(),
            "log": _add_request_id(None, "info", {}),
            "state": request.state.request_id,
        }

    app.add_middleware(RequestContextMiddleware)
    reply = call_asgi(app, path="/rid", headers=[("X-Request-ID", "bound-id-12345")])
    assert reply.json() == {"ctx": "bound-id-12345", "log": {"request_id": "bound-id-12345"}, "state": "bound-id-12345"}
    assert request_id_ctx.get() is None


# --------------------------------------------------------------------------- body size limit
class Payload(BaseModel):  # module level: FastAPI resolves string annotations from module globals
    items: list[str]


def body_app(limit: int) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.state.completed = []

    @app.post("/upload")
    async def upload(request: Request) -> dict:
        data = await request.body()
        app.state.completed.append(len(data))
        return {"size": len(data)}

    @app.post("/json")
    def json_route(payload: Payload) -> dict:
        app.state.completed.append(len(payload.items))
        return {"count": len(payload.items)}

    @app.post("/stream")
    async def stream(request: Request) -> dict:
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
        app.state.completed.append(total)
        return {"size": total}

    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=limit)
    app.add_middleware(RequestContextMiddleware)
    return app


def test_declared_content_length_over_limit_is_rejected_before_the_app_runs() -> None:
    app = body_app(100)
    reply = call_asgi(app, "POST", "/upload", headers=[("content-length", "101")], chunks=[b"x" * 101])
    assert reply.status == 413
    error = envelope(reply)
    assert error["code"] == "payload_too_large" and "100" in error["message"]
    assert error["request_id"] == reply.headers["x-request-id"]
    assert app.state.completed == []


@pytest.mark.parametrize("path", ["/upload", "/json", "/stream"])
def test_streamed_chunked_body_over_limit_is_rejected(path: str) -> None:
    app = body_app(100)
    chunks = [b'{"items": ["' + b"x" * 30] + [b"y" * 30] * 5 + [b'"]}']
    reply = call_asgi(app, "POST", path, headers=[("content-type", "application/json")], chunks=chunks)
    assert reply.status == 413
    assert envelope(reply)["code"] == "payload_too_large"
    assert app.state.completed == []


def test_content_length_that_understates_the_stream_is_rejected() -> None:
    app = body_app(100)
    reply = call_asgi(app, "POST", "/upload", headers=[("content-length", "10")], chunks=[b"x" * 60, b"x" * 60])
    assert reply.status == 413


def test_bodies_within_the_limit_pass() -> None:
    app = body_app(100)
    assert call_asgi(app, "POST", "/upload", chunks=[b"x" * 45, b"x" * 45]).json() == {"size": 90}
    assert call_asgi(app, "POST", "/stream", headers=[("content-length", "100")], chunks=[b"x" * 100]).json() == {
        "size": 100}


@pytest.mark.parametrize("values", [["abc"], ["-1"], ["1e3"], [" "], ["5", "6"], ["9" * 25]])
def test_invalid_content_length_is_a_400(values: list[str]) -> None:
    reply = call_asgi(body_app(100), "POST", "/upload", headers=[("content-length", v) for v in values],
                      chunks=[b"xxxxx"])
    assert reply.status == 400 and envelope(reply)["code"] == "bad_request"


def test_middleware_answers_413_itself_when_no_handler_catches_it() -> None:
    async def raw_reader(scope, receive, send):
        while (await receive()).get("more_body"):
            pass
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    reply = call_asgi(BodySizeLimitMiddleware(raw_reader, max_body_bytes=10), "POST", "/", chunks=[b"x" * 8] * 3)
    assert reply.status == 413 and envelope(reply)["code"] == "payload_too_large"


def test_real_app_enforces_configured_body_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 256)
    big = json.dumps({"email": "a@example.com", "password": "p" * 1000}).encode()
    response = client.post("/api/v1/auth/login", content=big, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert envelope(response)["code"] == "payload_too_large"
    assert response.headers["x-content-type-options"] == "nosniff"
    streamed = client.post("/api/v1/auth/login", content=iter([b"x" * 200] * 3),
                           headers={"content-type": "application/json"})
    assert streamed.status_code == 413


# --------------------------------------------------------------------------- client identity
def ip(value: str):
    return ipaddress.ip_address(value)


def scope_for(peer: str | None, *forwarded: str) -> dict:
    return {"type": "http", "client": (peer, 1234) if peer else None,
            "headers": [(b"x-forwarded-for", v.encode()) for v in forwarded]}


def test_forwarded_for_ignored_without_trusted_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", [])
    assert client_ip(scope_for("203.0.113.5", "1.2.3.4")) == ip("203.0.113.5")


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        ("10.0.0.2", ["6.6.6.6, 198.51.100.7"], "198.51.100.7"),  # left-most hop is attacker-controlled
        ("10.0.0.2", ["198.51.100.7, 10.0.0.9"], "198.51.100.7"),  # chain of trusted proxies
        ("10.0.0.2", ["6.6.6.6", "198.51.100.7, 10.1.1.1"], "198.51.100.7"),  # repeated headers
        ("198.51.100.66", ["1.2.3.4"], "198.51.100.66"),  # untrusted peer: header ignored
        ("10.0.0.2", ["198.51.100.7, not-an-ip"], "10.0.0.2"),  # malformed hop: stay conservative
        ("10.0.0.2", ["10.0.0.7"], "10.0.0.7"),  # only trusted hops
        ("10.0.0.2", ["198.51.100.7:4711"], "198.51.100.7"),
        ("10.0.0.2", ["[2001:db8::1]:443"], "2001:db8::1"),
        ("::ffff:10.0.0.2", ["198.51.100.8"], "198.51.100.8"),  # IPv4-mapped peer
        ("10.0.0.2", [], "10.0.0.2"),
    ],
)
def test_client_ip_behind_trusted_proxy(peer, forwarded, expected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", ["10.0.0.0/8", "not-a-cidr"])
    assert client_ip(scope_for(peer, *forwarded)) == ip(expected)


def test_client_ip_bounds_forwarded_chain_and_handles_missing_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", ["10.0.0.0/8"])
    long_chain = ", ".join(["6.6.6.6"] * 5000 + ["198.51.100.9"])
    assert client_ip(scope_for("10.0.0.2", long_chain)) == ip("198.51.100.9")
    assert client_ip(scope_for(None, "1.2.3.4")) is None
    assert parse_ip("testclient") is None and parse_ip("fe80::1%eth0") == ip("fe80::1")


def test_ipv6_clients_are_keyed_by_their_64() -> None:
    assert ip_rate_key(ip("2001:db8:1:2:aaaa::1")) == ip_rate_key(ip("2001:db8:1:2:ffff::9")) == "2001:db8:1:2::/64"
    assert ip_rate_key(ip("203.0.113.1")) == "203.0.113.1" and ip_rate_key(None) == "unknown"


def access_token(subject: str | None = None) -> str:
    return create_access_token(subject=subject or str(uuid.uuid4()), role="developer")


def test_jwt_subject_accepts_only_valid_access_tokens() -> None:
    subject = str(uuid.uuid4())
    now = int(time.time())
    base = {"sub": subject, "type": "access", "exp": now + 600}
    assert jwt_subject(f"Bearer {access_token(subject)}") == subject
    assert jwt_subject(f"bearer   {access_token(subject)}  ") == subject
    rejected = [
        None, "", "Bearer", "Bearer ", f"Basic {access_token(subject)}", "Bearer not.a.jwt",
        f"Bearer {jwt.encode({**base, 'exp': now - 10}, settings.SECRET_KEY, algorithm='HS256')}",
        f"Bearer {jwt.encode(base, 'a-different-signing-key-of-decent-length', algorithm='HS256')}",
        f"Bearer {jwt.encode({**base, 'type': 'refresh'}, settings.SECRET_KEY, algorithm='HS256')}",
        f"Bearer {jwt.encode({**base, 'sub': 'bad subject'}, settings.SECRET_KEY, algorithm='HS256')}",
        f"Bearer {jwt.encode(base, None, algorithm='none')}",
        "Bearer " + "a" * 9000,
    ]
    for header in rejected:
        assert jwt_subject(header) is None, header


def test_rate_limit_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", [])
    subject = str(uuid.uuid4())
    scope = scope_for("203.0.113.5")
    scope["headers"].append((b"authorization", f"Bearer {access_token(subject)}".encode()))
    assert rate_limit_identity(scope) == f"user:{subject}"
    assert rate_limit_identity(scope_for("203.0.113.5")) == "ip:203.0.113.5"


# --------------------------------------------------------------------------- rate limiting
def limited_app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/api/v1/items")
    def items() -> dict:
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    def login() -> dict:
        return {"ok": True}

    @app.post("/api/v1/auth/refresh")
    def refresh() -> dict:
        return {"ok": True}

    @app.get("/api/v1/auth/me")
    def me() -> dict:
        return {"ok": True}

    @app.get("/api/v1/health/live")
    def live() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/health/ready")
    def ready() -> dict:
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics_route() -> dict:
        return {"ok": True}

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    return app


@pytest.fixture()
def limiter(monkeypatch: pytest.MonkeyPatch) -> CacheClient:
    cache = CacheClient(connect=False, clock=lambda: 1_000_020.0)
    monkeypatch.setattr(middleware, "cache", cache)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 3)
    monkeypatch.setattr(settings, "AUTH_RATE_LIMIT_PER_MINUTE", 2)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_IPS", ["10.0.0.0/8"])
    return cache


def statuses(app, n: int, **kwargs) -> list[int]:
    return [call_asgi(app, **kwargs).status for _ in range(n)]


def test_limit_exceeded_returns_429_envelope_with_retry_after(limiter: CacheClient) -> None:
    app = limited_app()
    assert statuses(app, 3, path="/api/v1/items") == [200, 200, 200]
    reply = call_asgi(app, path="/api/v1/items")
    assert reply.status == 429
    assert envelope(reply)["code"] == "rate_limited"
    assert 1 <= int(reply.headers["retry-after"]) <= 120
    assert UUID4_RE.match(reply.headers["x-request-id"])


def test_one_user_cannot_exhaust_a_shared_proxy_ip_budget(limiter: CacheClient) -> None:
    app = limited_app()
    shared = {"client": ("10.0.0.2", 5000), "path": "/api/v1/items"}
    user_a = [("x-forwarded-for", "203.0.113.50"), ("authorization", f"Bearer {access_token()}")]
    user_b = [("x-forwarded-for", "203.0.113.50"), ("authorization", f"Bearer {access_token()}")]
    assert statuses(app, 4, headers=user_a, **shared) == [200, 200, 200, 429]
    assert call_asgi(app, headers=user_b, **shared).status == 200
    assert call_asgi(app, headers=[("x-forwarded-for", "203.0.113.50")], **shared).status == 200


def test_distinct_clients_behind_a_trusted_proxy_have_separate_budgets(limiter: CacheClient) -> None:
    app = limited_app()
    via_proxy = {"client": ("10.0.0.2", 5000), "path": "/api/v1/items"}
    assert statuses(app, 4, headers=[("x-forwarded-for", "203.0.113.1")], **via_proxy) == [200, 200, 200, 429]
    assert call_asgi(app, headers=[("x-forwarded-for", "203.0.113.2")], **via_proxy).status == 200


def test_spoofed_forwarded_for_cannot_evade_the_limit(limiter: CacheClient) -> None:
    app = limited_app()
    untrusted = [call_asgi(app, path="/api/v1/items", client=("198.51.100.66", 1),
                           headers=[("x-forwarded-for", f"192.0.2.{i}")]).status for i in range(4)]
    assert untrusted == [200, 200, 200, 429]
    behind_proxy = [call_asgi(app, path="/api/v1/items", client=("10.0.0.2", 1),
                              headers=[("x-forwarded-for", f"192.0.2.{i}, 203.0.113.9")]).status for i in range(4)]
    assert behind_proxy == [200, 200, 200, 429]


def test_invalid_tokens_cannot_mint_fresh_budgets(limiter: CacheClient) -> None:
    app = limited_app()
    results = []
    for _ in range(4):
        forged = jwt.encode({"sub": str(uuid.uuid4()), "type": "access", "exp": int(time.time()) + 600},
                            "attacker-chosen-signing-key-000000", algorithm="HS256")
        results.append(call_asgi(app, path="/api/v1/items", headers=[("authorization", f"Bearer {forged}")]).status)
    assert results == [200, 200, 200, 429]


def test_ipv6_clients_in_the_same_64_share_a_budget(limiter: CacheClient) -> None:
    app = limited_app()
    peers = ["2001:db8:1:2::10", "2001:db8:1:2::11", "2001:db8:1:2:ffff::1", "2001:db8:1:2::99"]
    assert [call_asgi(app, path="/api/v1/items", client=(p, 1)).status for p in peers] == [200, 200, 200, 429]


def test_auth_bucket_is_stricter_and_keyed_by_ip_even_with_valid_tokens(limiter: CacheClient) -> None:
    app = limited_app()
    logins = [call_asgi(app, "POST", "/api/v1/auth/login",
                        headers=[("authorization", f"Bearer {access_token()}")]).status for _ in range(3)]
    assert logins == [200, 200, 429]
    assert call_asgi(app, path="/api/v1/items").status == 200  # API bucket is separate


def test_metrics_and_liveness_are_exempt_but_readiness_is_limited(limiter: CacheClient) -> None:
    """Regression: the whole /health prefix was exempt, including the DB-touching readiness probe."""
    app = limited_app()
    assert statuses(app, 10, path="/metrics") == [200] * 10
    assert statuses(app, 10, path="/api/v1/health/live") == [200] * 10
    assert statuses(app, 4, path="/api/v1/health/ready") == [200, 200, 200, 429]
    assert not is_rate_limit_exempt("/api/v1/health/ready") and not is_rate_limit_exempt("/api/v1/healthz")
    assert not is_rate_limit_exempt("/docs") and not is_rate_limit_exempt("/metrics/")


def test_readiness_checks_run_at_most_once_per_cache_window(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.routers import health

    calls: list[str] = []
    monkeypatch.setattr(health, "_database_ok", lambda: calls.append("database") or True)
    monkeypatch.setattr(health, "_cache_ok", lambda: True)
    monkeypatch.setattr(health, "_model_ok", lambda: False)
    health.reset_readiness_cache()
    try:
        assert all(health.ready().status_code == 200 for _ in range(50))
        assert calls == ["database"]
        health.reset_readiness_cache()
        health.ready()
        assert calls == ["database", "database"]
    finally:
        health.reset_readiness_cache()


def test_strict_auth_bucket_covers_only_credential_endpoints(limiter: CacheClient) -> None:
    """Regression: refresh/me/logout shared the 10/min per-IP login bucket, so one client flooding login
    from a shared address locked everyone behind it out of session renewal."""
    app = limited_app()
    shared = ("203.0.113.40", 1)
    assert [call_asgi(app, "POST", "/api/v1/auth/login", client=shared).status for _ in range(4)] == \
        [200, 200, 429, 429]
    assert call_asgi(app, "POST", "/api/v1/auth/refresh", client=shared).status == 200
    assert call_asgi(app, path="/api/v1/auth/me", client=shared,
                     headers=[("authorization", f"Bearer {access_token()}")]).status == 200
    assert middleware.is_credential_endpoint("/api/v1/auth/register")
    assert not middleware.is_credential_endpoint("/api/v1/auth/refresh")


def test_middleware_path_rules_apply_under_a_root_path(limiter: CacheClient) -> None:
    """Regression: with --root-path the scope path carries the prefix, so every prefix rule silently failed."""
    app = limited_app()
    app.add_middleware(middleware.SecurityHeadersMiddleware)
    prefixed = {"root_path": "/warden", "client": ("203.0.113.61", 1)}
    logins = [call_asgi(app, "POST", "/warden/api/v1/auth/login", **prefixed).status for _ in range(3)]
    assert logins == [200, 200, 429]  # strict bucket (2/min), not the API bucket (3/min)
    assert [call_asgi(app, path="/warden/api/v1/health/live", **prefixed).status for _ in range(6)] == [200] * 6
    reply = call_asgi(app, path="/warden/api/v1/items", **prefixed)
    assert reply.status == 200 and reply.headers["cache-control"] == "no-store"
    assert middleware.route_path({"path": "/warden", "root_path": "/warden"}) == ""
    assert middleware.route_path({"path": "/wardenx/api", "root_path": "/warden"}) == "/wardenx/api"


def test_rate_limiter_cache_call_runs_off_the_event_loop(monkeypatch: pytest.MonkeyPatch, limiter: CacheClient) -> None:
    """Regression: a blocking Redis call on the event loop stalled every in-flight request during an outage."""
    seen: list[int] = []

    class Recording:
        def rate_limit(self, key, limit, window_seconds=60):
            seen.append(threading.get_ident())
            return RateLimitResult(allowed=True, count=1.0, limit=limit, retry_after=0)

    monkeypatch.setattr(middleware, "cache", Recording())
    assert call_asgi(limited_app(), path="/api/v1/items").status == 200
    assert seen and seen[0] != threading.get_ident()  # asyncio.run drives the loop on this thread


def test_redis_limiter_errors_open_a_short_circuit_breaker() -> None:
    calls: list[bool] = []

    class DownRedis:
        def pipeline(self, transaction=True):
            calls.append(transaction)
            raise ConnectionError("socket timeout")

    now = {"t": 100.0}
    client = CacheClient(redis_client=DownRedis(), connect=False, clock=lambda: 1_000_020.0,
                         monotonic=lambda: now["t"])
    results = [client.rate_limit("ratelimit:api:ip:198.51.100.9", 2) for _ in range(4)]
    assert len(calls) == 1  # later requests skip Redis while the breaker is open
    assert [r.allowed for r in results] == [True, True, False, False]  # the fallback still limits
    now["t"] += RATE_LIMIT_BREAKER_SECONDS + 0.1
    client.rate_limit("ratelimit:api:ip:198.51.100.9", 2)
    assert len(calls) == 2


def test_in_process_rate_limit_counters_survive_cache_churn() -> None:
    """Regression: counters shared one key cap with cached JSON and were evicted first, resetting budgets."""
    client = CacheClient(connect=False, clock=lambda: 1_000_020.0)
    client._fallback = _InProcessBackend(clock=lambda: 1_000_020.0, max_keys=1000)
    key = "ratelimit:auth:ip:203.0.113.9"
    results = [client.rate_limit(key, 10) for _ in range(11)]
    assert results[-1].allowed is False and results[-1].count == 11.0
    for i in range(1001):
        client.set_json(f"verdict:pypi:pkg{i}", {"i": i}, 3600)
    after = client.rate_limit(key, 10)
    assert after.allowed is False and after.count == 12.0


def test_in_process_eviction_is_amortised_at_the_key_cap() -> None:
    backend = _InProcessBackend(clock=lambda: 1000.0, max_keys=1000)
    for i in range(1000):
        backend.setex(f"k{i}", 60, "v")
    before = backend.sweeps
    for i in range(1000, 3000):
        backend.setex(f"k{i}", 60 + i, "v")
    assert backend.sweeps - before <= 30  # previously one full sweep per write past the cap
    assert len(backend._kv) <= 1000
    assert backend.window_incr("ratelimit:x:1", 120) == 1
    for i in range(3000, 5000):
        backend.setex(f"k{i}", 60, "v")
    assert backend.window_get("ratelimit:x:1") == 1


def test_limiter_failure_fails_open(monkeypatch: pytest.MonkeyPatch, limiter: CacheClient) -> None:
    class ExplodingCache:
        def rate_limit(self, *args, **kwargs):
            raise RuntimeError("redis exploded")

    monkeypatch.setattr(middleware, "cache", ExplodingCache())
    assert statuses(limited_app(), 5, path="/api/v1/items") == [200] * 5


def test_real_app_429_is_readable_by_allowed_browser_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(middleware, "cache", CacheClient(connect=False))
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 2)
    origin = settings.CORS_ORIGINS[0]
    tc = TestClient(create_app(), client=("198.51.100.77", 5000))
    codes = [tc.get("/", headers={"Origin": origin}) for _ in range(3)]
    assert [r.status_code for r in codes] == [200, 200, 429]
    limited = codes[-1]
    assert limited.headers["access-control-allow-origin"] == origin
    assert "retry-after" in limited.headers["access-control-expose-headers"].lower()
    assert limited.headers["retry-after"].isdigit()
    assert limited.headers["content-security-policy"] == API_CSP


@pytest.mark.parametrize("previous", [0, 1, 50, 500])
@pytest.mark.parametrize("current", [1, 3, 4, 100])
@pytest.mark.parametrize("elapsed", [0.0, 12.5, 59.9])
def test_retry_after_is_positive_and_bounded(previous: int, current: int, elapsed: float) -> None:
    assert 1 <= retry_after_seconds(previous, current, 3, elapsed, 60) <= 120


# --------------------------------------------------------------------------- security headers
def csp_directives(csp: str) -> dict[str, list[str]]:
    return {p.split()[0]: p.split()[1:] for p in (part.strip() for part in csp.split(";")) if p}


def test_api_responses_carry_strict_headers(client: TestClient) -> None:
    for response in (client.get("/api/v1/health/live"), client.get("/api/v1/does-not-exist")):
        h = response.headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        assert h["cross-origin-opener-policy"] == "same-origin"
        assert "camera=()" in h["permissions-policy"]
        assert h["content-security-policy"] == API_CSP
        assert h["cache-control"] == "no-store"
        assert "strict-transport-security" not in h


def test_hsts_only_in_production(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ENV", "production")
    assert client.get("/api/v1/health/live").headers["strict-transport-security"] == HSTS_VALUE


def has_source(directives: dict[str, list[str]], name: str, source: str) -> bool:
    """Exact match of one CSP source token in one directive."""
    return any(token == source for token in directives.get(name, []))


def inline_script_hashes(html: str) -> set[str]:
    bodies = [b for b in re.findall(r"<script>(.*?)</script\b[^>]*>", html, re.DOTALL | re.IGNORECASE) if b.strip()]
    return {"'sha256-" + base64.b64encode(hashlib.sha256(b.encode()).digest()).decode() + "'" for b in bodies}


def test_swagger_ui_csp_allows_its_assets_without_unsafe_inline_scripts(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    d = csp_directives(response.headers["content-security-policy"])
    hashes = inline_script_hashes(response.text)
    assert hashes and hashes <= set(d["script-src"])
    assert has_source(d, "script-src", "https://cdn.jsdelivr.net") and has_source(d, "style-src", "https://cdn.jsdelivr.net")
    assert "'unsafe-inline'" not in d["script-src"] and "'unsafe-eval'" not in d["script-src"]
    assert d["default-src"] == ["'none'"] and d["frame-ancestors"] == ["'none'"] and d["object-src"] == ["'none'"]
    assert has_source(d, "img-src", "https://fastapi.tiangolo.com")
    assert response.headers["x-frame-options"] == "DENY"

    redirect = client.get("/docs/oauth2-redirect")
    assert inline_script_hashes(redirect.text) <= set(csp_directives(redirect.headers["content-security-policy"])[
        "script-src"])


def test_redoc_csp_allows_fonts_and_worker(client: TestClient) -> None:
    d = csp_directives(client.get("/redoc").headers["content-security-policy"])
    assert has_source(d, "script-src", "https://cdn.jsdelivr.net")
    assert has_source(d, "style-src", "https://fonts.googleapis.com") and has_source(d, "font-src", "https://fonts.gstatic.com")
    assert d["worker-src"] == ["blob:"]


def test_docs_csp_ignores_non_https_and_hostile_sources() -> None:
    html = ('<script src="http://evil.example/x.js"></script><script src="javascript:alert(1)"></script>'
            '<script src="https://cdn.example.org:8443/ok.js"></script><link rel="stylesheet" href="//evil/x.css">'
            '<link rel="icon" href="https://icons.example/i.png"><script>   </script>')
    d = csp_directives(docs_csp(html))
    assert d["script-src"] == ["'self'", "https://cdn.example.org:8443"]
    assert has_source(d, "img-src", "https://icons.example")
    assert not any("evil" in src for values in d.values() for src in values)


def test_production_serves_no_docs_and_strict_csp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ENV", "production")
    tc = TestClient(create_app())
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        response = tc.get(path)
        assert response.status_code == 404, path
        assert response.headers["content-security-policy"] == API_CSP
        assert response.headers["strict-transport-security"] == HSTS_VALUE
    assert tc.get("/").json()["docs"] is None


# --------------------------------------------------------------------------- error envelopes
class RecordingLog:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict]] = []

    def __getattr__(self, level: str):
        return lambda event, **kw: self.records.append((level, event, kw))


def test_unhandled_exception_returns_sanitised_500_and_logs_type_and_redacted_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = RecordingLog()
    monkeypatch.setattr(errors, "log", recorder)
    app = create_app()

    def boom() -> dict:
        raise RuntimeError(f"database password leak {GH_TOKEN}\n\x1b[31m")

    app.add_api_route("/api/v1/boom", boom)
    # The test client's peer is not a trusted proxy, so the supplied id is replaced by a server id.
    response = TestClient(app, raise_server_exceptions=False).get("/api/v1/boom",
                                                                   headers={"X-Request-ID": "boom-request-0001"})
    assert response.status_code == 500
    rid = response.headers["x-request-id"]
    assert UUID4_RE.match(rid)
    assert envelope(response) == {"code": "internal_error", "message": "An internal error occurred.",
                                  "request_id": rid}
    assert response.headers["content-security-policy"] == API_CSP and response.headers["cache-control"] == "no-store"
    assert GH_TOKEN not in response.text and "database" not in response.text

    (level, event, fields), = [r for r in recorder.records if r[1] == "unhandled_exception"]
    assert level == "error" and fields["error_type"] == "RuntimeError"
    assert GH_TOKEN not in fields["error"] and "\x1b" not in fields["error"]
    assert set(fields) <= {"error_type", "error", "request_id"}


def test_422_status_uses_current_starlette_name_with_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    assert errors.HTTP_422_UNPROCESSABLE == 422 and errors.HTTP_413_CONTENT_TOO_LARGE == 413
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the current name must not trigger Starlette's deprecation warning
        assert errors._status_constant("HTTP_422_UNPROCESSABLE_CONTENT", "HTTP_422_UNPROCESSABLE_ENTITY", 0) == 422
    monkeypatch.setattr(errors, "_starlette_status", types.SimpleNamespace(HTTP_422_UNPROCESSABLE_ENTITY=422))
    assert errors._status_constant("HTTP_422_UNPROCESSABLE_CONTENT", "HTTP_422_UNPROCESSABLE_ENTITY", 0) == 422
    monkeypatch.setattr(errors, "_starlette_status", types.SimpleNamespace())
    assert errors._status_constant("HTTP_422_UNPROCESSABLE_CONTENT", "HTTP_422_UNPROCESSABLE_ENTITY", 422) == 422


class HostileModel(BaseModel):
    scan_id: uuid.UUID
    email: EmailStr
    when: datetime
    count: int
    name: str = Field(max_length=16)

    @field_validator("name")
    @classmethod
    def _no_evil(cls, v: str) -> str:
        if "evil" in v:
            raise ValueError(f"name {v!r} is not allowed")
        return v


class RangeModel(BaseModel):
    low: int
    high: int
    label: str

    @model_validator(mode="after")
    def _ordered(self) -> RangeModel:
        if self.low > self.high:
            raise ValueError(f"{self.label}: low {self.low} must not exceed high {self.high}")
        return self


def validation_message(model: type[BaseModel], data: dict) -> str:
    with pytest.raises(ValidationError) as exc:
        model.model_validate(data)
    return format_validation_errors(exc.value.errors())


def test_validation_messages_never_echo_input_values() -> None:
    message = validation_message(HostileModel, {
        "scan_id": "<script>alert(1)</script>",
        "email": "<img src=x onerror=alert(2)>@‮example.com",
        "when": AWS_KEY,
        "count": "99999999999999999999xyz",
        "name": "evil\x1bname",
    })
    for leaked in ("<script>", "alert", "<img", "‮", AWS_KEY, "99999999999", "evil", "\x1b"):
        assert leaked not in message, leaked
    for field in ("scan_id", "email", "when", "count", "name"):
        assert field in message


def test_model_level_validator_messages_are_scrubbed() -> None:
    message = validation_message(RangeModel, {"low": 98765, "high": 12345, "label": "customer-secret-label"})
    assert "98765" not in message and "12345" not in message and "customer-secret-label" not in message
    assert "must not exceed" in message


def test_validation_locations_are_bounded_and_redacted() -> None:
    errors_list = [
        {"loc": ("body", "items", AWS_KEY), "msg": "Field required", "type": "missing"},
        {"loc": ("body", "bad key\n<x>", 3), "msg": "Field required", "type": "missing"},
    ] + [{"loc": ("query", f"f{i}"), "msg": "Field required", "type": "missing"} for i in range(12)]
    message = format_validation_errors(errors_list)
    assert AWS_KEY not in message and "<x>" not in message and "<key>.3" in message
    assert message.endswith("and 4 more error(s)")


def test_real_app_validation_and_json_errors_do_not_reflect_input(client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": "<script>alert(1)</script>", "password": ""})
    assert response.status_code == 422
    error = envelope(response)
    assert error["code"] == "validation_error" and "email" in error["message"]
    assert "<script>" not in response.text and "alert" not in response.text

    broken = client.post("/api/v1/auth/login", content=b'{"email": "<script>',
                         headers={"content-type": "application/json"})
    assert broken.status_code == 422 and "<script>" not in broken.text


# --------------------------------------------------------------------------- system endpoints
def test_system_info_requires_system_read_and_contains_no_secrets(client: TestClient, admin_token: str) -> None:
    for path in ("/system/info", "/system/tools"):
        route = next(r for r in system_router.router.routes if r.path == path)
        assert route.dependencies[0].dependency.required_permissions == frozenset({Permission.SYSTEM_READ})
    assert client.get("/api/v1/system/info").status_code == 401

    response = client.get("/api/v1/system/info", headers=auth(admin_token))
    assert response.status_code == 200
    body = response.json()
    assert {"version", "env", "analyzer_version", "features", "limits"} <= set(body)
    assert body["limits"]["max_request_body_bytes"] == settings.MAX_REQUEST_BODY_BYTES
    assert {"intel", "provenance", "monitoring", "sandbox", "metrics"} <= set(body["features"])
    for secret in (settings.SECRET_KEY, settings.DATABASE_URL, settings.REDIS_URL, settings.FIRST_ADMIN_PASSWORD):
        assert secret not in response.text


def test_system_tools_reports_availability_without_paths(client: TestClient, admin_token: str,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    import app.analysis.tools as tools_module

    def fake_find_tool(binary: str, **kwargs) -> ToolStatus:
        if binary.endswith("gitleaks"):
            raise RuntimeError("probe crashed")
        if binary.endswith("semgrep"):
            return ToolStatus(name="semgrep", available=True, version="1.2.3")
        return ToolStatus(name=binary, available=False, detail="not found on PATH")

    monkeypatch.setattr(tools_module, "find_tool", fake_find_tool)
    monkeypatch.setattr(settings, "SEMGREP_BINARY", "/opt/private-toolchain/bin/semgrep")
    response = client.get("/api/v1/system/tools", headers=auth(admin_token))
    assert response.status_code == 200
    tools = {t["name"]: t for t in response.json()}
    assert set(tools) == {"yara", "semgrep", "gitleaks", "syft", "grype", "trivy"}
    assert all(set(t) == {"name", "available", "version", "detail"} for t in tools.values())
    assert tools["semgrep"] == {"name": "semgrep", "available": True, "version": "1.2.3", "detail": None}
    assert tools["gitleaks"]["available"] is False and "RuntimeError" in tools["gitleaks"]["detail"]
    assert "private-toolchain" not in response.text
    assert metrics.REGISTRY.get_sample_value("tool_available", {"tool": "semgrep"}) == 1
    assert metrics.REGISTRY.get_sample_value("tool_available", {"tool": "trivy"}) == 0
    assert client.get("/api/v1/system/tools").status_code == 401
