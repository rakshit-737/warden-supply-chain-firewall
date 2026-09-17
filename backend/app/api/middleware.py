"""Cross-cutting ASGI middleware: request ids, access log + HTTP metrics, security headers,
request-body limits and rate limiting.

Everything here is *pure ASGI* rather than Starlette's ``BaseHTTPMiddleware``: pure ASGI sees
the raw ``receive`` stream (needed to cap chunked bodies without buffering them), does not run
the app in a separate task (context variables such as the request id propagate naturally),
and adds no per-request stream copying.

Installed by :func:`app.main.create_app` in this order (outermost first)::

    RequestContextMiddleware → SecurityHeadersMiddleware → CORSMiddleware
        → RateLimitMiddleware → BodySizeLimitMiddleware → routes

Security rationale
------------------
* **Paths** are matched relative to the app mount: ``scope["root_path"]`` is removed first (as
  Starlette's router does), so deploying behind a path prefix (``--root-path /warden``) cannot
  move requests out of the auth bucket, drop ``Cache-Control: no-store`` or rate-limit probes.
* **Request ids** end up in logs, error envelopes and the hash-chained audit trail, so a
  client-chosen value is honoured only when the direct peer is a configured trusted proxy (which
  is expected to set its own id) *and* it matches ``^[A-Za-z0-9._-]{8,64}$``. Anything else gets
  a fresh UUID: an internet client cannot inject markup or reuse another user's id to blur
  correlation.
* **Body limits** are enforced on the declared ``Content-Length`` *and* on the bytes actually
  streamed, so chunked uploads cannot bypass ``MAX_REQUEST_BODY_BYTES``.
* **Client IPs** come from ``X-Forwarded-For`` only when the direct peer is a configured
  trusted proxy, and then the right-most *untrusted* hop is used — the left part of the header
  is attacker-controlled. IPv6 clients are keyed by their /64, which a single host typically
  controls in full.
* **Rate limits** key authenticated requests by the JWT subject (signature and expiry
  verified; invalid tokens are ignored and fall back to the IP key), so one user behind a
  shared NAT/proxy cannot exhaust everyone else's budget. The stricter auth bucket applies only
  to the endpoints that accept guessable credentials (``/auth/login``, ``/auth/register``) and
  is always keyed by client IP: presenting some account's valid token must not buy extra
  credential-guessing budget, and one client hammering login from a shared address cannot lock
  everyone there out of ``/auth/refresh`` or ``/auth/me``. Only ``/metrics`` and the liveness
  probe are exempt (readiness touches the database and the cache, so it is limited like any
  other request). The limiter's cache call runs in the threadpool, never on the event loop, and
  limiter failures fail *open*: a cache outage must not take the API down.
* **Metrics** use the matched route *template* as the label, never the raw path.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import time
import uuid
from functools import lru_cache
from urllib.parse import urlsplit

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core import metrics
from app.core.cache import cache
from app.core.config import settings
from app.core.errors import RequestBodyTooLarge, error_response, internal_error_response
from app.core.logging import get_logger, request_id_ctx
from app.core.redaction import sanitize_text
from app.core.security import decode_access_token

log = get_logger("warden.http")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._-]{8,64}")


# =========================================================================== request id
def resolve_request_id(candidate: str | None) -> str:
    """Return ``candidate`` if it is a well-formed request id, otherwise a new UUID4."""
    if candidate is not None and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


# =========================================================================== security headers
_BASE_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
HSTS_VALUE = "max-age=63072000; includeSubDomains"
# Backwards-compatible name: the static header set applied to every response.
_SECURITY_HEADERS = {**_BASE_SECURITY_HEADERS, "Content-Security-Policy": API_CSP}


def _under(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def route_path(scope: Scope) -> str:
    """The request path relative to the app mount (``root_path`` removed), as the router matches it.

    ASGI servers put the full path, mount prefix included, in ``scope["path"]`` when a
    ``root_path`` is configured; path-based middleware rules must use the routed path.
    """
    path = scope.get("path", "") or ""
    root = scope.get("root_path", "") or ""
    if not root or not path.startswith(root):
        return path
    if path == root:
        return ""
    return path[len(root):] if path[len(root)] == "/" else path


def apply_security_headers(headers: MutableHeaders, path: str) -> None:
    """Add Warden's security headers to a response's headers.

    A response may set its own ``Content-Security-Policy`` (the API docs pages do, see
    :func:`docs_csp`); every other response gets the strict API policy. API and metrics
    responses always get ``Cache-Control: no-store`` — they carry verdicts, audit data and
    tokens that shared caches must never keep.
    """
    for name, value in _BASE_SECURITY_HEADERS.items():
        if name not in headers:
            headers[name] = value
    if "content-security-policy" not in headers:
        headers["Content-Security-Policy"] = API_CSP
    if _under(path, settings.API_V1_PREFIX) or path == "/metrics":
        headers["Cache-Control"] = "no-store"
    if settings.ENV == "production" and "strict-transport-security" not in headers:
        headers["Strict-Transport-Security"] = HSTS_VALUE


_SCRIPT_RE = re.compile(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script\b[^>]*>", re.IGNORECASE | re.DOTALL)
_LINK_RE = re.compile(r"<link\b(?P<attrs>[^>]*)>", re.IGNORECASE)
_SRC_RE = re.compile(r"""\bsrc\s*=\s*["']?(?P<url>[^"'\s>]+)""", re.IGNORECASE)
_HREF_RE = re.compile(r"""\bhref\s*=\s*["']?(?P<url>[^"'\s>]+)""", re.IGNORECASE)


def _https_origin(url: str) -> str | None:
    try:
        parts = urlsplit(url)
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None
    return f"https://{parts.hostname}{port}"


def docs_csp(html: str) -> str:
    """Content-Security-Policy for the Swagger UI / ReDoc pages generated by FastAPI.

    Inline scripts are allowed by their exact SHA-256 hash (no ``'unsafe-inline'`` for
    scripts); external scripts, stylesheets and icons only from the HTTPS origins the page
    itself references. ReDoc injects ``<style>`` elements at runtime and runs its search in a
    ``blob:`` worker, so ``style-src 'unsafe-inline'`` and ``worker-src blob:`` are granted —
    acceptable because docs are served only outside production and contain no user data.
    """
    script_src = {"'self'"}
    style_src = {"'self'", "'unsafe-inline'"}
    img_src = {"'self'", "data:", "https://cdn.redoc.ly", "https://validator.swagger.io"}
    font_src = {"'self'", "data:"}
    for match in _SCRIPT_RE.finditer(html):
        src = _SRC_RE.search(match.group("attrs"))
        if src:
            origin = _https_origin(src.group("url"))
            if origin:
                script_src.add(origin)
        elif match.group("body").strip():
            digest = base64.b64encode(hashlib.sha256(match.group("body").encode("utf-8")).digest()).decode("ascii")
            script_src.add(f"'sha256-{digest}'")
    for match in _LINK_RE.finditer(html):
        attrs = match.group("attrs")
        href = _HREF_RE.search(attrs)
        origin = _https_origin(href.group("url")) if href else None
        if origin is None:
            continue
        if "stylesheet" in attrs.lower():
            style_src.add(origin)
            if origin == "https://fonts.googleapis.com":
                font_src.add("https://fonts.gstatic.com")
        elif "icon" in attrs.lower():
            img_src.add(origin)
    return "; ".join([
        "default-src 'none'",
        "script-src " + " ".join(sorted(script_src)),
        "style-src " + " ".join(sorted(style_src)),
        "img-src " + " ".join(sorted(img_src)),
        "font-src " + " ".join(sorted(font_src)),
        "connect-src 'self'",
        "worker-src blob:",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'none'",
    ])


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = route_path(scope)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                apply_security_headers(MutableHeaders(scope=message), path)
            await send(message)

        await self.app(scope, receive, send_with_headers)


# =========================================================================== client identity
_MAX_FORWARDED_HOPS = 32
_SUBJECT_RE = re.compile(r"[A-Za-z0-9._:@\-]{1,128}")
_MAX_AUTHORIZATION_LENGTH = 8192


def parse_ip(value: str | None) -> IPAddress | None:
    """Parse an address as found in ``scope['client']`` / ``X-Forwarded-For`` (ports, brackets, zones)."""
    if not value:
        return None
    v = value.strip()
    if v.startswith("["):  # "[2001:db8::1]" or "[2001:db8::1]:443"
        end = v.find("]")
        if end == -1:
            return None
        v = v[1:end]
    elif v.count(":") == 1 and "." in v:  # "203.0.113.7:51234"
        v = v.split(":", 1)[0]
    v = v.split("%", 1)[0]  # IPv6 zone id
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


@lru_cache(maxsize=8)
def _trusted_networks(entries: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            log.warning("invalid_trusted_proxy_entry", entry=sanitize_text(entry, max_len=64))
    return tuple(networks)


def _is_trusted(ip: IPAddress, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]) -> bool:
    return any(ip.version == net.version and ip in net for net in networks)


def peer_is_trusted_proxy(scope: Scope) -> bool:
    """True when the direct TCP peer is one of ``TRUSTED_PROXY_IPS``."""
    client = scope.get("client")
    peer = parse_ip(client[0]) if client else None
    networks = _trusted_networks(tuple(settings.TRUSTED_PROXY_IPS))
    return peer is not None and bool(networks) and _is_trusted(peer, networks)


def client_ip(scope: Scope, headers: Headers | None = None) -> IPAddress | None:
    """The client address, honouring ``X-Forwarded-For`` only behind a trusted proxy.

    Walks the forwarded chain from the right, skipping trusted proxies, and returns the first
    untrusted hop. A malformed hop stops the walk at the last trusted address (conservative:
    requests share the proxy's budget rather than choosing an arbitrary key).
    """
    client = scope.get("client")
    peer = parse_ip(client[0]) if client else None
    if peer is None:
        return None
    networks = _trusted_networks(tuple(settings.TRUSTED_PROXY_IPS))
    if not networks or not _is_trusted(peer, networks):
        return peer
    headers = headers if headers is not None else Headers(scope=scope)
    hops = [hop.strip() for value in headers.getlist("x-forwarded-for") for hop in value.split(",") if hop.strip()]
    candidate = peer
    for hop in reversed(hops[-_MAX_FORWARDED_HOPS:]):
        ip = parse_ip(hop)
        if ip is None:
            return candidate
        if not _is_trusted(ip, networks):
            return ip
        candidate = ip
    return candidate


def ip_rate_key(ip: IPAddress | None) -> str:
    if ip is None:
        return "unknown"
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Network((ip, 64), strict=False))
    return str(ip)


def jwt_subject(authorization: str | None) -> str | None:
    """Subject of a *valid* bearer access token (signature + expiry verified), else ``None``."""
    if not authorization or len(authorization) > _MAX_AUTHORIZATION_LENGTH:
        return None
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        payload = decode_access_token(token)
    except Exception:  # invalid, expired, wrong algorithm ... -> treat as anonymous
        return None
    if not isinstance(payload, dict) or payload.get("type") != "access":
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not _SUBJECT_RE.fullmatch(subject):
        return None
    return subject


def rate_limit_identity(scope: Scope, headers: Headers | None = None) -> str:
    headers = headers if headers is not None else Headers(scope=scope)
    subject = jwt_subject(headers.get("authorization"))
    if subject is not None:
        return f"user:{subject}"
    return f"ip:{ip_rate_key(client_ip(scope, headers))}"


# =========================================================================== rate limiting
# Prometheus scrapers and liveness probes poll from shared addresses on a fixed cadence and do no
# backend work. Readiness (database + cache checks) is deliberately *not* exempt.
_EXEMPT_PATHS = frozenset({"/metrics"})
RATE_LIMIT_WINDOW_SECONDS = 60
# Endpoints that accept guessable credentials get the strict per-IP bucket.
CREDENTIAL_ENDPOINTS = ("/auth/login", "/auth/register")


def is_rate_limit_exempt(path: str) -> bool:
    return path in _EXEMPT_PATHS or _under(path, f"{settings.API_V1_PREFIX}/health/live")


def is_credential_endpoint(path: str) -> bool:
    return any(_under(path, f"{settings.API_V1_PREFIX}{suffix}") for suffix in CREDENTIAL_ENDPOINTS)


class RateLimitMiddleware:
    """Sliding-window rate limiting per user (valid JWT) or client IP, stricter on credential endpoints."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = route_path(scope)
        if scope["type"] != "http" or scope.get("method") == "OPTIONS" or is_rate_limit_exempt(path):
            await self.app(scope, receive, send)
            return
        is_auth = is_credential_endpoint(path)
        limit = settings.AUTH_RATE_LIMIT_PER_MINUTE if is_auth else settings.RATE_LIMIT_PER_MINUTE
        try:
            headers = Headers(scope=scope)
            if is_auth:
                identity = f"ip:{ip_rate_key(client_ip(scope, headers))}"
            else:
                identity = rate_limit_identity(scope, headers)
            key = f"ratelimit:{'auth' if is_auth else 'api'}:{identity}"
            # Blocking Redis I/O (socket timeouts, reconnects) must never stall the event loop.
            result = await run_in_threadpool(cache.rate_limit, key, int(limit),
                                             window_seconds=RATE_LIMIT_WINDOW_SECONDS)
        except Exception as exc:  # never let the limiter take down the API
            log.warning("rate_limiter_failed", error_type=type(exc).__name__)
            await self.app(scope, receive, send)
            return
        if not result.allowed:
            log.info("rate_limited", bucket="auth" if is_auth else "api", identity=identity)
            response = error_response(429, "rate_limited", "Too many requests",
                                      headers={"Retry-After": str(result.retry_after)})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# =========================================================================== body size limit
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,19}")


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``MAX_REQUEST_BODY_BYTES`` with a 413 envelope.

    The declared ``Content-Length`` is checked before the app runs; the streamed body is
    counted as the app reads it, and reading past the limit raises
    :class:`~app.core.errors.RequestBodyTooLarge` (turned into a 413 by the exception handlers,
    or by this middleware if it escapes them).
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int | None = None) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    def _limit(self) -> int:
        configured = self.max_body_bytes if self.max_body_bytes is not None else settings.MAX_REQUEST_BODY_BYTES
        return max(0, int(configured))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit()
        declared = {v.strip() for v in Headers(scope=scope).getlist("content-length")}
        if declared:
            value = next(iter(declared))
            if len(declared) != 1 or not _CONTENT_LENGTH_RE.fullmatch(value):
                await error_response(400, "bad_request", "Invalid Content-Length header")(scope, receive, send)
                return
            if int(value) > limit:
                await self._too_large(limit)(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > limit:
                    raise RequestBodyTooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLarge:
            if not response_started:
                await self._too_large(limit)(scope, receive, tracking_send)

    @staticmethod
    def _too_large(limit: int):
        return error_response(RequestBodyTooLarge(limit).status_code, "payload_too_large",
                              f"Request body exceeds the {limit}-byte limit")


# =========================================================================== request context
def route_template(scope: Scope) -> str:
    """The matched route's path *template* (``/api/v1/scans/{scan_id}``) — never the raw path.

    FastAPI >= 0.13x records the fully prefixed template of routes from included routers in
    ``scope["fastapi"]["effective_route_context"]``; ``scope["route"]`` / endpoint lookup are
    fallbacks (the former may lack the include prefix, but is still a template). Requests
    that matched no route get ``__unmatched__``; requests answered by middleware before
    routing (413/429) get ``__unrouted__``.
    """
    try:
        fastapi_scope = scope.get("fastapi")
        context = fastapi_scope.get("effective_route_context") if isinstance(fastapi_scope, dict) else None
        template = getattr(context, "path", None)
        if isinstance(template, str) and template.startswith("/"):
            return template
        template = getattr(scope.get("route"), "path", None)
        if isinstance(template, str) and template.startswith("/"):
            return template
        endpoint, app = scope.get("endpoint"), scope.get("app")
        if endpoint is not None and app is not None:
            for route in getattr(app, "routes", ()):
                if getattr(route, "endpoint", None) is endpoint and isinstance(getattr(route, "path", None), str):
                    return route.path
    except Exception:  # nosec B110 - labelling must never break a request
        pass
    return metrics.UNMATCHED_ROUTE if "router" in scope else metrics.UNROUTED


class RequestContextMiddleware:
    """Assign/validate the request id, bind it for logging, record access log + HTTP metrics.

    If the app raises before sending a response, a sanitised 500 envelope (with request id and
    security headers) is sent here and the exception is re-raised so the registered handler
    still logs it and the server still sees the failure.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        candidate = Headers(scope=scope).get("x-request-id") if peer_is_trusted_proxy(scope) else None
        rid = resolve_request_id(candidate)
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["request_id"] = rid
        token = request_id_ctx.set(rid)
        path = scope.get("path", "")
        mounted_path = route_path(scope)
        start = time.perf_counter()
        status_code: int | None = None
        cancelled = False

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception:
            if status_code is None:
                response = internal_error_response(request_id=rid)
                apply_security_headers(response.headers, mounted_path)
                try:
                    await response(scope, receive, send_with_request_id)
                except Exception:  # nosec B110 - client gone; the original error is re-raised below
                    pass
            raise
        except BaseException:  # cancellation / client disconnect
            cancelled = True
            raise
        finally:
            elapsed = time.perf_counter() - start
            final_status = status_code if status_code is not None else (499 if cancelled else 500)
            route = route_template(scope)
            metrics.observe_http(scope.get("method", ""), route, final_status, elapsed)
            ip = client_ip(scope)
            log.info(
                "request",
                method=sanitize_text(scope.get("method", ""), max_len=16),
                route=route,
                path=sanitize_text(path, max_len=256),
                status=final_status,
                duration_ms=int(elapsed * 1000),
                client=str(ip) if ip is not None else None,
            )
            request_id_ctx.reset(token)


__all__ = [
    "API_CSP", "BodySizeLimitMiddleware", "RateLimitMiddleware", "RequestContextMiddleware",
    "SecurityHeadersMiddleware", "apply_security_headers", "client_ip", "docs_csp", "ip_rate_key",
    "is_credential_endpoint", "is_rate_limit_exempt", "jwt_subject", "parse_ip", "peer_is_trusted_proxy",
    "rate_limit_identity", "resolve_request_id", "route_path", "route_template",
]
