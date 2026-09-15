"""Hardened outbound HTTP client shared by every component that talks to the network.

Warden talks to package registries and vulnerability-intelligence services whose responses
are untrusted (a registry serves attacker-published metadata; any service can misbehave).
``SafeHttpClient`` centralises the controls every outbound call needs:

* **Host allowlist + HTTPS only** — each request *and each redirect hop* is checked, so a
  redirect cannot bounce Warden to an internal address (SSRF).
* **Response size cap** — bodies are streamed and aborted past ``max_response_bytes``.
* **Timeouts, bounded retries, exponential backoff with jitter** — retrying only on
  network errors and 429/5xx, honouring ``Retry-After``.
* **Client-side rate limiting** — a token bucket so Warden never hammers public services.
* **No secret leakage** — URLs in errors/logs have their query strings stripped (API keys
  often travel as query parameters) and request headers are never logged.
"""

from __future__ import annotations

import ipaddress
import json
import random
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.logging import get_logger

log = get_logger("warden.http")

USER_AGENT = "Warden-X/2.0 (+https://github.com/rakshit-737/warden-supply-chain-firewall)"
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class OutboundHTTPError(Exception):
    """A failed outbound request. ``kind`` is machine-readable, the message is log-safe."""

    def __init__(self, message: str, *, kind: str, status: int | None = None, url: str | None = None) -> None:
        super().__init__(message)
        self.kind = kind  # network | status | too_large | host_not_allowed | scheme | redirect | decode
        self.status = status
        self.url = url


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]  # lower-cased header names
    content: bytes
    url: str

    def json(self) -> Any:
        try:
            return json.loads(self.content)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OutboundHTTPError("response is not valid JSON", kind="decode", status=self.status,
                                    url=safe_url(self.url)) from exc


def safe_url(url: str) -> str:
    """URL without query string, fragment or userinfo — safe to log."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path}"


class TokenBucket:
    """Thread-safe token bucket: ``rate`` tokens per second, up to ``burst`` stored."""

    def __init__(
        self,
        rate_per_second: float,
        burst: int | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = rate_per_second
        self.capacity = float(burst if burst is not None else max(1, int(rate_per_second)))
        self._tokens = self.capacity
        self._last = clock()
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate
            self._sleep(wait)


def _host_allowed(host: str, allowed: frozenset[str] | None) -> bool:
    host = host.lower().rstrip(".")
    if allowed is None:
        # No allowlist: permit public hostnames only; refuse loopback/private literals.
        if host in {"localhost"} or host.endswith(".localhost") or host.endswith(".internal"):
            return False
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return True
        return ip.is_global
    for entry in allowed:
        entry = entry.lower().rstrip(".")
        if entry.startswith("."):
            if host.endswith(entry) or host == entry[1:]:
                return True
        elif host == entry:
            return True
    return False


class SafeHttpClient:
    def __init__(
        self,
        *,
        name: str,
        allowed_hosts: Iterable[str] | None,
        max_response_bytes: int = 16 * 1024 * 1024,
        timeout: float = 20.0,
        retries: int = 2,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        rate_limit_per_second: float | None = None,
        allow_http: bool = False,
        max_redirects: int = 3,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.name = name
        self.allowed_hosts = frozenset(allowed_hosts) if allowed_hosts is not None else None
        self.max_response_bytes = max_response_bytes
        self.retries = max(0, retries)
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.allow_http = allow_http
        self.max_redirects = max_redirects
        self._sleep = sleep
        self._bucket = TokenBucket(rate_limit_per_second, sleep=sleep) if rate_limit_per_second else None
        self._owns_client = client is None
        # Redirects are followed manually so that every hop is re-validated.
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # ------------------------------------------------------------------ public helpers
    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
        allow_404: bool = False,
    ) -> Any | None:
        result = self.request("GET", url, params=params, headers=headers, max_bytes=max_bytes)
        if result.status == 404 and allow_404:
            return None
        self._raise_for_status(result)
        return result.json()

    def post_json(
        self,
        url: str,
        body: Any,
        *,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> Any:
        result = self.request("POST", url, json_body=body, headers=headers, max_bytes=max_bytes)
        self._raise_for_status(result)
        return result.json()

    def get_bytes(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        result = self.request("GET", url, headers=headers, max_bytes=max_bytes)
        self._raise_for_status(result)
        return result.content

    # ------------------------------------------------------------------ core
    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> HttpResult:
        limit = max_bytes or self.max_response_bytes
        current, current_method, current_params, current_body = url, method.upper(), params, json_body
        for _ in range(self.max_redirects + 1):
            result = self._with_retries(current_method, current, current_params, current_body, headers, limit)
            if result.status not in _REDIRECT_STATUSES:
                return result
            location = result.headers.get("location")
            if not location:
                raise OutboundHTTPError(f"{self.name}: redirect without location", kind="redirect",
                                        status=result.status, url=safe_url(current))
            current = urljoin(current, location)
            current_params = None  # the Location URL already carries its own query
            if result.status == 303 or (result.status in (301, 302) and current_method == "POST"):
                current_method, current_body = "GET", None
        raise OutboundHTTPError(f"{self.name}: too many redirects", kind="redirect", url=safe_url(url))

    def _raise_for_status(self, result: HttpResult) -> None:
        if result.status >= 400:
            raise OutboundHTTPError(f"{self.name}: HTTP {result.status}", kind="status", status=result.status,
                                    url=safe_url(result.url))

    def _check_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise OutboundHTTPError(f"{self.name}: invalid URL", kind="scheme") from exc
        allowed_schemes = {"https", "http"} if self.allow_http else {"https"}
        if parts.scheme.lower() not in allowed_schemes:
            raise OutboundHTTPError(f"{self.name}: refusing non-HTTPS URL", kind="scheme", url=safe_url(url))
        if parts.username or parts.password:
            raise OutboundHTTPError(f"{self.name}: refusing URL with embedded credentials", kind="scheme",
                                    url=safe_url(url))
        host = parts.hostname or ""
        if not host or not _host_allowed(host, self.allowed_hosts):
            raise OutboundHTTPError(f"{self.name}: host not allowed: {host or '<none>'}", kind="host_not_allowed",
                                    url=safe_url(url))

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after and retry_after.strip().isdigit():
            return min(self.backoff_max, float(retry_after.strip()))
        base = min(self.backoff_max, self.backoff_base * (2 ** attempt))
        return base * (0.5 + random.random() / 2)  # nosec B311 - retry jitter, not security-sensitive

    def _with_retries(self, method, url, params, json_body, headers, limit) -> HttpResult:
        attempt = 0
        while True:
            try:
                result = self._send_once(method, url, params, json_body, headers, limit)
            except OutboundHTTPError:
                raise
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self.retries:
                    log.warning("outbound_http_failed", client=self.name, url=safe_url(url),
                                error_type=type(exc).__name__)
                    raise OutboundHTTPError(f"{self.name}: network error ({type(exc).__name__})", kind="network",
                                            url=safe_url(url)) from exc
                self._sleep(self._backoff(attempt, None))
                attempt += 1
                continue
            if result.status in _RETRY_STATUSES and attempt < self.retries:
                self._sleep(self._backoff(attempt, result.headers.get("retry-after")))
                attempt += 1
                continue
            return result

    def _send_once(self, method, url, params, json_body, headers, limit) -> HttpResult:
        self._check_url(url)
        if self._bucket is not None:
            self._bucket.acquire()
        req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"}
        if headers:
            req_headers.update(headers)
        with self._client.stream(method, url, params=params, json=json_body, headers=req_headers) as resp:
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise OutboundHTTPError(f"{self.name}: response exceeds {limit} bytes", kind="too_large",
                                        status=resp.status_code, url=safe_url(url))
            buf = bytearray()
            for chunk in resp.iter_bytes(chunk_size=65536):
                buf.extend(chunk)
                if len(buf) > limit:
                    raise OutboundHTTPError(f"{self.name}: response exceeds {limit} bytes", kind="too_large",
                                            status=resp.status_code, url=safe_url(url))
            return HttpResult(
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                content=bytes(buf),
                url=str(resp.url),
            )
