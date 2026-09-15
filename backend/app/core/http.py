"""Hardened outbound HTTP client shared by every component that talks to the network.

Warden talks to package registries and vulnerability-intelligence services whose responses
are untrusted (a registry serves attacker-published metadata; any service can misbehave).
``SafeHttpClient`` centralises the controls every outbound call needs:

* **Host allowlist + HTTPS only** — each request *and each redirect hop* is checked, so a
  redirect cannot bounce Warden to an internal address (SSRF).
* **Response size cap** — bodies are streamed and aborted past ``max_response_bytes``.
* **Timeouts, bounded retries, exponential backoff with jitter** — retrying only on
  network errors and 429/5xx, honouring ``Retry-After``. httpx timeouts apply per network
  operation, so a server that drips one byte at a time is not bounded by them; the optional
  ``total_timeout`` is a wall-clock budget for a whole ``request()`` (retries, backoff sleeps,
  redirects and body streaming). Exhausting it raises ``kind="network"`` and is not retried.
* **Client-side rate limiting** — a token bucket so Warden never hammers public services.
* **No secret leakage** — URLs in errors/logs have their query strings stripped (API keys
  often travel as query parameters), request headers are never logged, and caller-supplied
  headers other than content negotiation (``Authorization``, cookies, API-key headers ...)
  are dropped when a redirect crosses to a different origin.
* **Typed failures** — every transport, decoding or URL problem surfaces as
  :class:`OutboundHTTPError`, so hostile responses cannot crash callers with unexpected
  exception types.
* **Bounded decoding** — httpx decodes ``Content-Encoding`` a whole raw chunk at a time (and
  chains decoders for stacked encodings), so a few hundred bytes could expand to hundreds of
  MiB before a size check ran. Warden therefore reads the *raw* stream and decodes it itself:
  only ``identity``, ``gzip`` and ``deflate`` are accepted (and advertised in
  ``Accept-Encoding``), a stacked or unknown encoding is refused with ``kind="decode"`` without
  decoding anything, and output is produced at most ``DECODE_CHUNK_BYTES`` at a time with the
  size cap checked after each piece.
"""

from __future__ import annotations

import email.utils
import ipaddress
import json
import random
import re
import threading
import time
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.logging import get_logger
from app.core.redaction import sanitize_text

log = get_logger("warden.http")

USER_AGENT = "Warden-X/2.0 (+https://github.com/rakshit-737/warden-supply-chain-firewall)"
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# ASCII digits only: str.isdigit() also accepts e.g. "²", which int()/float() then reject.
_DIGITS_RE = re.compile(r"[0-9]{1,32}")
# Legacy numeric host forms ("2130706433", "0x7f.1", "127.1") that ipaddress rejects but many
# resolvers map to addresses. No public DNS name has an all-numeric top-level label.
_NUMERIC_LABEL_RE = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)")
# Caller headers that may follow a redirect to a different origin.
_CROSS_ORIGIN_SAFE_HEADERS = frozenset({"accept", "accept-language", "content-type", "user-agent"})
_MAX_HTTP_DATE_LENGTH = 64
ACCEPT_ENCODING = "gzip, deflate"
DECODE_CHUNK_BYTES = 64 * 1024


class _BodyDecoder:
    """Incremental ``Content-Encoding`` decoder whose output per call is bounded.

    Raises ``ValueError`` on construction for stacked or unsupported encodings and ``zlib.error``
    for corrupt data. ``deflate`` accepts both zlib-wrapped and raw streams, like httpx.
    """

    def __init__(self, content_encoding: str | None) -> None:
        codings = [c.strip().lower() for c in (content_encoding or "").split(",") if c.strip()]
        codings = [c for c in codings if c != "identity"]
        if len(codings) > 1:
            raise ValueError("stacked content-encoding")
        self.kind = codings[0] if codings else "identity"
        self._first = True
        if self.kind in ("gzip", "x-gzip"):
            self._dec: zlib._Decompress | None = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif self.kind == "deflate":
            self._dec = zlib.decompressobj()
        elif self.kind == "identity":
            self._dec = None
        else:
            raise ValueError("unsupported content-encoding")

    def decode(self, raw: bytes) -> Iterator[bytes]:
        if self._dec is None:
            if raw:
                yield raw
            return
        data = raw
        while data and not self._dec.eof:
            try:
                out = self._dec.decompress(data, DECODE_CHUNK_BYTES)
            except zlib.error:
                if self.kind == "deflate" and self._first:  # not zlib-wrapped: retry as raw deflate
                    self._first = False
                    self._dec = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise
            self._first = False
            data = self._dec.unconsumed_tail
            if out:
                yield out
            elif not data:
                break

    def flush(self) -> bytes:
        return self._dec.flush() if self._dec is not None else b""


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
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:  # RecursionError: hostile deep nesting
            raise OutboundHTTPError("response is not valid JSON", kind="decode", status=self.status,
                                    url=safe_url(self.url)) from exc


def safe_url(url: str) -> str:
    """URL without query string, fragment or userinfo — safe to log."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""  # .port raises ValueError for e.g. ":abc"
    except ValueError:
        return "<invalid-url>"
    return f"{parts.scheme}://{host}{port}{parts.path}"


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        return scheme, parts.hostname or "", parts.port or {"https": 443, "http": 80}.get(scheme)
    except ValueError:
        return None


def parse_retry_after(value: str | None, *, now: Callable[[], float] = time.time) -> float | None:
    """Delay in seconds from a ``Retry-After`` header (delta-seconds or HTTP-date).

    Returns ``None`` for a missing or unparseable value; a date in the past gives ``0.0``.
    """
    if not value:
        return None
    value = value.strip()
    if _DIGITS_RE.fullmatch(value):
        return float(value)
    if len(value) > _MAX_HTTP_DATE_LENGTH:
        return None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:  # pragma: no cover - older Pythons returned None instead of raising
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, when.timestamp() - now())


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
            return not _NUMERIC_LABEL_RE.fullmatch(host.rsplit(".", 1)[-1])
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
        total_timeout: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.total_timeout = float(total_timeout) if total_timeout and total_timeout > 0 else None
        self._clock = clock
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
        deadline = self._clock() + self.total_timeout if self.total_timeout else None
        current, current_method, current_params, current_body = url, method.upper(), params, json_body
        current_headers: Mapping[str, str] | None = dict(headers) if headers else None
        for _ in range(self.max_redirects + 1):
            result = self._with_retries(current_method, current, current_params, current_body, current_headers, limit,
                                        deadline)
            if result.status not in _REDIRECT_STATUSES:
                return result
            location = result.headers.get("location")
            if not location:
                raise OutboundHTTPError(f"{self.name}: redirect without location", kind="redirect",
                                        status=result.status, url=safe_url(current))
            target = urljoin(current, location)
            if current_headers and _origin(target) != _origin(current):
                # Never forward credentials to another origin, even an allowlisted one.
                current_headers = {k: v for k, v in current_headers.items()
                                   if k.lower() in _CROSS_ORIGIN_SAFE_HEADERS}
            current = target
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
            _ = parts.port  # raises ValueError for a non-numeric or out-of-range port
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
            shown = sanitize_text(host, max_len=100) if host else "<none>"  # host may come from a Location header
            raise OutboundHTTPError(f"{self.name}: host not allowed: {shown}", kind="host_not_allowed",
                                    url=safe_url(url))

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        delay = parse_retry_after(retry_after)
        if delay is not None:
            return min(self.backoff_max, delay)
        base = min(self.backoff_max, self.backoff_base * (2 ** attempt))
        return base * (0.5 + random.random() / 2)  # nosec B311 - retry jitter, not security-sensitive

    def _budget_exceeded(self, url: str) -> OutboundHTTPError:
        return OutboundHTTPError(f"{self.name}: total time budget of {self.total_timeout:g}s exceeded", kind="network",
                                 url=safe_url(url))

    def _pause(self, delay: float, deadline: float | None, url: str) -> None:
        """Back off for ``delay`` seconds, or fail now if that would overrun the request budget."""
        if deadline is not None and self._clock() + delay > deadline:
            raise self._budget_exceeded(url)
        self._sleep(delay)

    def _with_retries(self, method, url, params, json_body, headers, limit, deadline=None) -> HttpResult:
        attempt = 0
        while True:
            if deadline is not None and self._clock() > deadline:
                raise self._budget_exceeded(url)
            try:
                result = self._send_once(method, url, params, json_body, headers, limit, deadline)
            except OutboundHTTPError:
                raise
            except httpx.DecodingError as exc:  # e.g. corrupt gzip body: not transient, do not retry
                raise OutboundHTTPError(f"{self.name}: undecodable response body", kind="decode",
                                        url=safe_url(url)) from exc
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self.retries:
                    log.warning("outbound_http_failed", client=self.name, url=safe_url(url),
                                error_type=type(exc).__name__)
                    raise OutboundHTTPError(f"{self.name}: network error ({type(exc).__name__})", kind="network",
                                            url=safe_url(url)) from exc
                self._pause(self._backoff(attempt, None), deadline, url)
                attempt += 1
                continue
            except (httpx.HTTPError, httpx.InvalidURL) as exc:  # anything else httpx raises for this request
                raise OutboundHTTPError(f"{self.name}: request failed ({type(exc).__name__})", kind="network",
                                        url=safe_url(url)) from exc
            if result.status in _RETRY_STATUSES and attempt < self.retries:
                self._pause(self._backoff(attempt, result.headers.get("retry-after")), deadline, url)
                attempt += 1
                continue
            return result

    def _send_once(self, method, url, params, json_body, headers, limit, deadline=None) -> HttpResult:
        self._check_url(url)
        if self._bucket is not None:
            self._bucket.acquire()
        req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5",
                       "Accept-Encoding": ACCEPT_ENCODING}
        if headers:
            req_headers.update(headers)
        # follow_redirects=False per request: an injected httpx.Client created with
        # follow_redirects=True would otherwise follow hops internally, bypassing _check_url.
        with self._client.stream(method, url, params=params, json=json_body, headers=req_headers,
                                 follow_redirects=False) as resp:
            declared = (resp.headers.get("content-length") or "").strip()
            if _DIGITS_RE.fullmatch(declared) and int(declared) > limit:
                raise OutboundHTTPError(f"{self.name}: response exceeds {limit} bytes", kind="too_large",
                                        status=resp.status_code, url=safe_url(url))
            try:
                decoder = _BodyDecoder(resp.headers.get("content-encoding"))
            except ValueError as exc:
                raise OutboundHTTPError(f"{self.name}: refusing stacked or unsupported Content-Encoding",
                                        kind="decode", status=resp.status_code, url=safe_url(url)) from exc
            buf = bytearray()

            def append(piece: bytes) -> None:
                buf.extend(piece)
                if len(buf) > limit:
                    raise OutboundHTTPError(f"{self.name}: response exceeds {limit} bytes", kind="too_large",
                                            status=resp.status_code, url=safe_url(url))

            if resp.is_stream_consumed:
                # In-memory transports (mocks, httpx.MockTransport with bytes content) hand over a body
                # httpx already read and decoded when the Response was built; nothing came off a socket.
                append(resp.content)
            else:
                try:
                    # Raw network chunks, decoded here with bounded output per step; the cap is checked
                    # after every decoded piece, before the next one is produced.
                    for raw in resp.iter_raw():
                        for piece in decoder.decode(raw):
                            append(piece)
                        if deadline is not None and self._clock() > deadline:
                            raise self._budget_exceeded(url)
                    append(decoder.flush())
                except zlib.error as exc:
                    raise OutboundHTTPError(f"{self.name}: undecodable response body", kind="decode",
                                            status=resp.status_code, url=safe_url(url)) from exc
            return HttpResult(
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                content=bytes(buf),
                url=str(resp.url),
            )
