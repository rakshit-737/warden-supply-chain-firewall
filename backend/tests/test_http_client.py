"""SafeHttpClient hardening tests.

Fully offline: responses come from ``httpx.MockTransport`` handlers (or ``respx``), and the
retry sleep is injected so no test ever waits.
"""

from __future__ import annotations

import email.utils
import tracemalloc
import zlib
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
import pytest
import respx

from app.core.http import (
    OutboundHTTPError,
    SafeHttpClient,
    TokenBucket,
    _host_allowed,
    parse_retry_after,
    safe_url,
)

Handler = Callable[[httpx.Request], httpx.Response]


class Script:
    """Returns scripted responses in order (the last one repeats) and records requests."""

    def __init__(self, *steps: Handler | Exception) -> None:
        self.steps = list(steps)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        step = self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]
        if isinstance(step, Exception):
            raise step
        return step(request)

    @property
    def hosts(self) -> list[str]:
        return [r.url.host for r in self.requests]


def make_client(script: Script, **kwargs) -> tuple[SafeHttpClient, list[float]]:
    sleeps: list[float] = []
    options = {"name": "test", "allowed_hosts": ["pypi.org", "files.pythonhosted.org"], **kwargs}
    client = SafeHttpClient(client=httpx.Client(transport=httpx.MockTransport(script)), sleep=sleeps.append, **options)
    return client, sleeps


def ok_json(payload: object = None) -> Handler:
    return lambda request: httpx.Response(200, json={"ok": True} if payload is None else payload)


def status(code: int, **headers: str) -> Handler:
    return lambda request: httpx.Response(code, headers=headers)


def redirect(location: str, code: int = 302) -> Handler:
    return lambda request: httpx.Response(code, headers={"Location": location})


# --------------------------------------------------------------------------- URL policy
def test_plain_http_is_refused_before_any_request() -> None:
    script = Script(ok_json())
    client, _ = make_client(script)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("http://pypi.org/pypi/requests/json")
    assert err.value.kind == "scheme"
    assert script.requests == []


def test_host_outside_allowlist_is_refused() -> None:
    script = Script(ok_json())
    client, _ = make_client(script)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org.evil.example/pypi/x/json")
    assert err.value.kind == "host_not_allowed"
    assert script.requests == []


def test_embedded_credentials_are_refused_and_not_echoed() -> None:
    client, _ = make_client(Script(ok_json()))
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://user:hunter2pass@pypi.org/x")
    assert err.value.kind == "scheme"
    assert "hunter2pass" not in str(err.value) and "hunter2pass" not in (err.value.url or "")


def test_redirect_to_disallowed_host_is_blocked_without_contacting_it() -> None:
    script = Script(redirect("https://evil.example.net/steal"), ok_json())
    client, _ = make_client(script)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/pypi/x/json")
    assert err.value.kind == "host_not_allowed"
    assert script.hosts == ["pypi.org"]


def test_total_time_budget_aborts_a_slow_drip_body_without_retrying() -> None:
    now = [0.0]

    def drip():  # each byte "takes" one second on the fake clock
        for _ in range(100):
            now[0] += 1.0
            yield b"x"

    script = Script(lambda request: httpx.Response(200, content=drip()))
    client = SafeHttpClient(name="test", allowed_hosts=["pypi.org"], sleep=lambda s: None, total_timeout=10.0,
                            clock=lambda: now[0], client=httpx.Client(transport=httpx.MockTransport(script)))
    with pytest.raises(OutboundHTTPError) as err:
        client.get_bytes("https://pypi.org/slow")
    assert err.value.kind == "network" and "time budget" in str(err.value)
    assert now[0] <= 12.0  # stopped right after the budget, not after all 100 chunks
    assert len(script.requests) == 1  # an exhausted budget is not retried


def test_total_time_budget_bounds_retries_and_retry_after_sleeps() -> None:
    now, sleeps = [0.0], []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    script = Script(status(503, **{"Retry-After": "30"}))
    client = SafeHttpClient(name="test", allowed_hosts=["pypi.org"], sleep=sleep, retries=5, total_timeout=45.0,
                            clock=lambda: now[0], client=httpx.Client(transport=httpx.MockTransport(script)))
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert "time budget" in str(err.value)
    assert sleeps == [30.0] and len(script.requests) == 2  # the second 30 s sleep would overrun the budget


def test_without_a_total_budget_behaviour_is_unchanged() -> None:
    script = Script(status(503), ok_json())
    client, sleeps = make_client(script)
    assert client.total_timeout is None
    assert client.get_json("https://pypi.org/x") == {"ok": True} and len(sleeps) == 1


def test_injected_client_that_follows_redirects_still_revalidates_every_hop() -> None:
    # A caller-supplied httpx.Client configured with follow_redirects=True must not be able to
    # follow a hop internally (which would skip the allowlist check on the redirect target).
    script = Script(redirect("https://evil.example.net/steal"), ok_json())
    inner = httpx.Client(transport=httpx.MockTransport(script), follow_redirects=True)
    client = SafeHttpClient(name="test", allowed_hosts=["pypi.org"], client=inner, sleep=lambda s: None)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/pypi/x/json")
    assert err.value.kind == "host_not_allowed"
    assert script.hosts == ["pypi.org"]


def test_redirect_to_cloud_metadata_is_blocked_even_without_an_allowlist() -> None:
    script = Script(redirect("https://169.254.169.254/latest/meta-data/"), ok_json())
    client, _ = make_client(script, allowed_hosts=None)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://registry.example.org/x")
    assert err.value.kind == "host_not_allowed"
    assert script.hosts == ["registry.example.org"]


def test_redirect_downgrade_to_http_is_blocked() -> None:
    script = Script(redirect("http://pypi.org/insecure"), ok_json())
    client, _ = make_client(script)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/secure")
    assert err.value.kind == "scheme"
    assert len(script.requests) == 1


@pytest.mark.parametrize("location", ["https://pypi.org:abc/x", "https://pypi.org:99999/x"])
def test_redirect_with_invalid_port_raises_typed_error(location: str) -> None:
    # httpx itself may reject an unparseable Location (a transport error, retried then typed
    # "network"); otherwise Warden's own URL check refuses it ("scheme"). Either way the caller
    # gets OutboundHTTPError and the bogus port is never contacted.
    script = Script(redirect(location))
    client, _ = make_client(script, retries=1)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind in {"scheme", "network"}
    assert all(r.url.host == "pypi.org" and r.url.port is None for r in script.requests)


def test_allowed_relative_redirect_is_followed() -> None:
    script = Script(redirect("/pypi/x/2.0/json", 301), ok_json({"version": "2.0"}))
    client, _ = make_client(script)
    assert client.get_json("https://pypi.org/pypi/x/json") == {"version": "2.0"}
    assert [r.url.path for r in script.requests] == ["/pypi/x/json", "/pypi/x/2.0/json"]


def test_too_many_redirects() -> None:
    script = Script(redirect("/loop"))
    client, _ = make_client(script, max_redirects=2)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/start")
    assert err.value.kind == "redirect"
    assert len(script.requests) == 3


def test_redirect_without_location() -> None:
    client, _ = make_client(Script(status(302)))
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind == "redirect"


def test_cross_origin_redirect_drops_credentials_but_same_origin_keeps_them() -> None:
    script = Script(redirect("/moved"), redirect("https://files.pythonhosted.org/file"), ok_json())
    client, _ = make_client(script)
    client.get_json("https://pypi.org/x", headers={"Authorization": "Bearer abc", "apiKey": "k-123", "Accept": "a/b"})
    same, cross = script.requests[1], script.requests[2]
    assert same.headers.get("authorization") == "Bearer abc" and same.headers.get("apikey") == "k-123"
    assert "authorization" not in cross.headers and "apikey" not in cross.headers
    assert cross.headers.get("accept") == "a/b"


def test_post_303_becomes_get_without_body() -> None:
    script = Script(redirect("/result", 303), ok_json())
    client, _ = make_client(script)
    client.post_json("https://pypi.org/query", {"q": 1})
    assert script.requests[0].method == "POST" and script.requests[0].content
    assert script.requests[1].method == "GET" and script.requests[1].content == b""


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("pypi.org", True), ("registry.example.org", True), ("localhost", False), ("api.localhost", False),
        ("metadata.google.internal", False), ("127.0.0.1", False), ("10.1.2.3", False), ("169.254.169.254", False),
        ("::1", False), ("[::1]", False), ("fe80::1", False), ("2130706433", False), ("0x7f.1", False),
        ("127.1", False), ("017700000001", False), ("8.8.8.8", True),
    ],
)
def test_host_policy_without_allowlist(host: str, expected: bool) -> None:
    assert _host_allowed(host, None) is expected


def test_suffix_allowlist_entries() -> None:
    allowed = frozenset({".pythonhosted.org", "pypi.org"})
    assert _host_allowed("files.pythonhosted.org", allowed)
    assert _host_allowed("pythonhosted.org", allowed)
    assert _host_allowed("PyPI.org.", allowed)
    assert not _host_allowed("evilpythonhosted.org", allowed)
    assert not _host_allowed("pypi.org.evil.example", allowed)


def test_safe_url_strips_secrets_and_never_raises() -> None:
    assert safe_url("https://u:p@pypi.org:8443/path?api_key=SECRET#frag") == "https://pypi.org:8443/path"
    assert safe_url("https://pypi.org:abc/x") == "<invalid-url>"
    assert safe_url("http://[::1") == "<invalid-url>"


# --------------------------------------------------------------------------- size caps
def test_declared_content_length_over_cap_is_rejected_without_reading_body() -> None:
    consumed = []

    def body():
        consumed.append(True)
        yield b"x" * 10

    script = Script(lambda request: httpx.Response(200, headers={"Content-Length": "5000"}, content=body()))
    client, _ = make_client(script, max_response_bytes=1000)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_bytes("https://pypi.org/big")
    assert err.value.kind == "too_large"
    assert consumed == []


def test_streamed_body_over_cap_is_aborted() -> None:
    produced = []

    def body():
        for _ in range(100):
            produced.append(1)
            yield b"x" * 600

    client, _ = make_client(Script(lambda request: httpx.Response(200, content=body())), max_response_bytes=1000)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_bytes("https://pypi.org/chunked")
    assert err.value.kind == "too_large"
    assert len(produced) <= 3  # checked per network chunk: stops right after crossing the cap


def test_per_call_max_bytes_and_exact_limit() -> None:
    client, _ = make_client(Script(lambda request: httpx.Response(200, content=b"y" * 100)))
    assert client.get_bytes("https://pypi.org/f", max_bytes=100) == b"y" * 100
    with pytest.raises(OutboundHTTPError):
        client.get_bytes("https://pypi.org/f", max_bytes=99)


# "\xb2" is SUPERSCRIPT TWO in latin-1: str.isdigit() accepts it but int()/float() raise ValueError.
NON_ASCII_DIGIT = b"\xb2"


def test_non_ascii_digit_content_length_does_not_crash() -> None:
    script = Script(lambda request: httpx.Response(200, headers={"Content-Length": NON_ASCII_DIGIT},
                                                   content=iter([b"{}"])))
    client, _ = make_client(script)
    assert client.get_json("https://pypi.org/x") == {}


# --------------------------------------------------------------------------- retries
def test_retries_503_honouring_retry_after() -> None:
    script = Script(status(503, **{"Retry-After": "2"}), status(503, **{"Retry-After": "1"}), ok_json())
    client, sleeps = make_client(script, retries=2)
    assert client.get_json("https://pypi.org/x") == {"ok": True}
    assert sleeps == [2.0, 1.0]
    assert len(script.requests) == 3


def test_retry_after_is_capped_by_backoff_max() -> None:
    client, sleeps = make_client(Script(status(429, **{"Retry-After": "3600"}), ok_json()), retries=1, backoff_max=5.0)
    client.get_json("https://pypi.org/x")
    assert sleeps == [5.0]


def test_retry_after_http_date_and_garbage() -> None:
    now = 1_800_000_000.0
    future = email.utils.format_datetime(datetime.fromtimestamp(now + 30, tz=timezone.utc), usegmt=True)
    past = email.utils.format_datetime(datetime.fromtimestamp(now - 30, tz=timezone.utc), usegmt=True)
    assert parse_retry_after(future, now=lambda: now) == pytest.approx(30.0)
    assert parse_retry_after(past, now=lambda: now) == 0.0
    assert parse_retry_after(" 7 ") == 7.0
    for garbage in (None, "", "soon", "²", "-5", "1.5", "x" * 500):
        assert parse_retry_after(garbage) is None


def test_unparseable_retry_after_falls_back_to_bounded_backoff() -> None:
    hostile = Script(lambda request: httpx.Response(503, headers={"Retry-After": NON_ASCII_DIGIT}), ok_json())
    client, sleeps = make_client(hostile, retries=1)
    assert client.get_json("https://pypi.org/x") == {"ok": True}
    assert len(sleeps) == 1 and 0.25 <= sleeps[0] <= 0.5


def test_no_retry_on_404() -> None:
    script = Script(status(404))
    client, sleeps = make_client(script, retries=3)
    assert client.get_json("https://pypi.org/missing", allow_404=True) is None
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/missing")
    assert err.value.kind == "status" and err.value.status == 404
    assert len(script.requests) == 2  # one per call, never retried
    assert sleeps == []


def test_retries_exhausted_returns_status_error() -> None:
    script = Script(status(503))
    client, sleeps = make_client(script, retries=2)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind == "status" and err.value.status == 503
    assert len(script.requests) == 3 and len(sleeps) == 2


def test_network_errors_are_retried_then_typed() -> None:
    script = Script(httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), ok_json())
    client, sleeps = make_client(script, retries=2)
    assert client.get_json("https://pypi.org/x") == {"ok": True}
    assert len(sleeps) == 2

    failing = Script(httpx.ConnectError("refused"))
    client, _ = make_client(failing, retries=1)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind == "network"
    assert len(failing.requests) == 2


def test_corrupt_content_encoding_is_a_decode_error_not_a_crash() -> None:
    script = Script(lambda request: httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=b"not gzip"))
    client, sleeps = make_client(script, retries=2)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind == "decode"
    assert len(script.requests) == 1 and sleeps == []


def _gzip(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    return compressor.compress(data) + compressor.flush()


def _peak_while(fn: Callable[[], object]) -> tuple[BaseException | None, int]:
    tracemalloc.start()
    try:
        try:
            fn()
            error = None
        except BaseException as exc:  # noqa: BLE001 - returned to the test for assertions
            error = exc
        return error, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _streamed(body: bytes, **headers: str) -> Handler:
    # An iterator body behaves like a network stream: httpx does not pre-read (and pre-decode) it.
    return lambda request: httpx.Response(200, headers=headers, content=iter([body]))


def test_stacked_content_encoding_is_refused_without_decoding() -> None:
    """Regression: httpx decoded 'gzip, gzip' a whole raw chunk at a time (~750 MiB from 693 bytes)."""
    body = _gzip(_gzip(b"\x00" * (32 * 1024 * 1024)))
    assert len(body) < 4096
    client, _ = make_client(Script(_streamed(body, **{"Content-Encoding": "gzip, gzip"})),
                            max_response_bytes=1024 * 1024)
    error, peak = _peak_while(lambda: client.get_bytes("https://pypi.org/bomb"))
    assert isinstance(error, OutboundHTTPError) and error.kind == "decode"
    assert peak < 8 * 1024 * 1024, peak


def test_compressed_body_is_capped_while_decoding_not_after() -> None:
    body = _gzip(b"\x00" * (32 * 1024 * 1024))
    script = Script(_streamed(body, **{"Content-Encoding": "gzip"}))
    client, _ = make_client(script, max_response_bytes=1024 * 1024)
    error, peak = _peak_while(lambda: client.get_bytes("https://pypi.org/bomb"))
    assert isinstance(error, OutboundHTTPError) and error.kind == "too_large"
    assert peak < 8 * 1024 * 1024, peak


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


@pytest.mark.parametrize("encoding,encode", [
    ("gzip", _gzip), ("deflate", zlib.compress), ("deflate", _raw_deflate), ("identity", lambda data: data),
], ids=["gzip", "zlib-deflate", "raw-deflate", "identity"])
def test_supported_encodings_are_decoded(encoding: str, encode: Callable[[bytes], bytes]) -> None:
    payload = b'{"releases": "' + b"x" * 200_000 + b'"}'
    body = encode(payload)
    script = Script(_streamed(body, **{"Content-Encoding": encoding}))
    client, _ = make_client(script)
    assert client.get_bytes("https://pypi.org/x") == payload
    assert script.requests[0].headers["accept-encoding"] == "gzip, deflate"


def test_corrupt_streamed_body_is_a_decode_error() -> None:
    client, sleeps = make_client(Script(_streamed(b"not gzip at all", **{"Content-Encoding": "gzip"})), retries=2)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_bytes("https://pypi.org/x")
    assert err.value.kind == "decode" and sleeps == []


@pytest.mark.parametrize("encoding", ["br", "zstd", "compress", "gzip, identity, deflate"])
def test_unsupported_or_stacked_encodings_are_decode_errors(encoding: str) -> None:
    script = Script(_streamed(b"\x00" * 64, **{"Content-Encoding": encoding}))
    client, sleeps = make_client(script, retries=2)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_bytes("https://pypi.org/x")
    assert err.value.kind == "decode" and len(script.requests) == 1 and sleeps == []


@pytest.mark.parametrize("body", [b"{not json", b"\xff\xfe\x00", b"[" * 200_000 + b"]" * 200_000],
                         ids=["truncated", "bad-utf8", "deep-nesting"])  # short ids: Windows env-var length limit
def test_invalid_or_hostile_json_is_a_decode_error(body: bytes) -> None:
    client, _ = make_client(Script(lambda request: httpx.Response(200, content=body)))
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x")
    assert err.value.kind == "decode"


def test_errors_never_carry_query_string_secrets() -> None:
    client, _ = make_client(Script(status(500)), retries=0)
    with pytest.raises(OutboundHTTPError) as err:
        client.get_json("https://pypi.org/x?api_key=SUPERSECRET123", params={"token": "ALSOSECRET456"})
    text = f"{err.value} {err.value.url}"
    assert "SUPERSECRET123" not in text and "ALSOSECRET456" not in text


def test_default_headers_and_caller_headers() -> None:
    script = Script(ok_json())
    client, _ = make_client(script)
    client.get_json("https://pypi.org/x", headers={"Accept": "application/vnd.pypi.simple.v1+json"})
    sent = script.requests[0].headers
    assert sent["user-agent"].startswith("Warden/")
    assert sent["accept"] == "application/vnd.pypi.simple.v1+json"


@respx.mock
def test_works_with_respx_mocked_transport() -> None:
    route = respx.post("https://api.osv.dev/v1/query").mock(return_value=httpx.Response(200, json={"vulns": []}))
    client = SafeHttpClient(name="osv", allowed_hosts=["api.osv.dev"], sleep=lambda _: None)
    try:
        assert client.post_json("https://api.osv.dev/v1/query", {"package": {"name": "x"}}) == {"vulns": []}
    finally:
        client.close()
    assert route.called


# --------------------------------------------------------------------------- rate limiting
class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_token_bucket_allows_burst_then_paces() -> None:
    clock = FakeClock()
    bucket = TokenBucket(2.0, burst=2, clock=clock, sleep=clock.sleep)
    bucket.acquire()
    bucket.acquire()
    assert clock.sleeps == []
    bucket.acquire()
    assert clock.sleeps == [pytest.approx(0.5)]
    clock.now += 60  # idle: refills to capacity only, not 120 tokens
    for _ in range(2):
        bucket.acquire()
    assert len(clock.sleeps) == 1
    bucket.acquire()
    assert len(clock.sleeps) == 2


def test_token_bucket_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        TokenBucket(0)


def test_client_acquires_a_token_for_every_attempt() -> None:
    class CountingBucket:
        calls = 0

        def acquire(self) -> None:
            CountingBucket.calls += 1

    client, _ = make_client(Script(status(503), ok_json()), retries=1, rate_limit_per_second=5.0)
    client._bucket = CountingBucket()  # type: ignore[assignment]
    client.get_json("https://pypi.org/x")
    assert CountingBucket.calls == 2
