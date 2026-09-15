"""Test fixtures.

The suite runs entirely on a throwaway SQLite database and never touches the network:
the analysis orchestrator is replaced with a deterministic fake in API tests, and the
analyzer/fetcher tests operate on in-memory inputs. This is what lets `pytest` verify the
whole system with zero external services.

Offline is *enforced*, not just intended: before the app is imported, ``socket.connect`` /
``connect_ex`` and ``socket.getaddrinfo`` are wrapped so that only loopback / local-socket
traffic is possible (the optional Redis probe and asyncio's self-pipe use loopback; respx and
``httpx.MockTransport`` never open sockets). A blocked attempt raises an ``OSError`` subclass —
so code under test degrades exactly as it would during a real outage — *and* is recorded, and
the test that caused it fails at teardown. Set ``WARDEN_TEST_ALLOW_NETWORK=1`` to disable.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import tempfile

import pytest

# --------------------------------------------------------------------------- network guard
_BLOCKED_NETWORK_ATTEMPTS: list[str] = []


class NetworkAccessBlocked(OSError):
    """Raised when a test tries to reach a non-loopback host."""


def _is_local_host(host: object) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    text = str(host).strip().strip("[]").split("%", 1)[0].rstrip(".").lower()
    if text in {"", "localhost", "localhost.localdomain"} or text.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _is_ip_literal(host: object) -> bool:
    try:
        ipaddress.ip_address(str(host).strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


def _refuse(what: str) -> NetworkAccessBlocked:
    _BLOCKED_NETWORK_ATTEMPTS.append(what)
    return NetworkAccessBlocked(f"real network I/O is disabled in tests: {what}")


def _install_network_guard() -> None:
    real_connect, real_connect_ex, real_getaddrinfo = (
        socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo)

    def _check_address(sock: socket.socket, address: object) -> None:
        if sock.family in (socket.AF_INET, socket.AF_INET6) and isinstance(address, tuple) and address:
            if not _is_local_host(address[0]):
                raise _refuse(f"connect {address[0]!s}:{address[1] if len(address) > 1 else '?'}")

    def guarded_connect(self, address):
        _check_address(self, address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        _check_address(self, address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        # IP literals need no DNS (connect() then enforces loopback); names must be local.
        if not (_is_local_host(host) or _is_ip_literal(host)):
            raise _refuse(f"resolve {host!s}")
        return real_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]


if os.environ.get("WARDEN_TEST_ALLOW_NETWORK") != "1":
    _install_network_guard()

# Configure a fully isolated environment BEFORE importing the app. The database file is
# per-process so concurrent test runs (e.g. parallel CI jobs) never share state.
_TMP_DB = os.path.join(tempfile.gettempdir(), f"warden_test_{os.getpid()}.db")
os.environ.update(
    # Tests are offline: no vulnerability-intelligence or provenance network lookups unless a
    # test explicitly enables them with mocked HTTP (respx).
    INTEL_OFFLINE="true",
    PROVENANCE_ENABLED="false",
    MONITOR_ENABLED="false",
    ENV="development",
    DEBUG="false",
    DATABASE_URL=f"sqlite+pysqlite:///{_TMP_DB}",
    REDIS_OPTIONAL="true",
    REDIS_URL="redis://localhost:6390/0",  # intentionally unused -> in-process fallback
    SECRET_KEY="test-secret-key-that-is-sufficiently-long-1234567890",
    FIRST_ADMIN_EMAIL="admin@warden.io",
    FIRST_ADMIN_PASSWORD="AdminPassw0rd!2026",
    RATE_LIMIT_PER_MINUTE="100000",
    AUTH_RATE_LIMIT_PER_MINUTE="100000",
)

if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_network():
    """Fail any test during which a non-loopback connection or DNS lookup was attempted."""
    start = len(_BLOCKED_NETWORK_ATTEMPTS)
    yield
    attempts = _BLOCKED_NETWORK_ATTEMPTS[start:]
    if attempts:
        pytest.fail(f"test attempted real network I/O (blocked): {sorted(set(attempts))[:5]}", pytrace=False)


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token(client) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "AdminPassw0rd!2026"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
