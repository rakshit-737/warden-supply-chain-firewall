"""The suite's offline guarantee is enforced by a socket guard in ``conftest.py``; prove it works.

If the guard silently stopped working, a test that accidentally reached PyPI or OSV would still
pass whenever the network happened to be available. These tests trigger the guard on purpose
and then remove their own (expected) attempts from the record so they do not fail at teardown.
"""

from __future__ import annotations

import os
import socket

import httpx
import pytest

from tests import conftest

pytestmark = pytest.mark.skipif(os.environ.get("WARDEN_TEST_ALLOW_NETWORK") == "1",
                                reason="network guard disabled by WARDEN_TEST_ALLOW_NETWORK=1")


@pytest.fixture()
def expected_attempts():
    start = len(conftest._BLOCKED_NETWORK_ATTEMPTS)
    yield lambda: conftest._BLOCKED_NETWORK_ATTEMPTS[start:]
    del conftest._BLOCKED_NETWORK_ATTEMPTS[start:]


def test_dns_lookup_of_a_public_name_is_blocked_and_recorded(expected_attempts):
    with pytest.raises(conftest.NetworkAccessBlocked):
        socket.getaddrinfo("pypi.org", 443)
    assert expected_attempts() == ["resolve pypi.org"]


@pytest.mark.parametrize("address", [("203.0.113.10", 443), ("8.8.8.8", 53), ("169.254.169.254", 80)],
                         ids=["documentation-range", "public-dns", "cloud-metadata"])
def test_connect_to_a_non_loopback_address_is_blocked(expected_attempts, address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(conftest.NetworkAccessBlocked):
            sock.connect(address)
        with pytest.raises(conftest.NetworkAccessBlocked):  # connect_ex is guarded too
            sock.connect_ex(address)
    finally:
        sock.close()
    assert len(expected_attempts()) == 2


def test_an_unmocked_httpx_request_fails_as_a_connection_error(expected_attempts):
    # Code under test sees an ordinary outage (httpx.ConnectError), and the attempt is recorded.
    with pytest.raises(httpx.ConnectError):
        httpx.get("https://pypi.org/simple/", timeout=5)
    assert expected_attempts()


def test_loopback_traffic_is_allowed():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.create_connection(listener.getsockname(), timeout=5)
        client.close()
    finally:
        listener.close()
    assert socket.getaddrinfo("localhost", 80)


@pytest.mark.parametrize("host,local", [
    ("127.0.0.1", True), ("::1", True), ("[::1]", True), ("localhost", True), ("LOCALHOST.", True),
    ("0.0.0.0", True), (None, True), (b"127.0.0.2", True),
    ("pypi.org", False), ("203.0.113.1", False), ("localhost.evil.example", False), ("127.0.0.1.nip.io", False),
])
def test_local_host_classification(host, local):
    assert conftest._is_local_host(host) is local
