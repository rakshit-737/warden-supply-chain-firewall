"""CISA KEV, FIRST EPSS and NVD clients (offline: HTTP mocked with respx, synthetic fixtures)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest
import respx

from app.core.config import settings
from app.intel.client import IntelCache, IntelSourceError, build_http_client, cache_key
from app.intel.epss import EpssClient
from app.intel.kev import KEV_CACHE_KEY, KevClient, catalog_from_cache, parse_kev_feed
from app.intel.nvd import NvdClient, parse_cve_response

DATA = Path(__file__).parent / "data" / "intel"
KEV_URL = settings.KEV_FEED_URL
EPSS_URL = settings.EPSS_API_BASE
NVD_URL = settings.NVD_API_BASE
NVD_KEY = "nvd-fixture-key-0123456789abcdef"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    def get_json(self, key):
        raw = self.data.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.data[key] = json.dumps(value, default=str)
        self.ttls[key] = ttl


def _http(source: str, url: str):
    return build_http_client(source, url, timeout=5, rate_limit_per_second=None, max_response_bytes=4_000_000,
                             sleep=lambda _s: None)


def kev_client(cache: MemoryCache, *, ttl: int = 43200, clock=None) -> KevClient:
    kwargs = {"clock": clock} if clock else {}
    return KevClient(_http("cisa-kev", KEV_URL), IntelCache(cache), feed_url=KEV_URL, ttl_seconds=ttl, **kwargs)


def epss_client(cache: MemoryCache) -> EpssClient:
    return EpssClient(_http("first-epss", EPSS_URL), IntelCache(cache), base_url=EPSS_URL, ttl_seconds=86400)


def nvd_client(cache: MemoryCache, api_key: str | None = None) -> NvdClient:
    return NvdClient(_http("nvd", NVD_URL), IntelCache(cache), base_url=NVD_URL, api_key=api_key, ttl_seconds=3600)


# --------------------------------------------------------------------------- KEV
def test_kev_feed_is_validated():
    catalog = parse_kev_feed(load("kev_feed.json"))
    assert set(catalog.entries) == {"CVE-2099-0001", "CVE-2099-0100", "CVE-2099-0200"}
    assert catalog.entries["CVE-2099-0001"] == "2099-03-01"
    assert catalog.entries["CVE-2099-0200"] is None  # malformed dateAdded is dropped, entry kept
    assert catalog.catalog_version == "2099.03.01"


def test_kev_lookup_by_any_identifier():
    catalog = parse_kev_feed(load("kev_feed.json"))
    assert catalog.lookup(["GHSA-fx01-fx01-fx01", "cve-2099-0001"]) == ("CVE-2099-0001", "2099-03-01")
    assert catalog.lookup(["CVE-2099-9999", None, 5]) is None


@pytest.mark.parametrize("feed", [
    {"vulnerabilities": []},
    {"vulnerabilities": [{"cveID": "not-a-cve"}, "x"]},
    {"vulnerabilities": "nope"},
    {"catalogVersion": "1"},
    [],
    None,
])
def test_empty_or_malformed_kev_feed_is_an_error_not_an_empty_catalog(feed):
    with pytest.raises(ValueError):
        parse_kev_feed(feed)


def test_kev_catalog_fetched_once_then_served_from_memo_and_cache():
    cache = MemoryCache()
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        client = kev_client(cache)
        assert len(client.catalog()) == 3
        assert len(client.catalog()) == 3
        # A second process/client sharing the cache does not refetch either.
        assert len(kev_client(cache).catalog()) == 3
    assert route.call_count == 1
    assert cache.ttls[KEV_CACHE_KEY] == 43200


def test_kev_memo_expires_with_ttl():
    cache = MemoryCache()
    now = {"t": 1000.0}
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        client = kev_client(cache, ttl=60, clock=lambda: now["t"])
        client.catalog()
        cache.data.clear()  # shared cache entry expired as well
        now["t"] += 61
        client.catalog()
    assert route.call_count == 2


def test_kev_http_failure_raises_and_caches_nothing():
    cache = MemoryCache()
    with respx.mock() as router:
        router.get(KEV_URL).mock(return_value=httpx.Response(503))
        with pytest.raises(IntelSourceError) as exc:
            kev_client(cache).catalog()
    assert exc.value.source == "cisa-kev"
    assert cache.data == {}


def test_kev_failed_fetch_is_not_retried_by_every_caller_during_backoff():
    cache = MemoryCache()
    now = {"t": 1000.0}
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(503))
        client = kev_client(cache, clock=lambda: now["t"])
        with pytest.raises(IntelSourceError):
            client.catalog()
        assert route.call_count == 3  # one attempt + two retries
        now["t"] += 30
        with pytest.raises(IntelSourceError) as suppressed:
            client.catalog()
        assert route.call_count == 3  # still an error for the caller, but no new requests
        assert suppressed.value.kind == "status" and "retry suppressed" in str(suppressed.value)
        route.mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        now["t"] += 31  # backoff elapsed
        assert len(client.catalog()) == 3
        assert route.call_count == 4


def test_kev_backoff_still_uses_a_catalog_another_process_cached():
    cache = MemoryCache()
    with respx.mock() as router:
        router.get(KEV_URL).mock(return_value=httpx.Response(503))
        client = kev_client(cache)
        with pytest.raises(IntelSourceError):
            client.catalog()
        cache.set_json(KEV_CACHE_KEY, parse_kev_feed(load("kev_feed.json")).to_cache(), 60)
        assert "CVE-2099-0001" in client.catalog().entries


def test_kev_memo_from_a_shared_entry_expires_with_the_entrys_age():
    """Regression: a catalog read from the shared cache was memoised for a fresh TTL from the read time,
    so a nearly expired entry could be served for almost twice the configured TTL."""
    cache = MemoryCache()
    ttl = 3600
    wall = {"t": 50_000.0}
    mono = {"t": 10.0}
    payload = {**parse_kev_feed(load("kev_feed.json")).to_cache(), "fetched_at": wall["t"] - (ttl - 10)}
    cache.set_json(KEV_CACHE_KEY, payload, ttl)
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        client = KevClient(_http("cisa-kev", KEV_URL), IntelCache(cache), feed_url=KEV_URL, ttl_seconds=ttl,
                           clock=lambda: mono["t"], wall_clock=lambda: wall["t"])
        assert len(client.catalog()) == 3 and route.call_count == 0  # served from the shared entry
        mono["t"] += 9
        wall["t"] += 9
        client.catalog()
        assert route.call_count == 0  # still within the entry's remaining 10 s
        mono["t"] += 2
        wall["t"] += 2
        client.catalog()  # the shared entry is now older than the TTL: refetched, not re-memoised
        assert route.call_count == 1
    assert json.loads(cache.data[KEV_CACHE_KEY])["fetched_at"] == wall["t"]


def test_kev_undated_shared_entry_is_memoised_only_briefly():
    cache = MemoryCache()
    cache.set_json(KEV_CACHE_KEY, parse_kev_feed(load("kev_feed.json")).to_cache(), 43200)  # older format
    mono = {"t": 0.0}
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        client = kev_client(cache, clock=lambda: mono["t"])
        client.catalog()
        cache.data.clear()
        mono["t"] += 301
        client.catalog()
    assert route.call_count == 1


def test_kev_tampered_cache_entry_is_ignored():
    cache = MemoryCache()
    cache.set_json(KEV_CACHE_KEY, {"entries": {"<script>": "x", "CVE-1": "y"}}, 60)
    assert catalog_from_cache(cache.get_json(KEV_CACHE_KEY)) is None
    with respx.mock() as router:
        route = router.get(KEV_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        catalog = kev_client(cache).catalog()
    assert route.call_count == 1 and "CVE-2099-0001" in catalog.entries


# --------------------------------------------------------------------------- EPSS
def test_epss_scores_parsed_from_strings():
    cache = MemoryCache()
    with respx.mock() as router:
        route = router.get(EPSS_URL).mock(return_value=httpx.Response(200, json=load("epss_response.json")))
        result = epss_client(cache).lookup(["CVE-2099-0001", "cve-2099-0002", "CVE-2099-0003", "not-a-cve"])
    assert route.calls[0].request.url.params["cve"] == "CVE-2099-0001,CVE-2099-0002,CVE-2099-0003"
    assert result.scores["CVE-2099-0001"].epss == pytest.approx(0.91234)
    assert result.scores["CVE-2099-0001"].percentile == pytest.approx(0.99876)
    assert result.scores["CVE-2099-0001"].date == "2099-03-02"
    assert "CVE-2099-0002" not in result.scores  # EPSS has no score for it...
    assert result.resolved == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}  # ...which is an answer
    assert result.errors == []


def test_epss_requests_carry_at_most_100_cves():
    cache = MemoryCache()
    cves = [f"CVE-2099-{n:04d}" for n in range(1, 251)]
    with respx.mock() as router:
        route = router.get(EPSS_URL).mock(return_value=httpx.Response(200, json={"status": "OK", "total": 0,
                                                                                 "data": []}))
        result = epss_client(cache).lookup(cves)
    sizes = [len(c.request.url.params["cve"].split(",")) for c in route.calls]
    assert sizes == [100, 100, 50]
    assert result.resolved == set(cves)


def test_epss_answers_are_cached_per_cve_including_not_scored():
    cache = MemoryCache()
    with respx.mock() as router:
        route = router.get(EPSS_URL).mock(return_value=httpx.Response(200, json=load("epss_response.json")))
        epss_client(cache).lookup(["CVE-2099-0001", "CVE-2099-0002"])
        again = epss_client(cache).lookup(["CVE-2099-0002", "CVE-2099-0001"])
    assert route.call_count == 1
    assert again.resolved == {"CVE-2099-0001", "CVE-2099-0002"}
    assert again.scores["CVE-2099-0001"].epss == pytest.approx(0.91234)
    assert cache.ttls[cache_key("epss:v1", "CVE-2099-0002")] == 86400


def test_epss_rejects_out_of_range_and_unrequested_values():
    cache = MemoryCache()
    hostile = {"status": "OK", "total": 3, "data": [
        {"cve": "CVE-2099-0001", "epss": "1.5", "percentile": "0.5"},
        {"cve": "CVE-2099-0002", "epss": "nan"},
        {"cve": "CVE-2099-7777", "epss": "0.5"},
    ]}
    with respx.mock() as router:
        router.get(EPSS_URL).mock(return_value=httpx.Response(200, json=hostile))
        result = epss_client(cache).lookup(["CVE-2099-0001", "CVE-2099-0002"])
    assert result.scores == {}
    assert result.resolved == set()  # present-but-invalid is not "not scored"
    assert cache.data == {}


def test_epss_truncated_response_leaves_missing_cves_unresolved():
    cache = MemoryCache()
    truncated = {"status": "OK", "total": 5, "data": [{"cve": "CVE-2099-0001", "epss": "0.1", "percentile": "0.2"}]}
    with respx.mock() as router:
        router.get(EPSS_URL).mock(return_value=httpx.Response(200, json=truncated))
        result = epss_client(cache).lookup(["CVE-2099-0001", "CVE-2099-0002"])
    assert result.resolved == {"CVE-2099-0001"}
    assert result.errors and "truncated" in result.errors[0]
    assert cache_key("epss:v1", "CVE-2099-0002") not in cache.data


def test_epss_integer_too_large_for_a_float_is_rejected_without_crashing():
    body = b'{"status": "OK", "total": 1, "data": [{"cve": "CVE-2099-0001", "epss": 1' + b"0" * 400 + b"}]}"
    with respx.mock() as router:
        router.get(EPSS_URL).mock(return_value=httpx.Response(200, content=body))
        result = epss_client(MemoryCache()).lookup(["CVE-2099-0001"])
    assert result.scores == {} and result.resolved == set()


@pytest.mark.parametrize("response", [
    httpx.Response(200, json={"status": "error", "data": []}),
    httpx.Response(200, json=["not", "an", "object"]),
    httpx.Response(200, content=b"<html>not json</html>"),
    httpx.Response(500),
])
def test_epss_failures_are_reported(response):
    with respx.mock() as router:
        router.get(EPSS_URL).mock(return_value=response)
        result = epss_client(MemoryCache()).lookup(["CVE-2099-0001"])
    assert result.errors
    assert result.resolved == set() and result.scores == {}


# --------------------------------------------------------------------------- NVD
def test_nvd_parser_prefers_primary_and_recomputes_the_score():
    data = load("nvd_cve.json")
    scored = parse_cve_response(data, "CVE-2099-0002")
    assert (scored.base_score, scored.version) == (6.1, "3.1")
    assert scored.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    tampered = copy.deepcopy(data)
    tampered["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][1]["cvssData"]["baseScore"] = 0.1
    assert parse_cve_response(tampered, "CVE-2099-0002").base_score == 6.1  # the vector, not the number, counts
    assert parse_cve_response(data, "CVE-2099-0003") is None  # a different CVE's record is never used
    with pytest.raises(ValueError):
        parse_cve_response({"unexpected": True}, "CVE-2099-0002")


def test_nvd_sends_api_key_only_as_header():
    cache = MemoryCache()
    with respx.mock() as router:
        route = router.get(NVD_URL).mock(return_value=httpx.Response(200, json=load("nvd_cve.json")))
        scored = nvd_client(cache, NVD_KEY).cvss_for("CVE-2099-0002")
    request = route.calls[0].request
    assert request.headers["apiKey"] == NVD_KEY
    assert NVD_KEY not in str(request.url)
    assert request.url.params["cveId"] == "CVE-2099-0002"
    assert scored.base_score == 6.1
    assert NVD_KEY not in json.dumps(cache.data)


def test_nvd_without_key_sends_no_key_header():
    with respx.mock() as router:
        route = router.get(NVD_URL).mock(return_value=httpx.Response(200, json=load("nvd_cve.json")))
        nvd_client(MemoryCache()).cvss_for("CVE-2099-0002")
    assert "apiKey" not in route.calls[0].request.headers


def test_nvd_api_key_never_leaks_into_errors_repr_or_logs(capsys):
    client = nvd_client(MemoryCache(), NVD_KEY)
    with respx.mock() as router:
        router.get(NVD_URL).mock(return_value=httpx.Response(403, json={"message": "forbidden"}))
        with pytest.raises(IntelSourceError) as exc:
            client.cvss_for("CVE-2099-0002")
        router.get(NVD_URL).mock(side_effect=httpx.ConnectError(f"connect failed apiKey={NVD_KEY}"))
        with pytest.raises(IntelSourceError) as exc2:
            client.cvss_for("CVE-2099-0002")
    captured = capsys.readouterr()
    for text in (str(exc.value), str(exc2.value), repr(client), captured.out, captured.err):
        assert NVD_KEY not in text


def test_nvd_negative_answer_is_cached():
    cache = MemoryCache()
    no_metrics = {"vulnerabilities": [{"cve": {"id": "CVE-2099-0003", "metrics": {}}}]}
    with respx.mock() as router:
        route = router.get(NVD_URL).mock(return_value=httpx.Response(200, json=no_metrics))
        client = nvd_client(cache)
        assert client.cvss_for("CVE-2099-0003") is None
        assert client.cvss_for("CVE-2099-0003") is None
    assert route.call_count == 1


@pytest.mark.parametrize("bad", ["CVE-XXXX&apiKey=steal", "CVE-2099-0001\n&x=1", "", None])
def test_nvd_rejects_invalid_cve_without_a_request(bad):
    with respx.mock() as router:
        with pytest.raises(IntelSourceError):
            nvd_client(MemoryCache()).cvss_for(bad)
        # Asserted inside the block: respx resets recorded calls when the mock context exits.
        assert router.calls.call_count == 0
