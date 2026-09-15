"""OSV client and advisory parser (offline: HTTP mocked with respx, synthetic fixtures)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from app.intel.client import IntelCache, IntelSourceError, build_http_client, cache_key
from app.intel.osv import (
    MAX_AFFECTED_ENTRIES,
    MAX_EVENTS_PER_RANGE,
    MAX_EVENTS_PER_RECORD,
    MAX_PAGES_PER_QUERY,
    OsvClient,
    OsvQuery,
    normalize_package_name,
    osv_ecosystem,
    parse_vulnerability,
    trim_record,
)

DATA = Path(__file__).parent / "data" / "intel"
OSV = "https://api.osv.dev"
PKG = "warden-fixture-pkg"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


class MemoryCache:
    """In-memory stand-in for app.core.cache.cache (JSON round-trip like the real one)."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    def get_json(self, key):
        raw = self.data.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.data[key] = json.dumps(value, default=str)
        self.ttls[key] = ttl


def make_client(cache: MemoryCache | None = None, *, max_bytes: int = 2_000_000) -> tuple[OsvClient, MemoryCache]:
    cache = cache or MemoryCache()
    http = build_http_client("osv", OSV, timeout=5, rate_limit_per_second=None, max_response_bytes=max_bytes,
                             sleep=lambda _s: None)
    return OsvClient(http, IntelCache(cache), base_url=OSV, ttl_seconds=3600), cache


def _empty_results(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(200, json={"results": [{} for _ in body["queries"]]})


# --------------------------------------------------------------------------- parsing
def test_parse_github_advisory_for_the_queried_package_only():
    vuln = parse_vulnerability(load("osv_vuln_GHSA-fx01-fx01-fx01.json"), ecosystem="PyPI", name=PKG)
    assert vuln is not None
    assert vuln.id == "GHSA-fx01-fx01-fx01"
    assert vuln.aliases == ["CVE-2099-0001"]
    assert vuln.cve_ids() == ["CVE-2099-0001"]
    assert vuln.summary == "Synthetic fixture: remote code execution in warden-fixture-pkg"
    assert (vuln.cvss_score, vuln.cvss_version, vuln.severity) == (9.8, "3.1", "critical")
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vuln.database_specific_severity == "CRITICAL"
    assert (vuln.published, vuln.modified) == ("2099-01-01T00:00:00Z", "2099-01-05T10:00:00Z")
    # The affected entry is named "Warden_Fixture.Pkg": PEP 503 normalisation must match it,
    # the GIT range is ignored, and the unrelated package's fix (9.9.9) must not leak in.
    assert vuln.affected_ranges == [
        {"type": "ECOSYSTEM", "introduced": "0", "fixed": "1.0.5", "last_affected": None},
        {"type": "ECOSYSTEM", "introduced": "2.0.0", "fixed": "2.0.3", "last_affected": None},
    ]
    assert vuln.fixed_versions == ["1.0.5", "2.0.3"]
    assert vuln.withdrawn is False
    assert vuln.sources == ["osv"]


def test_references_are_capped_prioritised_and_http_only():
    vuln = parse_vulnerability(load("osv_vuln_GHSA-fx01-fx01-fx01.json"), ecosystem="PyPI", name=PKG)
    assert len(vuln.references) == 10
    assert vuln.references[0] == "https://example.invalid/advisory/GHSA-fx01-fx01-fx01"
    assert vuln.references[1] == "https://example.invalid/fix/1"
    assert all(r.startswith("https://") for r in vuln.references)
    assert not any("javascript" in r for r in vuln.references)


def test_record_without_summary_or_severity():
    vuln = parse_vulnerability(load("osv_vuln_PYSEC-2099-1.json"), ecosystem="PyPI", name=PKG)
    assert vuln.summary == "Synthetic fixture: path traversal in archive helper."
    assert vuln.severity == "unknown"
    assert vuln.cvss_score is None and vuln.cvss_vector is None
    assert vuln.affected_ranges == [{"type": "ECOSYSTEM", "introduced": "0.5", "fixed": None, "last_affected": "1.0.0"}]
    assert vuln.fixed_versions == []
    assert vuln.cve_ids() == ["CVE-2099-0002"]


def test_cvss_v4_vector_is_carried_not_scored_and_database_severity_is_used():
    vuln = parse_vulnerability(load("osv_vuln_GHSA-fx03-fx03-fx03.json"), ecosystem="PyPI", name=PKG)
    assert vuln.cvss_score is None
    assert vuln.cvss_version == "4.0"
    assert vuln.cvss_vector.startswith("CVSS:4.0/")
    assert vuln.database_specific_severity == "MODERATE"
    assert vuln.severity == "medium"


def test_withdrawn_advisory_is_flagged():
    vuln = parse_vulnerability(load("osv_vuln_GHSA-fx02-fx02-fx02.json"), ecosystem="PyPI", name=PKG)
    assert vuln.withdrawn is True


def test_highest_cvss_v3_version_wins_and_affected_level_severity_is_read():
    record = {
        "id": "GHSA-mix0-mix0-mix0",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z"},  # invalid: ignored
        ],
        "affected": [{"package": {"ecosystem": "PyPI", "name": PKG},
                      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}]}],
        "database_specific": {"severity": "LOW"},
    }
    vuln = parse_vulnerability(record, ecosystem="PyPI", name=PKG)
    assert (vuln.cvss_version, vuln.cvss_score, vuln.severity) == ("3.1", 7.8, "high")
    assert vuln.database_specific_severity == "LOW"  # carried, but the computed CVSS rating wins


def test_hostile_record_is_sanitised_and_bounded():
    record = {
        "id": "GHSA-evil-evil-evil",
        "aliases": ["../../etc/passwd", "CVE-2099-0042", "CVE-2099-0042", 7],
        "summary": "\x1b[31mred‮evil AKIAIOSFODNN7EXAMPLE " + "A" * 5000,
        "severity": "not-a-list",
        "affected": ["junk", {"package": {"ecosystem": "PyPI", "name": PKG},
                              "ranges": [{"type": "ECOSYSTEM", "events": ["junk", {"introduced": "0", "fixed": "1"},
                                                                          {"fixed": {"nested": 1}}]}]}],
        "references": [{"type": "ADVISORY", "url": "data:text/html,<script>alert(1)</script>"},
                       {"type": "WEB", "url": "https://example.invalid/" + "x" * 1000},
                       {"type": "WEB", "url": 12}],
    }
    vuln = parse_vulnerability(record, ecosystem="PyPI", name=PKG)
    assert vuln is not None
    assert vuln.aliases == ["CVE-2099-0042"]
    assert "\x1b" not in vuln.summary and "‮" not in vuln.summary
    assert "AKIAIOSFODNN7EXAMPLE" not in vuln.summary
    assert len(vuln.summary) <= 500
    assert vuln.references == []
    assert vuln.affected_ranges == []  # multi-key and non-string events are rejected, not guessed


@pytest.mark.parametrize("record", [[], "x", None, {"id": "../x"}, {"id": 5}, {}])
def test_unusable_records_return_none(record):
    assert parse_vulnerability(record, ecosystem="PyPI", name=PKG) is None


def test_name_normalisation_and_ecosystem_mapping():
    assert normalize_package_name("PyPI", "Warden_Fixture.Pkg") == "warden-fixture-pkg"
    assert normalize_package_name("npm", "@Scope/Pkg") == "@Scope/Pkg"
    assert osv_ecosystem("pypi") == "PyPI"
    assert osv_ecosystem("PyPI") == "PyPI"
    assert osv_ecosystem("conda") is None
    assert osv_ecosystem(None) is None


def test_trim_record_drops_unused_bulk():
    trimmed = trim_record(load("osv_vuln_GHSA-fx01-fx01-fx01.json"))
    assert "versions" not in json.dumps(trimmed["affected"])
    assert all(r["type"] in ("ECOSYSTEM", "SEMVER") for a in trimmed["affected"] for r in a["ranges"])
    # Parsing the trimmed record gives the same answer as parsing the full one.
    full = parse_vulnerability(load("osv_vuln_GHSA-fx01-fx01-fx01.json"), ecosystem="PyPI", name=PKG)
    assert parse_vulnerability(trimmed, ecosystem="PyPI", name=PKG) == full


# --------------------------------------------------------------------------- querybatch
def test_query_batch_request_shape_and_results():
    client, cache = make_client()
    with respx.mock(assert_all_called=False) as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=load(
            "osv_querybatch.json")))
        outcomes = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0"), OsvQuery("PyPI", "warden-clean-fixture", "3.1")])
    body = json.loads(route.calls[0].request.content)
    assert body == {"queries": [
        {"package": {"ecosystem": "PyPI", "name": PKG}, "version": "1.0.0"},
        {"package": {"ecosystem": "PyPI", "name": "warden-clean-fixture"}, "version": "3.1"},
    ]}
    assert [vid for vid, _ in outcomes[0].vulns] == [
        "GHSA-fx01-fx01-fx01", "PYSEC-2099-1", "GHSA-fx02-fx02-fx02", "GHSA-fx03-fx03-fx03"]
    assert outcomes[0].vulns[0][1] == "2099-01-05T10:00:00Z"
    assert outcomes[1].vulns == [] and outcomes[1].error is None and outcomes[1].incomplete is None


def test_query_results_are_cached_including_negative_answers():
    client, cache = make_client()
    with respx.mock() as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=load(
            "osv_querybatch.json")))
        queries = [OsvQuery("PyPI", PKG, "1.0.0"), OsvQuery("PyPI", "warden-clean-fixture", "3.1")]
        first = client.query_batch(queries)
        # A differently-spelled but PEP 503-equivalent name hits the same cache entry.
        second = client.query_batch([OsvQuery("PyPI", "Warden_Fixture.Pkg", "1.0.0"), queries[1]])
    assert route.call_count == 1
    assert [o.vulns for o in first] == [o.vulns for o in second]
    assert set(cache.ttls.values()) == {3600}


def test_queries_are_chunked_at_1000():
    client, _ = make_client()
    with respx.mock() as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(side_effect=_empty_results)
        outcomes = client.query_batch([OsvQuery("PyPI", f"pkg-{n}", "1.0") for n in range(1500)])
    sizes = [len(json.loads(c.request.content)["queries"]) for c in route.calls]
    assert sizes == [1000, 500]
    assert len(outcomes) == 1500 and all(o.error is None for o in outcomes)


def test_next_page_token_is_followed_for_that_query_only():
    client, cache = make_client()
    pages = [
        {"results": [{"vulns": [{"id": "GHSA-page-0001-aaaa", "modified": "m1"}], "next_page_token": "tok-1"}, {}]},
        {"results": [{"vulns": [{"id": "GHSA-page-0002-bbbb", "modified": "m2"}]}]},
    ]
    with respx.mock() as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(
            side_effect=[httpx.Response(200, json=p) for p in pages])
        outcomes = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0"), OsvQuery("PyPI", "other", "1.0")])
    second_body = json.loads(route.calls[1].request.content)
    assert second_body == {"queries": [{"package": {"ecosystem": "PyPI", "name": PKG}, "version": "1.0.0",
                                        "page_token": "tok-1"}]}
    assert [vid for vid, _ in outcomes[0].vulns] == ["GHSA-page-0001-aaaa", "GHSA-page-0002-bbbb"]
    assert outcomes[0].incomplete is None
    assert len(cache.data) == 2  # both complete answers cached


def test_repeated_page_token_cannot_loop_forever():
    client, cache = make_client()
    looping = {"results": [{"vulns": [{"id": "GHSA-loop-0001-aaaa"}], "next_page_token": "same"}]}
    with respx.mock() as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=looping))
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
    assert route.call_count == 2
    assert outcome.incomplete == "pagination limit reached"
    assert [vid for vid, _ in outcome.vulns] == ["GHSA-loop-0001-aaaa"]
    assert cache.data == {}  # incomplete answers are never cached


def test_pagination_is_bounded():
    client, _ = make_client()
    counter = {"n": 0}

    def endless(request):
        counter["n"] += 1
        return httpx.Response(200, json={"results": [{"vulns": [], "next_page_token": f"t{counter['n']}"}]})

    with respx.mock() as router:
        router.post(f"{OSV}/v1/querybatch").mock(side_effect=endless)
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
    assert counter["n"] == MAX_PAGES_PER_QUERY
    assert outcome.incomplete == "pagination limit reached"


def test_misaligned_results_are_rejected_for_every_query():
    client, cache = make_client()
    bad = {"results": [{"vulns": [{"id": "GHSA-fx01-fx01-fx01"}]}]}  # 1 result for 2 queries
    with respx.mock() as router:
        router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=bad))
        outcomes = client.query_batch([OsvQuery("PyPI", "a", "1"), OsvQuery("PyPI", "b", "1")])
    assert all(o.error and "does not match" in o.error for o in outcomes)
    assert all(o.vulns == [] for o in outcomes)
    assert cache.data == {}


def test_invalid_advisory_ids_are_dropped_and_flagged():
    client, cache = make_client()
    hostile = {"results": [{"vulns": [{"id": "../../v1/admin"}, {"id": "GHSA ok?x=1"}, "junk",
                                      {"id": "GHSA-good-good-good"}]}]}
    with respx.mock() as router:
        router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=hostile))
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
    assert [vid for vid, _ in outcome.vulns] == ["GHSA-good-good-good"]
    assert outcome.incomplete is not None
    assert cache.data == {}


def test_network_failure_is_an_error_not_an_empty_answer():
    client, cache = make_client()
    with respx.mock() as router:
        route = router.post(f"{OSV}/v1/querybatch").mock(side_effect=httpx.ConnectError("boom"))
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
    assert route.call_count == 3  # initial attempt + 2 retries
    assert outcome.error is not None and "network" in outcome.error
    assert cache.data == {}


def test_redirect_to_another_host_is_refused():
    client, _ = make_client()
    # assert_all_called=False: the evil route exists only to prove it is never reached.
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{OSV}/v1/querybatch").mock(
            return_value=httpx.Response(307, headers={"Location": "https://evil.example/v1/querybatch"}))
        evil = router.post("https://evil.example/v1/querybatch").mock(return_value=httpx.Response(200, json={}))
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
        assert evil.call_count == 0
    assert "host not allowed" in outcome.error


def test_oversized_response_is_refused():
    client, _ = make_client(max_bytes=1000)
    big = {"results": [{"vulns": [{"id": f"GHSA-big{n:04d}-aaaa"} for n in range(500)]}]}
    with respx.mock() as router:
        router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json=big))
        (outcome,) = client.query_batch([OsvQuery("PyPI", PKG, "1.0.0")])
    assert outcome.error is not None and "exceeds" in outcome.error


# --------------------------------------------------------------------------- hydration
def test_get_vulnerability_hydrates_and_caches():
    client, cache = make_client()
    vid = "GHSA-fx01-fx01-fx01"
    with respx.mock() as router:
        route = router.get(f"{OSV}/v1/vulns/{vid}").mock(return_value=httpx.Response(200, json=load(
            f"osv_vuln_{vid}.json")))
        first = client.get_vulnerability(vid, "2099-01-05T10:00:00Z")
        second = client.get_vulnerability(vid, "2099-01-05T10:00:00Z")
    assert route.call_count == 1
    assert first == second and first["id"] == vid
    assert cache.ttls[cache_key("osv:vuln:v1", vid)] == 3600


def test_cached_record_is_refetched_when_modified_changes():
    client, cache = make_client()
    vid = "GHSA-fx01-fx01-fx01"
    record = load(f"osv_vuln_{vid}.json")
    updated = dict(record, modified="2099-06-01T00:00:00Z", summary="Synthetic fixture: updated")
    with respx.mock() as router:
        route = router.get(f"{OSV}/v1/vulns/{vid}").mock(
            side_effect=[httpx.Response(200, json=record), httpx.Response(200, json=updated)])
        client.get_vulnerability(vid, record["modified"])
        fresh = client.get_vulnerability(vid, "2099-06-01T00:00:00Z")
    assert route.call_count == 2
    assert fresh["summary"] == "Synthetic fixture: updated"


def test_get_vulnerability_not_found_raises():
    client, _ = make_client()
    with respx.mock() as router:
        router.get(f"{OSV}/v1/vulns/GHSA-gone-gone-gone").mock(return_value=httpx.Response(404, json={}))
        with pytest.raises(IntelSourceError) as exc:
            client.get_vulnerability("GHSA-gone-gone-gone")
    assert exc.value.source == "osv"


def test_record_with_a_different_id_is_rejected_and_not_cached():
    client, cache = make_client()
    impostor = load("osv_vuln_GHSA-fx01-fx01-fx01.json")
    with respx.mock() as router:
        router.get(f"{OSV}/v1/vulns/GHSA-fx03-fx03-fx03").mock(return_value=httpx.Response(200, json=impostor))
        with pytest.raises(IntelSourceError) as exc:
            client.get_vulnerability("GHSA-fx03-fx03-fx03")
    assert exc.value.kind == "invalid"
    assert cache.data == {}


@pytest.mark.parametrize("bad_id", ["../secrets", "GHSA/../../x", "id?x=1", "", "a" * 200])
def test_invalid_ids_are_never_requested(bad_id):
    client, _ = make_client()
    with respx.mock() as router:
        with pytest.raises(IntelSourceError):
            client.get_vulnerability(bad_id)
        assert router.calls.call_count == 0  # inside the block: respx resets recorded calls on exit


# --------------------------------------------------------------------------- canonical record form
def _huge_hostile_record() -> dict:
    events = [{"introduced": "0"}, {"fixed": "1.0.5"}] * 60  # 120 events per range
    entry = {"package": {"ecosystem": "PyPI", "name": PKG, "extra": "x" * 1000},
             "ranges": [{"type": "ECOSYSTEM", "events": events}] * 2, "versions": ["1.0.0"] * 500}
    return {
        "id": "GHSA-huge-0001-aaaa",
        "modified": "2099-01-01T00:00:00Z",
        "published": "2" * 5000,  # absurd timestamp: dropped, never truncated into a fake one
        "withdrawn": {"nested": True},
        "aliases": ["bad id"] * 2000 + ["CVE-2099-0077"],  # beyond the scan window: ignored
        "summary": "Synthetic fixture " + "S" * 200_000,
        "details": "D" * 200_000,
        "severity": [{"type": "CVSS_V3", "score": "X" * 5000}] * 500
        + [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "HIGH", "blob": "B" * 100_000},
        # First entry: an unhashable range "type" (a set-membership test on it would raise TypeError).
        "affected": [{"package": {"name": PKG}, "ranges": [{"type": ["ECOSYSTEM"], "events": []}]}] + [entry] * 250,
        "references": [{"type": "WEB", "url": "https://example.invalid/" + "r" * 600}] * 1000
        + [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}] * 200,
    }


def test_trim_record_bounds_a_huge_hostile_record():
    raw = _huge_hostile_record()
    trimmed = trim_record(raw)
    assert len(json.dumps(trimmed)) < 400_000  # the raw record is several megabytes
    assert len(trimmed["affected"]) == MAX_AFFECTED_ENTRIES
    events = [e for a in trimmed["affected"] for r in a["ranges"] for e in r["events"]]
    assert len(events) == MAX_EVENTS_PER_RECORD
    assert all(len(r["events"]) <= MAX_EVENTS_PER_RANGE for a in trimmed["affected"] for r in a["ranges"])
    assert trimmed["published"] is None and trimmed["withdrawn"] is True
    assert trimmed["aliases"] == []
    # Oversized vectors are dropped (not truncated into something that might parse); the valid one is kept.
    assert trimmed["severity"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert trimmed["affected"][0]["ranges"] == []
    assert all(len(r["url"]) <= 500 for r in trimmed["references"])
    assert "extra" not in json.dumps(trimmed) and "blob" not in json.dumps(trimmed)


def test_trim_record_is_idempotent_and_parsing_is_unchanged_by_it():
    for raw in (_huge_hostile_record(), load("osv_vuln_GHSA-fx01-fx01-fx01.json"), load("osv_vuln_PYSEC-2099-1.json")):
        trimmed = trim_record(raw)
        assert trim_record(trimmed) == trimmed
        assert parse_vulnerability(trimmed, ecosystem="PyPI", name=PKG) == parse_vulnerability(
            raw, ecosystem="PyPI", name=PKG)


def test_parse_survives_unhashable_range_types_and_bounds_output():
    vuln = parse_vulnerability(_huge_hostile_record(), ecosystem="PyPI", name=PKG)
    assert vuln is not None
    assert len(vuln.summary) <= 500 and vuln.published is None
    assert (vuln.cvss_score, vuln.severity) == (9.8, "critical")
    assert vuln.references == ["https://example.invalid/advisory"]
    assert vuln.fixed_versions == ["1.0.5"]
    assert len(vuln.affected_ranges) == 20


def test_cached_hydrated_record_is_the_bounded_form():
    client, cache = make_client(max_bytes=64 * 1024 * 1024)
    raw = _huge_hostile_record()
    with respx.mock() as router:
        router.get(f"{OSV}/v1/vulns/GHSA-huge-0001-aaaa").mock(return_value=httpx.Response(200, json=raw))
        record = client.get_vulnerability("GHSA-huge-0001-aaaa")
    stored = cache.data[cache_key("osv:vuln:v1", "GHSA-huge-0001-aaaa")]
    assert len(stored) < 400_000
    assert json.loads(stored) == record == trim_record(raw)
