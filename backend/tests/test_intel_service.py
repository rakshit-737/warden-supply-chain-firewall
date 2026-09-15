"""IntelService: status semantics, enrichment, caching and configuration switches (offline, respx).

Note on respx: the mock router rolls back its routes and recorded calls when the ``with``
block exits, so every assertion about ``router.calls`` / ``router.routes`` is made inside the
block (asserting after it would pass vacuously).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from app.core.config import settings
from app.intel import service as service_module
from app.intel.models import IntelResult, IntelStatus, Vulnerability, merge_aliased, normalize_severity
from app.intel.service import IntelService, get_intel_service, reset_intel_service

DATA = Path(__file__).parent / "data" / "intel"
OSV = settings.OSV_API_BASE
PKG = "warden-fixture-pkg"
FIXTURE_IDS = ("GHSA-fx01-fx01-fx01", "PYSEC-2099-1", "GHSA-fx02-fx02-fx02", "GHSA-fx03-fx03-fx03")
NVD_KEY = "nvd-fixture-key-0123456789abcdef"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


class MemoryCache:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get_json(self, key):
        raw = self.data.get(key)
        return json.loads(raw) if raw else None

    def set_json(self, key, value, ttl):
        self.data[key] = json.dumps(value, default=str)


class BrokenCache:
    def get_json(self, key):
        raise ConnectionError("redis down")

    def set_json(self, key, value, ttl):
        raise ConnectionError("redis down")


def make_service(cache=None, **overrides) -> IntelService:
    config = settings.model_copy(update={
        "INTEL_ENABLED": True, "INTEL_OFFLINE": False, "NVD_ENABLED": False, "NVD_API_KEY": None,
        "INTEL_RATE_LIMIT_PER_SECOND": 1000.0, **overrides,
    })
    return IntelService(config=config, cache=cache if cache is not None else MemoryCache(), sleep=lambda _s: None)


def _querybatch(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    results = []
    for q in body["queries"]:
        if q["package"]["name"] == PKG and q["version"] == "1.0.0":
            results.append(load("osv_querybatch.json")["results"][0])
        else:
            results.append({})
    return httpx.Response(200, json={"results": results})


def install_routes(router: respx.MockRouter) -> None:
    router.post(f"{OSV}/v1/querybatch", name="querybatch").mock(side_effect=_querybatch)
    for vid in FIXTURE_IDS:
        router.get(f"{OSV}/v1/vulns/{vid}", name=vid).mock(
            return_value=httpx.Response(200, json=load(f"osv_vuln_{vid}.json")))
    router.get(settings.KEV_FEED_URL, name="kev").mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
    router.get(settings.EPSS_API_BASE, name="epss").mock(
        return_value=httpx.Response(200, json=load("epss_response.json")))


def _by_id(result: IntelResult) -> dict[str, Vulnerability]:
    return {v.id: v for v in result.vulnerabilities}


# --------------------------------------------------------------------------- switches
def test_disabled_intel_touches_no_network():
    svc = make_service(INTEL_ENABLED=False)
    with respx.mock() as router:
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert router.calls.call_count == 0
    assert svc._owned == []  # no HTTP client was even constructed
    assert result.status == IntelStatus.DISABLED
    assert set(result.sources.values()) == {"disabled"}
    assert result.vulnerabilities == []
    assert not result.degraded


def test_offline_intel_touches_no_network():
    svc = make_service(INTEL_OFFLINE=True)
    with respx.mock() as router:
        results = svc.batch([("pypi", PKG, "1.0.0"), ("pypi", "other", "2.0")])
        assert router.calls.call_count == 0
    assert svc._owned == []
    assert [r.status for r in results] == [IntelStatus.DISABLED, IntelStatus.DISABLED]
    assert svc.mode() == "offline"


def test_singleton_follows_global_settings_and_can_be_reset():
    reset_intel_service()
    try:
        first = get_intel_service()
        assert get_intel_service() is first
        assert first.mode() == "offline"  # the test environment sets INTEL_OFFLINE=true
        replacement = make_service(INTEL_ENABLED=False)
        reset_intel_service(replacement)
        assert get_intel_service() is replacement
    finally:
        reset_intel_service()
    assert service_module._service is None


# --------------------------------------------------------------------------- happy path
def test_full_lookup_is_enriched_and_ok():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert router.routes["GHSA-fx02-fx02-fx02"].call_count == 1  # hydrated, then dropped as withdrawn
        epss_request = router.routes["epss"].calls[0].request
        assert set(epss_request.url.params["cve"].split(",")) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}
    assert result.status == IntelStatus.OK
    assert result.sources == {"osv": "ok", "cisa-kev": "ok", "first-epss": "ok", "nvd": "disabled"}
    assert (result.ecosystem, result.name, result.version) == ("pypi", PKG, "1.0.0")
    vulns = _by_id(result)
    assert sorted(vulns) == ["GHSA-fx01-fx01-fx01", "GHSA-fx03-fx03-fx03", "PYSEC-2099-1"]  # withdrawn excluded
    rce = vulns["GHSA-fx01-fx01-fx01"]
    assert (rce.kev, rce.kev_date_added) == (True, "2099-03-01")
    assert rce.epss_score == pytest.approx(0.91234) and rce.epss_percentile == pytest.approx(0.99876)
    assert rce.sources == ["osv", "cisa-kev", "first-epss"]
    assert vulns["PYSEC-2099-1"].kev is False and vulns["PYSEC-2099-1"].epss_score is None
    assert vulns["GHSA-fx03-fx03-fx03"].epss_score == pytest.approx(0.00123)


def test_result_round_trips_through_dict():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
    payload = json.loads(json.dumps(result.to_dict()))
    assert IntelResult.from_dict(payload) == result


def test_package_without_vulnerabilities_skips_enrichment():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        result = svc.package_vulnerabilities("pypi", "warden-clean-fixture", "3.1.4")
        assert router.routes["querybatch"].call_count == 1
        assert router.routes["kev"].call_count == 0 and router.routes["epss"].call_count == 0
    assert result.status == IntelStatus.OK and result.vulnerabilities == []
    assert result.sources["cisa-kev"] == "skipped" and result.sources["first-epss"] == "skipped"


def test_batch_preserves_order_and_uses_one_querybatch():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        results = svc.batch([
            ("pypi", "warden-clean-fixture", "3.1.4"),
            {"ecosystem": "pypi", "name": PKG, "version": "1.0.0"},
            ("pypi", PKG, "1.0.0"),  # duplicates are allowed and answered independently
        ])
        assert router.routes["querybatch"].call_count == 1
        assert len(json.loads(router.routes["querybatch"].calls[0].request.content)["queries"]) == 3
        assert router.routes["GHSA-fx01-fx01-fx01"].call_count == 1  # each advisory hydrated once per batch
    assert [r.name for r in results] == ["warden-clean-fixture", PKG, PKG]
    assert [len(r.vulnerabilities) for r in results] == [0, 3, 3]
    assert results[1].vulnerabilities is not results[2].vulnerabilities
    assert svc.batch([]) == []


def test_second_lookup_is_served_entirely_from_cache():
    cache = MemoryCache()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        first = make_service(cache).package_vulnerabilities("pypi", PKG, "1.0.0")
        calls_after_first = router.calls.call_count
        second = make_service(cache).package_vulnerabilities("pypi", PKG, "1.0.0")
        assert calls_after_first == 7  # querybatch + 4 advisories + KEV + EPSS
        assert router.calls.call_count == calls_after_first
    assert [v.to_dict() for v in second.vulnerabilities] == [v.to_dict() for v in first.vulnerabilities]
    assert second.status == IntelStatus.OK


def test_cache_outage_degrades_to_live_lookup():
    svc = make_service(BrokenCache())
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
    assert result.status == IntelStatus.OK and len(result.vulnerabilities) == 3


# --------------------------------------------------------------------------- failure semantics
@pytest.mark.parametrize("failure", [
    {"side_effect": httpx.ConnectError("down")},
    {"return_value": httpx.Response(503)},
    {"return_value": httpx.Response(200, content=b"not json")},
    {"return_value": httpx.Response(200, json={"results": []})},  # misaligned
])
def test_osv_failure_is_unavailable_never_clean(failure):
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{OSV}/v1/querybatch").mock(**failure)
        kev = router.get(settings.KEV_FEED_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert kev.call_count == 0
    assert result.status == IntelStatus.UNAVAILABLE
    assert result.vulnerabilities == []
    assert result.degraded and not result.complete
    assert result.sources["osv"] == "error" and result.errors["osv"]
    assert result.sources["cisa-kev"] == "skipped"


def test_hydration_failure_is_partial_and_the_advisory_is_still_reported():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        router.routes["GHSA-fx01-fx01-fx01"].mock(return_value=httpx.Response(500))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
    assert result.status == IntelStatus.PARTIAL
    assert result.sources["osv"] == "partial"
    minimal = _by_id(result)["GHSA-fx01-fx01-fx01"]
    assert minimal.severity == "unknown" and minimal.summary is None
    assert minimal.modified == "2099-01-05T10:00:00Z"


def test_hydration_circuit_breaker_limits_retries_against_a_dead_service():
    ids = [f"GHSA-dead-{n:04d}-aaaa" for n in range(6)]
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(200, json={
            "results": [{"vulns": [{"id": i} for i in ids]}]}))
        vulns_route = router.get(url__regex=r"^https://api\.osv\.dev/v1/vulns/.*").mock(
            side_effect=httpx.ConnectError("down"))
        router.get(settings.KEV_FEED_URL).mock(return_value=httpx.Response(200, json=load("kev_feed.json")))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert vulns_route.call_count == 3 * 3  # three advisories x (1 attempt + 2 retries), then the breaker opens
    assert result.status == IntelStatus.PARTIAL
    assert sorted(v.id for v in result.vulnerabilities) == ids


def test_kev_failure_is_partial():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        router.routes["kev"].mock(return_value=httpx.Response(500))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
    assert result.status == IntelStatus.PARTIAL
    assert result.sources["cisa-kev"] == "error" and "cisa-kev" in result.errors
    assert len(result.vulnerabilities) == 3
    assert not any(v.kev for v in result.vulnerabilities)  # unknown, not asserted either way


def test_epss_failure_is_partial():
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        router.routes["epss"].mock(side_effect=httpx.ConnectError("down"))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
    assert result.status == IntelStatus.PARTIAL
    assert result.sources["first-epss"] == "error"
    assert _by_id(result)["GHSA-fx01-fx01-fx01"].kev is True


@pytest.mark.parametrize(("package", "osv_status"), [
    (("conda", "numpy", "1.0"), "unsupported"),
    (("pypi", PKG, ""), "error"),
    (("pypi", "", "1.0"), "error"),
    (("pypi", "x" * 300, "1.0"), "error"),
])
def test_unqueryable_packages_are_unavailable(package, osv_status):
    svc = make_service()
    with respx.mock() as router:
        result = svc.batch([package])[0]
        assert router.calls.call_count == 0
    assert svc._owned == []
    assert result.status == IntelStatus.UNAVAILABLE
    assert result.sources["osv"] == osv_status


def test_invalid_batch_item_is_a_programming_error():
    with pytest.raises(TypeError):
        make_service().batch([42])


# --------------------------------------------------------------------------- NVD
def _nvd_side_effect(calls: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        cve = request.url.params["cveId"]
        calls.append(cve)
        if cve == "CVE-2099-0002":
            return httpx.Response(200, json=load("nvd_cve.json"))
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {"id": cve, "metrics": {}}}]})
    return handler


def test_nvd_fills_only_missing_scores_when_enabled():
    svc = make_service(NVD_ENABLED=True, NVD_API_KEY=NVD_KEY)
    requested: list[str] = []
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        nvd = router.get(settings.NVD_API_BASE).mock(side_effect=_nvd_side_effect(requested))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert all(c.request.headers["apiKey"] == NVD_KEY for c in nvd.calls)
    assert sorted(requested) == ["CVE-2099-0002", "CVE-2099-0003"]  # GHSA-fx01 already had a CVSS score
    assert result.status == IntelStatus.OK and result.sources["nvd"] == "ok"
    pysec = _by_id(result)["PYSEC-2099-1"]
    assert (pysec.cvss_score, pysec.severity, pysec.cvss_version) == (6.1, "medium", "3.1")
    assert "nvd" in pysec.sources
    v4_only = _by_id(result)["GHSA-fx03-fx03-fx03"]
    assert v4_only.cvss_score is None and v4_only.cvss_version == "4.0" and "nvd" not in v4_only.sources


def test_nvd_failure_is_partial_and_never_leaks_the_key(capsys):
    svc = make_service(NVD_ENABLED=True, NVD_API_KEY=NVD_KEY)
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        nvd = router.get(settings.NVD_API_BASE).mock(return_value=httpx.Response(403))
        result = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert nvd.call_count == 1  # stops after the first failure instead of hammering a refusing API
    assert result.status == IntelStatus.PARTIAL and result.sources["nvd"] == "error"
    captured = capsys.readouterr()
    assert NVD_KEY not in json.dumps(result.to_dict())
    assert NVD_KEY not in captured.out + captured.err
    assert NVD_KEY not in repr(svc._nvd)


# --------------------------------------------------------------------------- model
def test_intel_result_from_dict_fails_closed():
    restored = IntelResult.from_dict({"status": "totally-fine", "sources": {"osv": "great"},
                                      "vulnerabilities": [{"summary": "no id"}, "junk"]})
    assert restored.status == IntelStatus.UNAVAILABLE
    assert restored.sources == {"osv": "error"}
    assert restored.vulnerabilities == []


def test_vulnerability_from_dict_revalidates_stored_values():
    vuln = Vulnerability.from_dict({
        "id": "GHSA-store-0001-aaaa", "severity": "MODERATE", "cvss_score": 99, "epss_score": -1,
        "epss_percentile": "0.5", "references": ["javascript:alert(1)", "https://example.invalid/a"],
        "kev": "yes", "kev_date_added": "2099-03-01<b>", "summary": "‮flipped",
        "aliases": ["CVE-2099-0001", {"x": 1}],
    })
    assert vuln.severity == "medium"
    assert vuln.cvss_score is None and vuln.epss_score is None and vuln.epss_percentile == 0.5
    assert vuln.references == ["https://example.invalid/a"]
    assert vuln.kev is False and vuln.kev_date_added is None
    assert "‮" not in vuln.summary
    assert vuln.aliases == ["CVE-2099-0001"]
    with pytest.raises(ValueError):
        Vulnerability.from_dict({"summary": "missing id"})


@pytest.mark.parametrize(("label", "expected"), [
    ("CRITICAL", "critical"), ("High", "high"), ("important", "high"), ("MODERATE", "medium"),
    ("medium", "medium"), ("LOW", "low"), ("none", "low"), ("bogus", "unknown"), (None, "unknown"), (7, "unknown"),
])
def test_normalize_severity(label, expected):
    assert normalize_severity(label) == expected


def test_bounded_dict_trims_for_evidence():
    vuln = Vulnerability(id="GHSA-many-0001-aaaa", aliases=[f"CVE-2099-{n:04d}" for n in range(40)],
                         references=[f"https://example.invalid/{n}" for n in range(10)], summary="s" * 1000)
    bounded = vuln.to_dict(bounded=True)
    assert len(bounded["aliases"]) == 10
    assert len(bounded["summary"]) <= 300
    assert len(vuln.to_dict()["aliases"]) == 40


def test_intel_result_from_dict_fails_closed_on_unhashable_or_misshapen_values():
    restored = IntelResult.from_dict({"status": ["ok"], "sources": {"osv": ["ok"], "cisa-kev": {"x": 1}},
                                      "vulnerabilities": 5, "errors": {"osv": ["boom"]}})
    assert restored.status == IntelStatus.UNAVAILABLE
    assert restored.sources == {"osv": "error", "cisa-kev": "error"}
    assert restored.vulnerabilities == []
    assert isinstance(restored.errors["osv"], str)


def test_vulnerability_from_dict_rejects_overflowing_numbers_and_non_text():
    vuln = Vulnerability.from_dict({"id": "GHSA-num0-0001-aaaa", "cvss_score": 10 ** 400, "epss_score": 10 ** 400,
                                    "summary": True, "published": False})
    assert vuln.cvss_score is None and vuln.epss_score is None
    assert vuln.summary is None and vuln.published is None


# --------------------------------------------------------------------------- merge_aliased
def _v(vid: str, **kw) -> Vulnerability:
    return Vulnerability(id=vid, sources=kw.pop("sources", ["osv"]), **kw)


def test_merge_groups_pysec_and_ghsa_twins_without_understating_risk():
    pysec = _v("PYSEC-2099-7", aliases=["CVE-2099-0005", "GHSA-twin-0001-aaaa"], summary="Synthetic fixture: pysec",
               fixed_versions=["1.2"], references=["https://example.invalid/pysec"], published="2099-01-02T00:00:00Z",
               modified="2099-01-09T00:00:00Z", kev=True, kev_date_added="2099-03-01", sources=["osv", "cisa-kev"])
    ghsa = _v("GHSA-twin-0001-aaaa", aliases=["CVE-2099-0005"], severity="high", cvss_score=7.5,
              cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_version="3.1",
              fixed_versions=["2.0.10", "1.2"], references=["https://example.invalid/ghsa"],
              published="2099-01-01T00:00:00Z", modified="2099-01-05T00:00:00Z", epss_score=0.4,
              epss_percentile=0.9, database_specific_severity="HIGH", sources=["osv", "first-epss"])
    other = _v("GHSA-else-0001-aaaa", aliases=["CVE-2099-0006"], severity="critical", cvss_score=9.8)
    before = [v.to_dict() for v in (pysec, ghsa, other)]

    merged, untouched = merge_aliased([pysec, ghsa, other])

    assert untouched is other  # a single-advisory group is returned unchanged
    assert merged.id == "GHSA-twin-0001-aaaa"  # the member that supplies severity/CVSS
    assert merged.aliases == ["CVE-2099-0005", "PYSEC-2099-7"]
    assert (merged.severity, merged.cvss_score, merged.cvss_version) == ("high", 7.5, "3.1")
    assert (merged.kev, merged.kev_date_added) == (True, "2099-03-01")  # from the lower-rated twin
    assert (merged.epss_score, merged.epss_percentile) == (0.4, 0.9)
    assert merged.fixed_versions == ["1.2", "2.0.10"]  # PEP 440 order, not string order
    assert merged.references == ["https://example.invalid/ghsa", "https://example.invalid/pysec"]
    assert (merged.published, merged.modified) == ("2099-01-01T00:00:00Z", "2099-01-09T00:00:00Z")
    assert merged.summary == "Synthetic fixture: pysec"  # the rated member has none
    assert merged.sources == ["osv", "first-epss", "cisa-kev"]
    assert merged.database_specific_severity == "HIGH"
    assert [v.to_dict() for v in (pysec, ghsa, other)] == before  # inputs are not modified


def test_merge_is_transitive_case_insensitive_and_drops_withdrawn():
    a = _v("GHSA-aaaa-0001-aaaa", aliases=["cve-2099-0001"], severity="low")
    b = _v("PYSEC-2099-2", aliases=["CVE-2099-0001", "OSV-2099-3"], severity="medium")
    c = _v("OSV-2099-3", severity="unknown")
    withdrawn = _v("GHSA-gone-0001-aaaa", aliases=["CVE-2099-0001"], severity="critical", withdrawn=True)
    (merged,) = merge_aliased([a, withdrawn, b, c])
    assert merged.id == "PYSEC-2099-2" and merged.severity == "medium"  # the withdrawn critical does not count
    assert set(merged.aliases) == {"GHSA-aaaa-0001-aaaa", "CVE-2099-0001", "OSV-2099-3"}
    assert merge_aliased([]) == []


def test_merge_prefers_a_cvss_score_on_equal_severity_and_follows_input_order_on_ties():
    label_only = _v("GHSA-labl-0001-aaaa", aliases=["CVE-2099-0007"], severity="high")
    scored = _v("PYSEC-2099-8", aliases=["CVE-2099-0007"], severity="high", cvss_score=8.1)
    assert merge_aliased([label_only, scored])[0].id == "PYSEC-2099-8"
    first = _v("GHSA-tie0-0001-aaaa", aliases=["CVE-2099-0008"], severity="low")
    second = _v("PYSEC-2099-9", aliases=["CVE-2099-0008"], severity="low")
    assert merge_aliased([first, second])[0].id == "GHSA-tie0-0001-aaaa"
    assert merge_aliased([second, first])[0].id == "PYSEC-2099-9"


def test_merge_keeps_unparseable_fixed_versions_in_given_order():
    a = _v("GHSA-semv-0001-aaaa", aliases=["CVE-2099-0009"], fixed_versions=["branch fix #2", "1.0"])
    b = _v("PYSEC-2099-10", aliases=["CVE-2099-0009"], fixed_versions=["1.0", "0.5"])
    assert merge_aliased([a, b])[0].fixed_versions == ["branch fix #2", "1.0", "0.5"]


def test_merge_of_a_hostile_catch_all_alias_record_cannot_hide_the_worst_risk():
    victims = [_v(f"GHSA-vic{n}-0001-aaaa", aliases=[f"CVE-2099-01{n:02d}"], severity="critical",
                  cvss_score=9.8, kev=(n == 3)) for n in range(5)]
    catch_all = _v("GHSA-evil-0001-aaaa", aliases=[f"CVE-2099-01{n:02d}" for n in range(5)], severity="low")
    (merged,) = merge_aliased([catch_all, *victims])
    assert (merged.severity, merged.cvss_score, merged.kev) == ("critical", 9.8, True)
    assert len(merged.aliases) == 10


# --------------------------------------------------------------------------- lifecycle / hardening
def test_http_clients_are_restricted_to_the_documented_intel_hosts():
    svc = make_service(NVD_ENABLED=True)
    for build in (svc._get_osv, svc._get_kev, svc._get_epss, svc._get_nvd):
        build()  # constructing clients performs no network I/O
    hosts = [set(http.allowed_hosts) for http in svc._owned]
    assert hosts == [{"api.osv.dev"}, {"www.cisa.gov"}, {"api.first.org"}, {"services.nvd.nist.gov"}]
    assert all(http.allow_http is False for http in svc._owned)


def test_service_is_reusable_after_close():
    cache = MemoryCache()
    svc = make_service(cache)
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        assert svc.package_vulnerabilities("pypi", PKG, "1.0.0").status == IntelStatus.OK
        svc.close()
        assert svc._owned == []
        cache.data.clear()  # force real requests through freshly built clients
        again = svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        assert router.routes["querybatch"].call_count == 2
    assert again.status == IntelStatus.OK and len(again.vulnerabilities) == 3
    assert len(svc._owned) == 3  # osv, kev, epss rebuilt
    svc.close()


def test_consulted_sources_are_counted_with_their_outcome(monkeypatch):
    counted: list[tuple[str, str]] = []
    monkeypatch.setattr(service_module.metrics, "inc_intel", lambda source, status: counted.append((source, status)))
    svc = make_service()
    with respx.mock(assert_all_called=False) as router:
        install_routes(router)
        svc.package_vulnerabilities("pypi", PKG, "1.0.0")
        svc.package_vulnerabilities("pypi", "warden-clean-fixture", "3.1.4")
    # Enriched lookup: osv + kev + epss (nvd disabled); clean package: osv only (enrichment skipped).
    assert counted == [("osv", "ok"), ("cisa-kev", "ok"), ("first-epss", "ok"), ("osv", "ok")]

    counted.clear()
    with respx.mock() as router:
        router.post(f"{OSV}/v1/querybatch").mock(return_value=httpx.Response(503))
        make_service().package_vulnerabilities("pypi", PKG, "1.0.0")
    assert ("osv", "error") in counted

    counted.clear()
    make_service(INTEL_OFFLINE=True).package_vulnerabilities("pypi", PKG, "1.0.0")
    make_service(INTEL_ENABLED=False).package_vulnerabilities("pypi", PKG, "1.0.0")
    assert counted == []  # no source was consulted
