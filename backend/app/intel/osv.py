"""OSV (https://osv.dev) client and advisory parser.

Lookups use the documented two-step flow:

1. ``POST /v1/querybatch`` with ``{"queries": [{"package": {"ecosystem", "name"}, "version"}]}``
   (at most 1000 queries per request). Results come back *in query order* and contain only
   ``id``/``modified``; a query with more results carries ``next_page_token``, which is
   re-sent for just that query until exhausted.
2. ``GET /v1/vulns/{id}`` to hydrate each advisory. Hydrated records are reduced to a bounded
   canonical form (:func:`trim_record`) and cached; a cached record is reused only while its
   ``modified`` timestamp matches the one reported by the batch query.

The OSV API is a trusted service, but its responses are still validated as untrusted input:
a result list that does not line up with the queries is rejected outright (mis-aligned
results would attribute vulnerabilities to the wrong package), advisory ids must match a
conservative pattern before they are placed in a URL path, pagination is bounded and a
repeated page token stops the loop, and a hydrated record must carry the id that was
requested. The shared cache is another input, so cached records are re-normalised on use.

:func:`parse_vulnerability` extracts, for the *queried package only*: aliases, summary,
CVSS v3.x vectors (scored with :mod:`app.intel.cvss`; v4/v2 vectors carried), the
database-specific (GHSA) severity, ECOSYSTEM/SEMVER affected ranges, fixed versions,
up to 10 http(s) references (advisories first), published/modified and withdrawn.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from packaging.version import InvalidVersion, Version

from app.core.http import SafeHttpClient
from app.core.logging import get_logger
from app.core.redaction import sanitize_text
from app.intel import cvss
from app.intel.client import IntelCache, IntelSourceError, cache_key, translate_http_errors
from app.intel.models import (
    MAX_ALIASES,
    MAX_FIXED_VERSIONS,
    MAX_RANGES,
    MAX_REFERENCES,
    MAX_SUMMARY_CHARS,
    SOURCE_OSV,
    Vulnerability,
    normalize_severity,
)

log = get_logger("warden.intel.osv")

MAX_QUERIES_PER_BATCH = 1000
MAX_PAGES_PER_QUERY = 20
MAX_IDS_PER_QUERY = 2000
MAX_PAGE_TOKEN_CHARS = 2048

# Bounds of the canonical record form (see ``trim_record``): they cap the size of a cached
# advisory whatever the upstream response contains.
MAX_AFFECTED_ENTRIES = 200
MAX_EVENTS_PER_RANGE = 100
MAX_EVENTS_PER_RECORD = 4000
MAX_SEVERITY_ENTRIES = 10
MAX_RAW_REFERENCES = 100
MAX_RAW_TEXT_CHARS = 8192  # summary/details kept before being sanitised down to MAX_SUMMARY_CHARS
_MAX_ALIAS_SCAN = 1000
_MAX_SCORE_CHARS = 1024
_MAX_VERSION_CHARS = 64
_MAX_TIMESTAMP_CHARS = 64
_MAX_LABEL_CHARS = 64
_MAX_PACKAGE_NAME_CHARS = 512
_MAX_URL_CHARS = 500

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,99}\Z")  # \Z: "$" would accept a trailing newline
_PEP503_RE = re.compile(r"[-_.]+")
_REFERENCE_PRIORITY = {"ADVISORY": 0, "FIX": 1, "REPORT": 2, "WEB": 3, "ARTICLE": 4, "PACKAGE": 5, "EVIDENCE": 6}
_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
_EVENT_KINDS = frozenset({"introduced", "fixed", "last_affected", "limit"})

# Warden ecosystem name -> OSV ecosystem name (https://ossf.github.io/osv-schema/#affectedpackage-field).
OSV_ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "golang": "Go",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "composer": "Packagist",
}


def osv_ecosystem(ecosystem: str) -> str | None:
    """OSV's name for a Warden ecosystem, or ``None`` when the ecosystem is not supported."""
    if not isinstance(ecosystem, str):
        return None
    key = ecosystem.strip()
    return OSV_ECOSYSTEMS.get(key.lower()) or (key if key in OSV_ECOSYSTEMS.values() else None)


def normalize_package_name(osv_eco: str, name: str) -> str:
    """Name used for matching ``affected[].package.name``: PEP 503 for PyPI, exact otherwise."""
    if osv_eco == "PyPI":
        return _PEP503_RE.sub("-", name.strip()).lower()
    return name.strip()


def valid_vuln_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


@dataclass(frozen=True)
class OsvQuery:
    ecosystem: str  # OSV ecosystem name, e.g. "PyPI"
    name: str
    version: str


@dataclass
class QueryOutcome:
    """Advisory ids OSV reports for one query."""

    vulns: list[tuple[str, str | None]] = field(default_factory=list)  # (id, modified)
    error: str | None = None  # the query failed: vulnerability status unknown
    incomplete: str | None = None  # some ids may be missing (pagination failure, malformed entries)


class OsvClient:
    def __init__(self, http: SafeHttpClient, cache: IntelCache, *, base_url: str, ttl_seconds: int) -> None:
        self._http = http
        self._cache = cache
        self._base = base_url.rstrip("/")
        self._ttl = ttl_seconds

    # ------------------------------------------------------------------ querybatch
    def query_batch(self, queries: Sequence[OsvQuery]) -> list[QueryOutcome]:
        """Advisory ids per query (same order as ``queries``). Never raises for source failures."""
        outcomes = [QueryOutcome() for _ in queries]
        pending: list[int] = []
        for i, q in enumerate(queries):
            cached = self._cache.get(self._query_key(q))
            vulns = _vulns_from_cache(cached)
            if vulns is None:
                pending.append(i)
            else:
                outcomes[i].vulns = vulns
        for start in range(0, len(pending), MAX_QUERIES_PER_BATCH):
            self._run_chunk(queries, pending[start:start + MAX_QUERIES_PER_BATCH], outcomes)
        for i in pending:
            out = outcomes[i]
            if out.error is None and out.incomplete is None:
                self._cache.set(self._query_key(queries[i]),
                                {"vulns": [{"id": vid, "modified": mod} for vid, mod in out.vulns]}, self._ttl)
        return outcomes

    def _query_key(self, q: OsvQuery) -> str:
        return cache_key("osv:query:v1", q.ecosystem, normalize_package_name(q.ecosystem, q.name), q.version)

    def _post(self, body: dict) -> list:
        data = translate_http_errors(SOURCE_OSV, self._http.post_json, f"{self._base}/v1/querybatch", body)
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(body["queries"]):
            raise IntelSourceError(SOURCE_OSV, "querybatch response does not match the queries", kind="invalid")
        return results

    def _run_chunk(self, queries: Sequence[OsvQuery], indices: list[int], outcomes: list[QueryOutcome]) -> None:
        body = {"queries": [_query_body(queries[i]) for i in indices]}
        try:
            results = self._post(body)
        except IntelSourceError as exc:
            log.warning("osv_querybatch_failed", error=str(exc), queries=len(indices))
            for i in indices:
                outcomes[i].error = str(exc)
            return

        tokens: dict[int, str] = {}
        seen_tokens: dict[int, set[str]] = {i: set() for i in indices}
        pages: dict[int, int] = dict.fromkeys(indices, 1)
        for i, result in zip(indices, results):
            token = self._absorb(outcomes[i], result)
            if token:
                tokens[i] = token

        while tokens:
            batch: list[tuple[int, str]] = []
            for i, token in list(tokens.items())[:MAX_QUERIES_PER_BATCH]:
                del tokens[i]
                if token in seen_tokens[i] or pages[i] >= MAX_PAGES_PER_QUERY:
                    # A repeated token would loop forever; a page cap bounds a misbehaving server.
                    outcomes[i].incomplete = "pagination limit reached"
                    continue
                seen_tokens[i].add(token)
                pages[i] += 1
                batch.append((i, token))
            if not batch:
                continue
            page_body = {"queries": [dict(_query_body(queries[i]), page_token=t) for i, t in batch]}
            try:
                page_results = self._post(page_body)
            except IntelSourceError as exc:
                log.warning("osv_querybatch_page_failed", error=str(exc), queries=len(batch))
                for i, _ in batch:
                    outcomes[i].incomplete = str(exc)
                continue
            for (i, _), result in zip(batch, page_results):
                token = self._absorb(outcomes[i], result)
                if token:
                    tokens[i] = token

    @staticmethod
    def _absorb(outcome: QueryOutcome, result: Any) -> str | None:
        """Merge one query result into ``outcome``; return the next page token, if any."""
        if not isinstance(result, dict):
            outcome.incomplete = "malformed querybatch result"
            return None
        vulns = result.get("vulns") or []
        if not isinstance(vulns, list):
            outcome.incomplete = "malformed querybatch result"
            return None
        known = {vid for vid, _ in outcome.vulns}
        for item in vulns:
            vid = item.get("id") if isinstance(item, dict) else None
            if not valid_vuln_id(vid):
                outcome.incomplete = "querybatch returned an invalid advisory id"
                continue
            if vid in known:
                continue
            if len(outcome.vulns) >= MAX_IDS_PER_QUERY:
                outcome.incomplete = "too many advisories for one package"
                return None
            modified = item.get("modified")
            outcome.vulns.append((vid, modified if isinstance(modified, str) and len(modified) <= 40 else None))
            known.add(vid)
        token = result.get("next_page_token")
        # bandit B105 false positive: an OSV pagination token, not a credential.
        if token is None or token == "":  # nosec B105
            return None
        if not isinstance(token, str) or len(token) > MAX_PAGE_TOKEN_CHARS:
            outcome.incomplete = "invalid page token"
            return None
        return token

    # ------------------------------------------------------------------ hydration
    def get_vulnerability(self, vuln_id: str, modified: str | None = None) -> dict:
        """Canonical OSV record for ``vuln_id`` (cached). Raises :class:`IntelSourceError` on failure."""
        if not valid_vuln_id(vuln_id):
            raise IntelSourceError(SOURCE_OSV, "invalid advisory id", kind="invalid")
        key = cache_key("osv:vuln:v1", vuln_id)
        cached = self._cache.get(key)
        if cached and cached.get("id") == vuln_id and (modified is None or cached.get("modified") == modified):
            return cached
        url = f"{self._base}/v1/vulns/{quote(vuln_id, safe='')}"
        data = translate_http_errors(SOURCE_OSV, self._http.get_json, url, allow_404=True)
        if data is None:
            raise IntelSourceError(SOURCE_OSV, f"advisory {vuln_id} not found", kind="status")
        if not isinstance(data, dict) or data.get("id") != vuln_id:
            raise IntelSourceError(SOURCE_OSV, f"advisory {vuln_id}: unexpected record", kind="invalid")
        record = trim_record(data)
        self._cache.set(key, record, self._ttl)
        return record


def _query_body(q: OsvQuery) -> dict[str, Any]:
    return {"package": {"ecosystem": q.ecosystem, "name": q.name}, "version": q.version}


def _vulns_from_cache(cached: dict | None) -> list[tuple[str, str | None]] | None:
    if not cached or not isinstance(cached.get("vulns"), list):
        return None
    out: list[tuple[str, str | None]] = []
    for item in cached["vulns"]:
        if not isinstance(item, dict) or not valid_vuln_id(item.get("id")):
            return None  # corrupt cache entry: refetch
        mod = item.get("modified")
        out.append((item["id"], mod if isinstance(mod, str) else None))
    return out


# ---------------------------------------------------------------------------- canonical record form
def _short_str(value: object, max_len: int) -> str | None:
    """``value`` if it is a string of at most ``max_len`` characters, else ``None`` (never truncated)."""
    return value if isinstance(value, str) and len(value) <= max_len else None


def _long_text(value: object) -> str | None:
    return value[:MAX_RAW_TEXT_CHARS] if isinstance(value, str) else None


def _trim_severity(entries: object) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in entries if isinstance(entries, list) else []:
        if len(out) >= MAX_SEVERITY_ENTRIES:
            break
        if not isinstance(item, dict):
            continue
        kind, score = _short_str(item.get("type"), 32), _short_str(item.get("score"), _MAX_SCORE_CHARS)
        if kind and kind.startswith("CVSS_V") and score:
            out.append({"type": kind, "score": score})
    return out


def _trim_events(events: object, budget: int) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for event in events[:MAX_EVENTS_PER_RANGE] if isinstance(events, list) else []:
        if len(out) >= budget:
            break
        if not isinstance(event, dict) or len(event) != 1:
            continue  # the OSV schema allows exactly one key per event; anything else is not guessed at
        ((kind, value),) = event.items()
        value = _short_str(value, _MAX_VERSION_CHARS)
        if kind in _EVENT_KINDS and value is not None:
            out.append({kind: value})
    return out


def _trim_affected(entries: object) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    budget = MAX_EVENTS_PER_RECORD
    for entry in entries[:MAX_AFFECTED_ENTRIES] if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        ranges: list[dict[str, Any]] = []
        for rng in entry.get("ranges") if isinstance(entry.get("ranges"), list) else []:
            if len(ranges) >= MAX_RANGES:
                break
            # isinstance first: an unhashable "type" would make the set membership test raise.
            if isinstance(rng, dict) and isinstance(rng.get("type"), str) and rng["type"] in _RANGE_TYPES:
                events = _trim_events(rng.get("events"), budget)
                budget -= len(events)
                ranges.append({"type": rng["type"], "events": events})
        out.append({
            "package": {
                "ecosystem": _short_str(pkg.get("ecosystem"), _MAX_LABEL_CHARS),
                "name": _short_str(pkg.get("name"), _MAX_PACKAGE_NAME_CHARS),
            },
            "severity": _trim_severity(entry.get("severity")),
            "ranges": ranges,
        })
    return out


def _trim_aliases(aliases: object) -> list[str]:
    out: list[str] = []
    for alias in aliases[:_MAX_ALIAS_SCAN] if isinstance(aliases, list) else []:
        if valid_vuln_id(alias) and alias not in out:
            out.append(alias)
            if len(out) >= MAX_ALIASES:
                break
    return out


def _trim_references(refs: object) -> list[dict[str, str | None]]:
    out: list[dict[str, str | None]] = []
    for ref in refs if isinstance(refs, list) else []:
        if len(out) >= MAX_RAW_REFERENCES:
            break
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
            continue
        url = ref["url"].strip()
        if url.lower().startswith(("https://", "http://")) and len(url) <= _MAX_URL_CHARS:
            out.append({"type": _short_str(ref.get("type"), 32), "url": url})  # javascript:, data:, ... dropped
    return out


def _trim_withdrawn(value: object) -> str | bool | None:
    if isinstance(value, str):
        return value[:_MAX_TIMESTAMP_CHARS] or None
    return True if value else None


def trim_record(data: dict) -> dict:
    """Canonical, bounded form of an OSV record: only the fields Warden parses, in validated shapes.

    Used for the cache (a hostile or huge upstream record cannot produce a huge cache entry)
    and applied by :func:`parse_vulnerability` itself, so a cached record and a freshly fetched
    one always parse identically. The function is idempotent. Over-long identifiers, versions,
    timestamps, vectors and URLs are dropped rather than truncated, because a truncated value
    would be wrong data; free text is cut to ``MAX_RAW_TEXT_CHARS`` before sanitising.
    """
    if not isinstance(data, dict):
        data = {}
    db = data.get("database_specific") if isinstance(data.get("database_specific"), dict) else {}
    return {
        "id": data.get("id") if valid_vuln_id(data.get("id")) else None,
        "modified": _short_str(data.get("modified"), _MAX_TIMESTAMP_CHARS),
        "published": _short_str(data.get("published"), _MAX_TIMESTAMP_CHARS),
        "withdrawn": _trim_withdrawn(data.get("withdrawn")),
        "aliases": _trim_aliases(data.get("aliases")),
        "summary": _long_text(data.get("summary")),
        "details": _long_text(data.get("details")),
        "severity": _trim_severity(data.get("severity")),
        "database_specific": {"severity": _short_str(db.get("severity"), _MAX_LABEL_CHARS)},
        "affected": _trim_affected(data.get("affected")),
        "references": _trim_references(data.get("references")),
    }


# ---------------------------------------------------------------------------- parsing
def _text(value: object, max_len: int) -> str | None:
    if not isinstance(value, str):
        return None
    s = sanitize_text(value, max_len=max_len).strip()
    return s or None


def _summary(record: dict) -> str | None:
    summary = _text(record.get("summary"), MAX_SUMMARY_CHARS)
    if summary:
        return summary
    details = record.get("details")
    if isinstance(details, str) and details.strip():
        first = details.strip().splitlines()[0]
        return _text(first, MAX_SUMMARY_CHARS)
    return None


def _version_sort_key(osv_eco: str, value: str) -> tuple:
    if osv_eco == "PyPI":
        try:
            return (0, Version(value), value)
        except InvalidVersion:
            return (1, value, value)
    return (0, value, value)


def _ranges_for(entries: list[dict]) -> tuple[list[dict[str, Any]], list[str]]:
    """Affected intervals and fixed versions from canonical ``affected`` entries."""
    intervals: list[dict[str, Any]] = []
    fixed: list[str] = []
    for entry in entries:
        for rng in entry["ranges"]:
            current: dict[str, Any] | None = None
            for event in rng["events"]:
                ((kind, raw),) = event.items()
                value = _text(raw, _MAX_VERSION_CHARS)
                if value is None:
                    continue
                if kind == "introduced":
                    if current is not None:
                        intervals.append(current)
                    current = {"type": rng["type"], "introduced": value, "fixed": None, "last_affected": None}
                    continue
                if current is None:
                    current = {"type": rng["type"], "introduced": None, "fixed": None, "last_affected": None}
                if kind == "fixed":
                    current["fixed"] = value
                    if value not in fixed:
                        fixed.append(value)
                elif kind == "last_affected":
                    current["last_affected"] = value
                intervals.append(current)  # "fixed", "last_affected" and "limit" all close the interval
                current = None
            if current is not None:
                intervals.append(current)
    return intervals[:MAX_RANGES], fixed


def _references(record: dict) -> list[str]:
    ranked = sorted(
        (_REFERENCE_PRIORITY.get(str(ref["type"]), 9), pos, sanitize_text(ref["url"], max_len=_MAX_URL_CHARS))
        for pos, ref in enumerate(record["references"])
    )
    out: list[str] = []
    for _, _, url in ranked:
        if url not in out:
            out.append(url)
        if len(out) >= MAX_REFERENCES:
            break
    return out


def parse_vulnerability(record: dict, *, ecosystem: str, name: str) -> Vulnerability | None:
    """Normalise an OSV record for the queried package. ``None`` if the record is unusable.

    ``ecosystem`` is the OSV ecosystem name (e.g. ``"PyPI"``). Withdrawn advisories are
    returned with ``withdrawn=True``; excluding them is the caller's decision.
    """
    if not isinstance(record, dict) or not valid_vuln_id(record.get("id")):
        return None
    record = trim_record(record)
    vid = record["id"]
    wanted = normalize_package_name(ecosystem, name)
    matching = [
        entry for entry in record["affected"]
        if entry["package"]["name"] is not None
        and str(entry["package"]["ecosystem"] or "").split(":", 1)[0] == ecosystem
        and normalize_package_name(ecosystem, entry["package"]["name"]) == wanted
    ]

    vectors = [item["score"].strip() for item in record["severity"]]
    for entry in matching:
        vectors.extend(item["score"].strip() for item in entry["severity"])
    scored = [s for s in (cvss.score_vector(v) for v in vectors) if s is not None]
    carried = {cvss.vector_version(v): v for v in reversed(vectors)}

    db_label = _text(record["database_specific"]["severity"], 20)
    vuln = Vulnerability(id=vid, sources=[SOURCE_OSV], database_specific_severity=db_label)
    if scored:
        best = max(scored, key=lambda s: (s.version, s.base_score))
        vuln.cvss_score, vuln.cvss_vector, vuln.cvss_version = best.base_score, best.vector, best.version
        vuln.severity = normalize_severity(best.rating)
    else:
        for version in ("4.0", "2.0"):
            if carried.get(version):
                vuln.cvss_vector, vuln.cvss_version = _text(carried[version], cvss.MAX_VECTOR_LENGTH), version
                break
    if vuln.severity == "unknown" and db_label:
        vuln.severity = normalize_severity(db_label)

    vuln.aliases = [alias for alias in record["aliases"] if alias != vid]
    vuln.summary = _summary(record)
    vuln.published = _text(record["published"], 40)
    vuln.modified = _text(record["modified"], 40)
    vuln.withdrawn = bool(record["withdrawn"])
    ranges, fixed = _ranges_for(matching)
    vuln.affected_ranges = ranges
    vuln.fixed_versions = sorted(fixed, key=lambda v: _version_sort_key(ecosystem, v))[:MAX_FIXED_VERSIONS]
    vuln.references = _references(record)
    return vuln
