"""Vulnerability-intelligence data model.

``Vulnerability`` is Warden's normalised view of one advisory as it applies to one queried
package: identifiers, a severity bucket, an optional CVSS v3.x base score, the affected
ranges and fixed versions *for that package only*, and exploitability enrichment (CISA KEV
membership, FIRST EPSS probability).

``IntelResult`` wraps the vulnerabilities for one ``(ecosystem, name, version)`` lookup with
an explicit completeness ``status``. The status is the important part of the contract: a
lookup whose intelligence sources could not be reached is ``unavailable`` (or ``partial``),
never an empty "no vulnerabilities" answer. Consumers must treat anything other than ``ok``
as "vulnerability status unknown".

Advisory text comes from third-party databases and is rendered in reports and dashboards, so
every string is sanitised (control/bidi characters escaped, secret-shaped values redacted,
length bounded) both when records are parsed and when they are rebuilt from storage.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from packaging.version import InvalidVersion, Version

from app.core.redaction import sanitize_text

SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Source labels used both in ``Vulnerability.sources`` and ``IntelResult.sources`` keys.
SOURCE_OSV = "osv"
SOURCE_KEV = "cisa-kev"
SOURCE_EPSS = "first-epss"
SOURCE_NVD = "nvd"
ALL_SOURCES: tuple[str, ...] = (SOURCE_OSV, SOURCE_KEV, SOURCE_EPSS, SOURCE_NVD)

# Vocabulary of other databases mapped onto Warden's buckets. GitHub advisories use
# LOW/MODERATE/HIGH/CRITICAL; some distributions use "important"/"negligible". A CVSS
# rating of "none" (score 0.0) is still a published advisory, so it maps to the lowest
# bucket rather than to "unknown".
_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "low",
    "none": "low",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")

MAX_ALIASES = 50
MAX_RANGES = 20
MAX_FIXED_VERSIONS = 50
MAX_REFERENCES = 10
MAX_SUMMARY_CHARS = 500
_BOUNDED_LIMITS = {"aliases": 10, "affected_ranges": 10, "fixed_versions": 10, "references": 10, "summary": 300}


class IntelStatus:
    """Completeness of an :class:`IntelResult`."""

    OK = "ok"  # every needed source answered
    PARTIAL = "partial"  # vulnerabilities known, but some enrichment/details are missing
    UNAVAILABLE = "unavailable"  # the vulnerability database could not be queried: status unknown
    DISABLED = "disabled"  # intelligence switched off (INTEL_ENABLED=false or INTEL_OFFLINE=true)

    ALL = frozenset({OK, PARTIAL, UNAVAILABLE, DISABLED})


class SourceStatus:
    """Per-source outcome recorded in ``IntelResult.sources``."""

    OK = "ok"
    PARTIAL = "partial"  # some requests for this source failed or were capped
    ERROR = "error"
    DISABLED = "disabled"
    SKIPPED = "skipped"  # not needed for this lookup (e.g. no CVE aliases to enrich)
    UNSUPPORTED = "unsupported"  # e.g. an ecosystem the source cannot be queried for

    ALL = frozenset({OK, PARTIAL, ERROR, DISABLED, SKIPPED, UNSUPPORTED})


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def normalize_severity(value: object) -> str:
    """Map a severity label from any supported database onto Warden's buckets."""
    if not isinstance(value, str):
        return "unknown"
    return _SEVERITY_ALIASES.get(value.strip().lower(), "unknown")


def severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(value, 0)


def is_cve_id(value: object) -> bool:
    return isinstance(value, str) and bool(_CVE_RE.match(value.strip().upper()))


def _clean_str(value: object, max_len: int) -> str | None:
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return None
    text = sanitize_text(value, max_len=max_len).strip()
    return text or None


def _clean_list(values: object, *, max_items: int, max_len: int = 200) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = _clean_str(v, max_len)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= max_items:
            break
    return out


def _bounded_float(value: object, lo: float, hi: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        f = float(value)
    except (ValueError, OverflowError):  # OverflowError: an integer too large for a float
        return None
    if not math.isfinite(f) or f < lo or f > hi:
        return None
    return f


def _clean_ranges(values: object) -> list[dict[str, Any]]:
    if not isinstance(values, (list, tuple)):
        return []
    out: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        out.append({
            "type": _clean_str(item.get("type"), 20),
            "introduced": _clean_str(item.get("introduced"), 64),
            "fixed": _clean_str(item.get("fixed"), 64),
            "last_affected": _clean_str(item.get("last_affected"), 64),
        })
        if len(out) >= MAX_RANGES:
            break
    return out


@dataclass
class Vulnerability:
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    severity: str = "unknown"  # critical | high | medium | low | unknown
    cvss_score: float | None = None  # CVSS v3.x base score computed from ``cvss_vector``
    cvss_vector: str | None = None
    cvss_version: str | None = None  # "3.1" | "3.0" | "4.0" (carried, not scored) | "2.0" (carried)
    published: str | None = None
    modified: str | None = None
    # [{"type": "ECOSYSTEM", "introduced": "0", "fixed": "1.2.3", "last_affected": None}]
    affected_ranges: list[dict[str, Any]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # http(s) URLs, advisories first
    kev: bool = False
    kev_date_added: str | None = None
    epss_score: float | None = None  # probability of exploitation activity (0..1)
    epss_percentile: float | None = None
    sources: list[str] = field(default_factory=list)  # e.g. ["osv", "cisa-kev", "first-epss", "nvd"]
    withdrawn: bool = False
    database_specific_severity: str | None = None  # the source database's own label, e.g. "MODERATE"

    def __post_init__(self) -> None:
        self.severity = self.severity if self.severity in _SEVERITY_RANK else normalize_severity(self.severity)

    # ------------------------------------------------------------------ helpers
    @property
    def severity_rank(self) -> int:
        return severity_rank(self.severity)

    def identifiers(self) -> list[str]:
        """The advisory id followed by its aliases (deduplicated, original order)."""
        out: list[str] = []
        for v in [self.id, *self.aliases]:
            if v and v not in out:
                out.append(v)
        return out

    def cve_ids(self) -> list[str]:
        """CVE identifiers among the id and aliases (upper-cased, deduplicated)."""
        out: list[str] = []
        for v in self.identifiers():
            cve = v.strip().upper()
            if is_cve_id(cve) and cve not in out:
                out.append(cve)
        return out

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    # ------------------------------------------------------------------ serialisation
    def to_dict(self, *, bounded: bool = False) -> dict[str, Any]:
        """Plain JSON-safe dict. ``bounded=True`` trims lists/text for use as finding evidence."""
        lim = _BOUNDED_LIMITS if bounded else None

        def cap(values: list, key: str) -> list:
            return list(values[: lim[key]]) if lim else list(values)

        summary = self.summary
        if lim and summary and len(summary) > lim["summary"]:
            summary = summary[: lim["summary"] - 1] + "…"
        return {
            "id": self.id,
            "aliases": cap(self.aliases, "aliases"),
            "summary": summary,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cvss_version": self.cvss_version,
            "published": self.published,
            "modified": self.modified,
            "affected_ranges": [dict(r) for r in cap(self.affected_ranges, "affected_ranges")],
            "fixed_versions": cap(self.fixed_versions, "fixed_versions"),
            "references": cap(self.references, "references"),
            "kev": self.kev,
            "kev_date_added": self.kev_date_added,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "sources": list(self.sources),
            "withdrawn": self.withdrawn,
            "database_specific_severity": self.database_specific_severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Vulnerability:
        """Rebuild from ``to_dict`` output (e.g. a stored scan). Values are re-validated."""
        if not isinstance(data, dict):
            raise ValueError("vulnerability record must be an object")
        vid = _clean_str(data.get("id"), 100)
        if not vid:
            raise ValueError("vulnerability record has no id")
        kev_date = _clean_str(data.get("kev_date_added"), 32)
        cvss_version = _clean_str(data.get("cvss_version"), 8)
        return cls(
            id=vid,
            aliases=_clean_list(data.get("aliases"), max_items=MAX_ALIASES, max_len=100),
            summary=_clean_str(data.get("summary"), MAX_SUMMARY_CHARS),
            severity=normalize_severity(data.get("severity")),
            cvss_score=_bounded_float(data.get("cvss_score"), 0.0, 10.0),
            cvss_vector=_clean_str(data.get("cvss_vector"), 256),
            cvss_version=cvss_version,
            published=_clean_str(data.get("published"), 40),
            modified=_clean_str(data.get("modified"), 40),
            affected_ranges=_clean_ranges(data.get("affected_ranges")),
            fixed_versions=_clean_list(data.get("fixed_versions"), max_items=MAX_FIXED_VERSIONS, max_len=64),
            references=[u for u in _clean_list(data.get("references"), max_items=MAX_REFERENCES, max_len=500)
                        if u.lower().startswith(("https://", "http://"))],
            kev=data.get("kev") is True,
            kev_date_added=kev_date if kev_date and _DATE_RE.match(kev_date) else None,
            epss_score=_bounded_float(data.get("epss_score"), 0.0, 1.0),
            epss_percentile=_bounded_float(data.get("epss_percentile"), 0.0, 1.0),
            sources=_clean_list(data.get("sources"), max_items=len(ALL_SOURCES) + 4, max_len=32),
            withdrawn=data.get("withdrawn") is True,
            database_specific_severity=_clean_str(data.get("database_specific_severity"), 20),
        )


def _sorted_versions(values: list[str]) -> list[str]:
    """PEP 440 order when every value parses; otherwise the given order (never a guessed order)."""
    try:
        return sorted(values, key=Version)
    except InvalidVersion:
        return list(values)


def _union(groups: Iterable[list], limit: int) -> list:
    out: list = []
    for values in groups:
        for value in values:
            if len(out) >= limit:
                return out
            if value not in out:
                out.append(value)
    return out


def _merge_group(members: list[Vulnerability]) -> Vulnerability:
    if len(members) == 1:
        return members[0]
    # Severity and the CVSS fields come from one record so they can never contradict each other.
    # ``max`` keeps the first of equal candidates, so the choice follows the input order.
    rated = max(members, key=lambda v: (v.severity_rank, v.cvss_score if v.cvss_score is not None else -1.0))
    ordered = [rated, *(v for v in members if v is not rated)]
    seen = {rated.id.strip().upper()}
    aliases: list[str] = []
    for vuln in ordered:
        for ident in vuln.identifiers():
            key = ident.strip().upper()
            if key not in seen:
                seen.add(key)
                aliases.append(ident)
    kev_dates = sorted(v.kev_date_added for v in members if v.kev and v.kev_date_added)
    with_epss = [v for v in ordered if v.epss_score is not None]
    best_epss = max(with_epss, key=lambda v: v.epss_score or 0.0) if with_epss else None
    published = [v.published for v in members if v.published]
    modified = [v.modified for v in members if v.modified]
    return Vulnerability(
        id=rated.id,
        aliases=aliases[:MAX_ALIASES],
        summary=next((v.summary for v in ordered if v.summary), None),
        severity=rated.severity,
        cvss_score=rated.cvss_score,
        cvss_vector=rated.cvss_vector,
        cvss_version=rated.cvss_version,
        published=min(published) if published else None,
        modified=max(modified) if modified else None,
        affected_ranges=[dict(r) for r in _union((v.affected_ranges for v in ordered), MAX_RANGES)],
        fixed_versions=_sorted_versions(_union((v.fixed_versions for v in ordered), MAX_FIXED_VERSIONS)),
        references=_union((v.references for v in ordered), MAX_REFERENCES),
        kev=any(v.kev for v in members),
        kev_date_added=kev_dates[0] if kev_dates else None,
        epss_score=best_epss.epss_score if best_epss else None,
        epss_percentile=best_epss.epss_percentile if best_epss else None,
        sources=_union((v.sources for v in ordered), len(ALL_SOURCES) + 4),
        withdrawn=False,
        database_specific_severity=rated.database_specific_severity
        or next((v.database_specific_severity for v in ordered if v.database_specific_severity), None),
    )


def merge_aliased(vulns: Iterable[Vulnerability]) -> list[Vulnerability]:
    """Merge advisories that describe the same vulnerability into one record each.

    Vulnerability databases publish overlapping advisories: for PyPI, OSV typically returns a
    ``PYSEC`` record *and* its GitHub ``GHSA`` twin, both aliasing the same CVE. Advisories are
    grouped transitively through shared identifiers (id or alias, compared case-insensitively)
    and each group is merged without understating risk:

    * the member with the highest severity (then CVSS score) supplies ``id``, ``severity`` and
      the CVSS fields; every other identifier becomes an alias;
    * ``kev`` is true if any member is KEV-listed (earliest ``kev_date_added``); EPSS is the
      highest member score;
    * aliases, affected ranges, fixed versions, references and sources are unioned (bounded);
      ``published`` is the earliest and ``modified`` the latest timestamp.

    Withdrawn advisories are dropped. Groups keep the order of their first member, a
    single-advisory group is returned unchanged, and the input records are never modified.
    """
    live = [v for v in vulns if not v.withdrawn]
    parent = list(range(len(live)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, vuln in enumerate(live):
        for ident in vuln.identifiers():
            key = ident.strip().upper()
            if not key:
                continue
            root_i, root_j = find(i), find(owner.setdefault(key, i))
            if root_i != root_j:
                # The smaller index stays the root, so a group's root is its first member.
                parent[max(root_i, root_j)] = min(root_i, root_j)
    groups: dict[int, list[Vulnerability]] = {}
    for i, vuln in enumerate(live):
        groups.setdefault(find(i), []).append(vuln)
    return [_merge_group(members) for _, members in sorted(groups.items())]


@dataclass
class IntelResult:
    """Vulnerability intelligence for one package version, with an explicit completeness status."""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    status: str = IntelStatus.OK
    sources: dict[str, str] = field(default_factory=dict)  # {"osv": "ok", "cisa-kev": "error", ...}
    fetched_at: str = field(default_factory=utc_now_iso)
    ecosystem: str | None = None
    name: str | None = None
    version: str | None = None
    # Log-safe, short error descriptions per failed source (never raw responses or secrets).
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return self.status == IntelStatus.OK

    @property
    def degraded(self) -> bool:
        """True when vulnerability status is unknown or incomplete (not merely switched off)."""
        return self.status in (IntelStatus.UNAVAILABLE, IntelStatus.PARTIAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "sources": dict(self.sources),
            "errors": dict(self.errors),
            "fetched_at": self.fetched_at,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IntelResult:
        """Rebuild from ``to_dict`` output. An unrecognised status fails closed to ``unavailable``."""
        if not isinstance(data, dict):
            raise ValueError("intel result must be an object")
        status = data.get("status")
        raw_vulns = data.get("vulnerabilities")
        vulns: list[Vulnerability] = []
        for item in raw_vulns if isinstance(raw_vulns, list) else []:
            try:
                vulns.append(Vulnerability.from_dict(item))
            except ValueError:
                continue
        raw_sources = data.get("sources") if isinstance(data.get("sources"), dict) else {}
        raw_errors = data.get("errors") if isinstance(data.get("errors"), dict) else {}
        # ``isinstance(..., str)`` first: an unhashable stored value (list/dict) would make the
        # set membership test raise TypeError instead of failing closed.
        return cls(
            vulnerabilities=vulns,
            status=status if isinstance(status, str) and status in IntelStatus.ALL else IntelStatus.UNAVAILABLE,
            sources={sanitize_text(k, max_len=32): (v if isinstance(v, str) and v in SourceStatus.ALL
                                                    else SourceStatus.ERROR)
                     for k, v in raw_sources.items()},
            fetched_at=_clean_str(data.get("fetched_at"), 40) or utc_now_iso(),
            ecosystem=_clean_str(data.get("ecosystem"), 40),
            name=_clean_str(data.get("name"), 214),
            version=_clean_str(data.get("version"), 64),
            errors={sanitize_text(k, max_len=32): sanitize_text(v, max_len=200) for k, v in raw_errors.items()},
        )
